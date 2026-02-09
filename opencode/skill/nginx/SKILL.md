---
name: nginx
description: Use when troubleshooting Nginx issues including 502/504 errors, upstream failures, SSL/TLS problems, config validation errors, reverse proxy misconfigurations, high latency, or when Nginx error logs need analysis.
---

# Nginx Troubleshooting

Diagnose and resolve Nginx issues: upstream failures, SSL problems, configuration errors, performance tuning.

Docs: https://nginx.org/en/docs/

## Quick Diagnostics

Run these first for any Nginx issue:

```bash
# Service status and process check
systemctl status nginx
pgrep -fa nginx

# Config syntax check
nginx -t

# Recent errors
tail -50 /var/log/nginx/error.log

# Listening ports
ss -tlnp | grep nginx
```

## Config Discovery

```bash
# Find main config path
nginx -t 2>&1 | grep "configuration file"

# Dump full effective config (resolves all includes)
nginx -T

# List all server blocks
rg "server_name|listen " /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null

# Find all include directives
rg "include " /etc/nginx/nginx.conf /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null
```

**Standard config locations:**

| Path                        | Purpose                                     |
| --------------------------- | ------------------------------------------- |
| `/etc/nginx/nginx.conf`     | Main config (http, events, workers)         |
| `/etc/nginx/conf.d/*.conf`  | Per-site configs (RHEL/CentOS)              |
| `/etc/nginx/sites-enabled/` | Symlinks to sites-available (Debian/Ubuntu) |
| `/etc/nginx/snippets/`      | Reusable config fragments                   |

## Log Analysis

```bash
# Find active log paths
rg "access_log|error_log" /etc/nginx/ -r

# Upstream errors (502/504 root cause)
rg "upstream" /var/log/nginx/error.log | tail -20

# Connection errors
rg "connect\(\) failed|Connection refused|Connection timed out" /var/log/nginx/error.log | tail -20

# Response code distribution
awk '{print $9}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head

# 5xx requests
awk '$9 >= 500' /var/log/nginx/access.log | tail -20

# Top requesting IPs
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -10
```

Error log levels (least → most verbose): `emerg`, `alert`, `crit`, `error`, `warn`, `notice`, `info`, `debug`.

## Service Won't Start / Reload

```bash
# Config syntax (always first)
nginx -t

# Port conflicts
ss -tlnp | grep ":80\|:443"

# Permissions on certs and log dirs
ls -la /etc/nginx/ssl/
ls -la /var/log/nginx/

# Missing included files
nginx -T 2>&1 | grep "open()"

# Detailed systemd error
journalctl -u nginx --since "5 min ago"
```

Common start failures:

- `Address already in use` → another process on port 80/443
- `cannot load certificate` → wrong path or permissions on SSL files
- `host not found in upstream` → DNS resolution failure at startup

## Reference Files

Load these for detailed diagnostics and config patterns on specific topics.

### `references/proxy-upstream.md`

Read when diagnosing **502/504 errors**, upstream connectivity, load balancing configuration, or proxy misconfigurations (missing headers, WebSocket failures, trailing slash path rewriting).

### `references/ssl-performance.md`

Read when diagnosing **SSL/TLS certificate issues**, TLS handshake failures, or when **tuning performance** (workers, connections, buffering, stub_status monitoring, latency log format).
