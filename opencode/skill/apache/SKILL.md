---
name: apache
description: Use when troubleshooting Apache HTTP Server (httpd) issues including 502/503/504 errors, mod_proxy upstream failures, SSL/TLS problems, config validation errors, .htaccess issues, MPM tuning, or when Apache error logs need analysis.
---

# Apache HTTP Server Troubleshooting

Diagnose and resolve Apache httpd issues: proxy failures, SSL problems, configuration errors, MPM tuning, and access control.

## Quick Diagnostics

Run these first for any Apache issue:

```bash
# Service status
systemctl status httpd        # RHEL/CentOS
systemctl status apache2      # Debian/Ubuntu

# Config syntax check
apachectl configtest

# Build info, loaded modules, parsed vhosts
httpd -V
httpd -M
httpd -S

# Recent errors
tail -50 /var/log/httpd/error_log          # RHEL/CentOS
tail -50 /var/log/apache2/error.log        # Debian/Ubuntu

# Listening ports
ss -tlnp | grep -E "httpd|apache2"
```

## Log Analysis

```bash
# Errors by severity
rg "\[error\]|\[crit\]|\[alert\]|\[emerg\]" /var/log/httpd/error_log | tail -20

# Apache error codes (AH#####)
rg "AH[0-9]+" /var/log/httpd/error_log | tail -20

# Response code distribution from access log
awk '{print $9}' /var/log/httpd/access_log | sort | uniq -c | sort -rn | head

# 5xx errors
awk '$9 >= 500' /var/log/httpd/access_log | tail -20

# Top IPs and URLs
awk '{print $1}' /var/log/httpd/access_log | sort | uniq -c | sort -rn | head -10
awk '{print $7}' /var/log/httpd/access_log | sort | uniq -c | sort -rn | head -10
```

## Service Won't Start

```bash
apachectl configtest
ss -tlnp | grep ":80\|:443"              # Port conflict?
journalctl -u httpd --since "5 min ago"
httpd -X -e debug 2>&1 | head -50        # Verbose foreground start
```

Common causes: port conflict, missing SSL cert file, missing module, nonexistent `DocumentRoot`, stale PID file (`/var/run/httpd/httpd.pid`).

## Issue-Specific References

Read these for detailed diagnostics and config patterns:

### `references/proxy-ssl.md`

- 502/503/504 proxy errors and backend verification
- mod_proxy configuration patterns (reverse proxy, load balancer, AJP)
- SSL/TLS certificate checks, chain validation, cert/key mismatch
- Ref: [mod_proxy](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html), [mod_ssl](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html)

### `references/config-mpm.md`

- Config file locations by distro (RHEL vs Debian)
- Config discovery commands (`httpd -S`, finding vhosts, log paths)
- MPM comparison (prefork/worker/event) and tuning directives
- Worker memory measurement and `MaxRequestWorkers` sizing
- Ref: [MPM directives](https://httpd.apache.org/docs/2.4/mod/mpm_common.html)

### `references/access-rewrite.md`

- 403 Forbidden causes: permissions, `Require` directives, SELinux, `AllowOverride`
- mod_rewrite debugging with `LogLevel rewrite:trace3`
- mod_status metrics and scoreboard interpretation
- Ref: [mod_authz_core](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html), [mod_rewrite](https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html)
