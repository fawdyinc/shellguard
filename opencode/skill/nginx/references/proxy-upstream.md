# Proxy & Upstream Reference

Detailed diagnostics and configuration patterns for reverse proxy and upstream issues.

Docs: https://nginx.org/en/docs/http/ngx_http_proxy_module.html
Upstream: https://nginx.org/en/docs/http/ngx_http_upstream_module.html

## 502 Bad Gateway Diagnosis

```bash
# Check error log for upstream failures
rg "upstream" /var/log/nginx/error.log | tail -10

# Find configured upstream addresses
rg "proxy_pass|upstream" /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null

# Test upstream directly
curl -v http://127.0.0.1:8080/
ss -tlnp | grep 8080

# Distinguish failure modes in logs:
# "connect() failed (111: Connection refused)" → upstream not running
# "no live upstreams" → all upstreams marked down
# "upstream prematurely closed connection" → upstream crashed mid-response
```

**Common causes and fixes:**

- Upstream not running → restart the application
- Wrong address/port in `proxy_pass` → verify with `ss -tlnp`
- SELinux blocking outbound connections → `setsebool -P httpd_can_network_connect 1`
- Upstream returning malformed HTTP → test with `curl -v` directly

## 504 Gateway Timeout Diagnosis

```bash
# Check configured timeouts
rg "proxy_connect_timeout|proxy_send_timeout|proxy_read_timeout" /etc/nginx/ -r

# Defaults: 60s for all three

# Measure upstream latency
curl -w "time_total: %{time_total}\n" -o /dev/null -s http://127.0.0.1:8080/
```

Increase timeouts only if the upstream legitimately needs more time. Otherwise investigate the upstream application.

```nginx
proxy_connect_timeout 5s;    # Fast-fail on dead upstreams
proxy_send_timeout 60s;
proxy_read_timeout 300s;     # For slow endpoints (reports, exports)
```

## Upstream & Load Balancing

```bash
# View upstream definitions
rg -A 10 "upstream " /etc/nginx/ -r

# Test individual upstream servers
rg "server " /etc/nginx/conf.d/upstream*.conf 2>/dev/null
```

**Upstream config pattern:**

```nginx
upstream backend {
    least_conn;                                # or: ip_hash, random
    server 10.0.0.1:8080 max_fails=3 fail_timeout=30s;
    server 10.0.0.2:8080 max_fails=3 fail_timeout=30s;
    server 10.0.0.3:8080 backup;               # only when others are down
    keepalive 32;                              # persistent connections to upstream
}
```

## Common Proxy Misconfigurations

### Missing proxy headers

Backend sees Nginx's IP instead of client IP, or `Host` header is wrong.

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

### WebSocket upgrade not handled

WebSocket connections drop or fail through the proxy.

```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_read_timeout 86400;    # keep WS connections alive
```

Docs: https://nginx.org/en/docs/http/websocket.html

### Trailing slash path rewriting

`/app` proxied but `/app/` is not (or vice versa). The trailing slash on `proxy_pass` controls path stripping.

```nginx
# Strips /app/ prefix before forwarding:
location /app/ {
    proxy_pass http://backend/;
}

# Preserves /app/ prefix:
location /app/ {
    proxy_pass http://backend;
}
```
