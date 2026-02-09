# SSL/TLS & Performance Reference

SSL diagnostics, certificate troubleshooting, and Nginx performance tuning.

SSL docs: https://nginx.org/en/docs/http/ngx_http_ssl_module.html

## SSL/TLS Diagnostics

```bash
# Check certificate expiry
openssl s_client -connect localhost:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -dates

# Check full certificate chain
openssl s_client -connect localhost:443 -servername example.com -showcerts </dev/null 2>/dev/null

# Verify certificate matches private key (md5sums must match)
openssl x509 -noout -modulus -in /etc/nginx/ssl/cert.pem | md5sum
openssl rsa -noout -modulus -in /etc/nginx/ssl/key.pem | md5sum

# Check certificate SANs
openssl x509 -noout -text -in /etc/nginx/ssl/cert.pem | rg "Subject:|DNS:"

# Test specific TLS versions
openssl s_client -connect localhost:443 -tls1_2 </dev/null
openssl s_client -connect localhost:443 -tls1_3 </dev/null

# Check SSL config directives
rg "ssl_certificate|ssl_protocols|ssl_ciphers" /etc/nginx/ -r

# Check for SSL errors in logs
rg "SSL" /var/log/nginx/error.log | tail -20
```

**Common SSL failures:**

- **Expired certificate** → check `-dates` output above
- **Certificate/key mismatch** → modulus md5sums differ
- **Missing intermediate chain** → browsers work, `curl` fails with "unable to verify"
- **Wrong `server_name`** → SNI routes to wrong certificate
- **"cannot load certificate"** → wrong path or file permissions

## Performance Tuning

Docs: https://nginx.org/en/docs/ngx_core_module.html

### Worker configuration

```bash
# Check current settings
rg "worker_processes|worker_connections|worker_rlimit" /etc/nginx/nginx.conf

# Current TCP connection count
ss -s | grep -i tcp

# File descriptor limits for Nginx process
cat /proc/$(pgrep -o nginx)/limits | grep "open files"
```

**Recommended settings:**

```nginx
worker_processes auto;          # match CPU cores
worker_connections 1024;        # per worker (default 512)
worker_rlimit_nofile 8192;      # file descriptor limit
keepalive_timeout 65;           # client keepalive
```

### Proxy buffering

```bash
# Check current buffering config
rg "proxy_buffering|proxy_buffer_size|proxy_buffers" /etc/nginx/ -r
```

```nginx
proxy_buffering on;             # buffer upstream responses (default: on)
proxy_buffer_size 4k;           # buffer for response headers
proxy_buffers 8 4k;             # buffers for response body
```

Disable buffering only for streaming/SSE endpoints:

```nginx
location /events {
    proxy_buffering off;
    proxy_pass http://backend;
}
```

### stub_status monitoring

Enable connection monitoring (https://nginx.org/en/docs/http/ngx_http_stub_status_module.html):

```nginx
server {
    listen 127.0.0.1:8080;
    location /nginx_status {
        stub_status;
        allow 127.0.0.1;
        deny all;
    }
}
```

```bash
# Query active connections
curl -s http://localhost:8080/nginx_status
```

### Detailed log format for latency diagnosis

Add upstream timing fields to isolate where latency occurs:

```nginx
log_format detailed '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    'rt=$request_time uct=$upstream_connect_time '
                    'uht=$upstream_header_time urt=$upstream_response_time';
```

Docs: https://nginx.org/en/docs/http/ngx_http_log_module.html
