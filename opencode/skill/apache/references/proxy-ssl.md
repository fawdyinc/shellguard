# mod_proxy Troubleshooting & SSL/TLS Diagnostics

## Proxy Error Diagnosis

### Identify the Error

```bash
# Proxy-specific errors from error log
rg "proxy.*error|AH0095|AH0110|AH0111|AH0089|AH0203" /var/log/httpd/error_log | tail -20

# Common AH codes:
# AH00957 - backend connection refused
# AH01102 - error reading status line from remote server
# AH01114 - failed to make connection to backend
# AH00898 - SSL handshake error with remote server
# AH02032 - no workers/backends configured
# AH00124 - error reading headers from client
```

### 502 Bad Gateway

Verify the backend is reachable from the Apache host:

```bash
# Find configured backends
rg "ProxyPass " /etc/httpd/conf.d/ /etc/apache2/sites-enabled/ 2>/dev/null

# Test backend directly
curl -v http://127.0.0.1:8080/
ss -tlnp | grep 8080

# Verify required modules are loaded
httpd -M | grep proxy
# Required: proxy_module, proxy_http_module
# WebSocket: proxy_wstunnel_module
# AJP (Tomcat): proxy_ajp_module
# Load balancing: proxy_balancer_module, lbmethod_byrequests_module
```

### 503 Service Unavailable

Usually means all workers exhausted or backend marked in error state:

```bash
rg "503|Service Unavailable|AH01121" /var/log/httpd/error_log | tail -10

# Check worker saturation
httpd -V | grep "Server MPM"
rg "MaxRequestWorkers|MaxClients|ServerLimit" /etc/httpd/ /etc/apache2/ 2>/dev/null -r

# Live worker count (requires mod_status)
curl -s http://localhost/server-status?auto
```

### 504 Gateway Timeout

```bash
# Check timeout settings
rg "ProxyTimeout|timeout" /etc/httpd/conf.d/ /etc/apache2/sites-enabled/ 2>/dev/null

# ProxyTimeout inherits from Timeout directive (default 60s)
rg "^Timeout " /etc/httpd/conf/httpd.conf /etc/apache2/apache2.conf 2>/dev/null

# Measure actual backend response time
curl -w "time_total: %{time_total}\n" -o /dev/null -s http://127.0.0.1:8080/
```

### Proxy Configuration Patterns

```apache
# Basic reverse proxy
ProxyPreserveHost On
ProxyPass / http://127.0.0.1:8080/
ProxyPassReverse / http://127.0.0.1:8080/

# With timeout and retry settings
ProxyPass / http://127.0.0.1:8080/ connectiontimeout=5 timeout=300 retry=0

# Load balancer
<Proxy balancer://backend>
    BalancerMember http://10.0.0.1:8080 route=node1
    BalancerMember http://10.0.0.2:8080 route=node2
    ProxySet lbmethod=byrequests
</Proxy>
ProxyPass / balancer://backend/

# AJP proxy (Tomcat)
ProxyPass / ajp://127.0.0.1:8009/
ProxyPassReverse / ajp://127.0.0.1:8009/
```

Ref: https://httpd.apache.org/docs/2.4/mod/mod_proxy.html

---

## SSL/TLS Diagnostics

### Certificate Verification

```bash
# Check expiry
openssl s_client -connect localhost:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -dates

# Full certificate chain
openssl s_client -connect localhost:443 -servername example.com -showcerts </dev/null 2>/dev/null

# Verify cert matches key (both md5sums must match)
openssl x509 -noout -modulus -in /etc/httpd/ssl/cert.pem | md5sum
openssl rsa -noout -modulus -in /etc/httpd/ssl/key.pem | md5sum
```

### SSL Configuration

```bash
# Find SSL directives
rg "SSLCertificate|SSLProtocol|SSLCipherSuite" /etc/httpd/ /etc/apache2/ 2>/dev/null -r

# Verify mod_ssl is loaded
httpd -M | grep ssl

# SSL errors in log
rg "SSL|AH0089|AH02003|AH02561" /var/log/httpd/error_log | tail -20
```

### Common SSL Fixes

| Symptom                             | Cause                | Fix                                                                       |
| ----------------------------------- | -------------------- | ------------------------------------------------------------------------- |
| `AH02003: certificate expired`      | Expired cert         | Renew and reload                                                          |
| `AH02561: certificate/key mismatch` | Wrong key for cert   | Verify modulus match (see above)                                          |
| `AH02559: chain incomplete`         | Missing intermediate | Add to `SSLCertificateChainFile` or concatenate into `SSLCertificateFile` |
| `mod_ssl` not found                 | Module not loaded    | `a2enmod ssl` (Debian) or add `LoadModule`                                |
| `Address already in use :443`       | Port conflict        | Check `Listen 443` and `ss -tlnp \| grep :443`                            |

Ref: https://httpd.apache.org/docs/2.4/mod/mod_ssl.html
