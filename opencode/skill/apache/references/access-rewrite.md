# 403 Forbidden, mod_rewrite Debugging & mod_status

## 403 Forbidden Diagnosis

```bash
# Identify the specific denial reason
rg "AH01630|AH01797|client denied|Permission" /var/log/httpd/error_log | tail -10
```

### Common Causes & Fixes

**1. Filesystem permissions**

```bash
ls -la /var/www/html/
namei -l /var/www/html/index.html    # Verify full path traversal
```

Apache needs `r` on files and `rx` on every directory in the path.

**2. `Require` directive (Apache 2.4+)**

```bash
rg "Require|Order|Allow|Deny" /etc/httpd/conf.d/ /etc/apache2/sites-enabled/ 2>/dev/null
```

Ensure the relevant `<Directory>` block has `Require all granted` or appropriate access rules. Note: `Order`/`Allow`/`Deny` are legacy (mod_access_compat); prefer `Require` directives.

**3. SELinux (RHEL/CentOS)**

```bash
getenforce
ls -Z /var/www/html/
ausearch -m avc -ts recent | grep httpd

# Fix context:
restorecon -Rv /var/www/html/

# Allow network connections (needed for proxying):
setsebool -P httpd_can_network_connect 1
```

**4. `.htaccess` ignored**

```bash
rg "AllowOverride" /etc/httpd/ /etc/apache2/ 2>/dev/null
# AllowOverride None  = .htaccess ignored entirely
# AllowOverride All   = .htaccess fully processed
```

**5. Missing `DirectoryIndex`**

```bash
rg "DirectoryIndex" /etc/httpd/ /etc/apache2/ 2>/dev/null
```

If no index file matches and `Options Indexes` is off, Apache returns 403.

Ref: https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html

---

## mod_rewrite Debugging

```bash
# Verify module is loaded
httpd -M | grep rewrite

# Find all rewrite rules
rg "Rewrite" /etc/httpd/ /etc/apache2/ 2>/dev/null
find /var/www -name ".htaccess" -exec grep -l "Rewrite" {} \;
```

### Enable Rewrite Logging

Add temporarily to the relevant vhost:

```apache
LogLevel alert rewrite:trace3
```

Then check the error log for rewrite decision traces. Remove after debugging.

### Common Pitfalls

- `AllowOverride None` silently prevents `.htaccess` `RewriteRule` directives
- Missing `RewriteEngine On` in the context
- Wrong `RewriteBase` in subdirectory `.htaccess` files
- Infinite redirect loops -- diagnose with: `curl -vL http://example.com/path 2>&1 | grep "< HTTP\|< Location"`

Ref: https://httpd.apache.org/docs/2.4/mod/mod_rewrite.html

---

## mod_status (Live Server Metrics)

```bash
# Verify module is loaded
httpd -M | grep status

# Query (must be configured with access controls)
curl -s http://localhost/server-status?auto
```

### Key Metrics

| Metric                            | Meaning                       |
| --------------------------------- | ----------------------------- |
| `BusyWorkers`                     | Currently handling requests   |
| `IdleWorkers`                     | Waiting for requests          |
| `Total Accesses` / `Total kBytes` | Cumulative since last restart |

**Scoreboard characters:** `_` Waiting, `S` Starting, `R` Reading, `W` Sending, `K` Keepalive, `D` DNS Lookup, `C` Closing, `L` Logging, `G` Graceful, `I` Idle cleanup, `.` Open slot

If `BusyWorkers == MaxRequestWorkers`, the server is at capacity. See `references/config-mpm.md` for tuning.

Ref: https://httpd.apache.org/docs/2.4/mod/mod_status.html
