# Config Discovery & MPM Tuning

## Config File Locations by Distro

| Distro        | Main config                  | Sites                         | Modules                            |
| ------------- | ---------------------------- | ----------------------------- | ---------------------------------- |
| RHEL/CentOS   | `/etc/httpd/conf/httpd.conf` | `/etc/httpd/conf.d/*.conf`    | `/etc/httpd/conf.modules.d/*.conf` |
| Debian/Ubuntu | `/etc/apache2/apache2.conf`  | `/etc/apache2/sites-enabled/` | `/etc/apache2/mods-enabled/`       |

## Config Discovery Commands

```bash
# Find main config and server root
httpd -V 2>&1 | grep "SERVER_CONFIG_FILE\|HTTPD_ROOT"

# Show all parsed vhosts with their config file locations
httpd -S 2>&1

# Find all config files
find /etc/httpd/ -name "*.conf" -type f 2>/dev/null          # RHEL/CentOS
find /etc/apache2/ -name "*.conf" -type f 2>/dev/null        # Debian/Ubuntu

# Enabled sites and modules (Debian/Ubuntu)
ls -la /etc/apache2/sites-enabled/
ls /etc/apache2/mods-enabled/

# Search for specific directives
rg "ProxyPass|ServerName|DocumentRoot" /etc/httpd/ 2>/dev/null
rg "ProxyPass|ServerName|DocumentRoot" /etc/apache2/ 2>/dev/null

# Find .htaccess files
find /var/www -name ".htaccess" -type f 2>/dev/null
```

## Log Locations

```bash
# Find configured log paths
rg "ErrorLog|CustomLog" /etc/httpd/ /etc/apache2/ 2>/dev/null

# Defaults:
# RHEL/CentOS: /var/log/httpd/error_log, /var/log/httpd/access_log
# Debian/Ubuntu: /var/log/apache2/error.log, /var/log/apache2/access.log

# Per-vhost log paths
rg -B5 "ErrorLog|CustomLog" /etc/httpd/conf.d/ /etc/apache2/sites-enabled/ 2>/dev/null
```

Ref: https://httpd.apache.org/docs/2.4/configuring.html

---

## MPM Tuning

### Identify Current MPM

```bash
httpd -V | grep "Server MPM"

# Current process/thread count
ps aux | grep httpd | wc -l
ps -eo pid,ppid,%mem,rss,cmd | grep httpd | sort -k4 -rn

# Average memory per worker
ps -eo rss,cmd | grep httpd | awk '{sum+=$1; count++} END {print "Avg MB:", sum/count/1024, "Count:", count}'
```

### MPM Comparison

| MPM       | Model                  | Use case                                                |
| --------- | ---------------------- | ------------------------------------------------------- |
| `prefork` | Process per connection | mod_php compatibility; high memory cost                 |
| `worker`  | Threads + processes    | Balanced memory/concurrency                             |
| `event`   | Async event-driven     | High concurrency, keepalive-heavy (recommended default) |

### Tuning Directives: event / worker

```apache
<IfModule mpm_event_module>
    StartServers             3
    MinSpareThreads         75
    MaxSpareThreads        250
    ThreadsPerChild         25
    MaxRequestWorkers      400    # ServerLimit * ThreadsPerChild
    ServerLimit             16
    MaxConnectionsPerChild   0    # 0 = unlimited; set e.g. 10000 to recycle
</IfModule>
```

### Tuning Directives: prefork

```apache
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers         10
    MaxRequestWorkers      256
    MaxConnectionsPerChild   0
</IfModule>
```

### Sizing Formula

```
MaxRequestWorkers = Available RAM / Average Worker Memory
```

Measure average worker memory with the `ps` command above, then set `MaxRequestWorkers` accordingly. For event/worker, `ServerLimit = MaxRequestWorkers / ThreadsPerChild`.

Ref: https://httpd.apache.org/docs/2.4/mod/mpm_common.html
