---
name: java-jvm
description: Use when troubleshooting Java applications, JVM issues, Spring Boot, heap dumps, thread dumps, GC problems, OutOfMemoryError, high CPU from Java processes, or when jstack/jmap/jcmd are needed.
---

# Java/JVM Troubleshooting

Diagnose Java application issues: memory, CPU, thread contention, GC pressure, startup failures.
See also: [Oracle Java Docs](https://docs.oracle.com/en/java/)

## References

Load these for deeper diagnosis:

- [GC & Memory Reference](./references/gc-memory.md) — OOM types, heap dumps, jstat reading, GC tuning, collector selection
- [Spring Boot Reference](./references/spring-boot.md) — Actuator endpoints, HikariCP/Tomcat pool config, startup failures, health checks

## Process Discovery

```bash
# Find Java processes
pgrep -fa java
jps -lvm                          # JVMs with main class and flags
jcmd -l                           # Alternative

# Inspect a running JVM
jcmd <pid> VM.flags               # Active JVM flags
jcmd <pid> VM.system_properties   # System properties
jcmd <pid> VM.command_line        # Original command line
jcmd <pid> VM.info                # Version, uptime, memory summary
```

## High CPU Workflow

```bash
# 1. Find the Java process
top -bn1 | grep java

# 2. Find the hot OS thread
top -H -p <pid> -bn1 | head -20

# 3. Convert thread ID to hex for matching in thread dump
printf '%x\n' <tid>

# 4. Thread dump and search for that thread
jstack <pid> | grep -A 30 "nid=0x<hex_tid>"

# 5. Multiple dumps to detect stuck threads
for i in 1 2 3; do jstack <pid> > /tmp/tdump_$i.txt; sleep 5; done
diff /tmp/tdump_1.txt /tmp/tdump_2.txt
```

Common causes: infinite loop/busy-wait (same stack across dumps), GC thrashing (see gc-memory ref), regex backtracking, large object serialization.

## Thread Dumps

```bash
# Capture
jstack <pid> > /tmp/thread_dump.txt
jcmd <pid> Thread.print > /tmp/thread_dump.txt
kill -3 <pid>                     # Dumps to stdout/stderr (check app logs)

# Analyze states
grep "java.lang.Thread.State" /tmp/thread_dump.txt | sort | uniq -c | sort -rn

# Find lock contention
rg -A 5 "BLOCKED" /tmp/thread_dump.txt
rg -B 2 -A 10 "waiting to lock" /tmp/thread_dump.txt

# Find deadlocks (reported at bottom of jstack output)
rg -A 20 "Found.*deadlock" /tmp/thread_dump.txt
```

Thread states: `RUNNABLE` (executing), `BLOCKED` (waiting for monitor lock), `WAITING` (indefinite wait — Object.wait, LockSupport.park), `TIMED_WAITING` (sleep/wait with timeout).

## Quick Memory Check

```bash
# Heap usage overview
jstat -gcutil <pid> 1000 5        # 5 samples at 1s intervals

# Quick object histogram (no full dump needed)
jmap -histo <pid> | head -30

# Take heap dump when needed
jcmd <pid> GC.heap_dump /tmp/heap.hprof
```

For OOM diagnosis, jstat interpretation, GC log analysis, and tuning flags, load the [GC & Memory Reference](./references/gc-memory.md).

## Connection Pool Issues

```bash
# HikariCP via actuator
curl -s localhost:8080/actuator/metrics/hikaricp.connections.active | jq .
curl -s localhost:8080/actuator/metrics/hikaricp.connections.pending | jq .
curl -s localhost:8080/actuator/metrics/hikaricp.connections.timeout | jq .

# pending > 0 or timeout > 0 = pool exhausted
# Check thread dump for blocked callers
jstack <pid> | rg -A 5 "HikariPool|getConnection|connectionTimeout"
```

Common causes: slow queries, missing `@Transactional`, pool too small (default `maximumPoolSize=10`), connection leaks (set `leakDetectionThreshold` to detect).

For pool config properties, see [Spring Boot Reference](./references/spring-boot.md).

## Service Startup Failures

```bash
# Service status and recent logs
systemctl status <service>
journalctl -u <service> --since "5 min ago"

# Common failure patterns
rg "APPLICATION FAILED TO START|BeanCreationException|BindException|Address already in use" /var/log/app/

# Port conflict
ss -tlnp | grep 8080

# Java version check
java -version

# Permissions
ls -la /etc/app/ /var/log/app/ /var/lib/app/
```

## Spring Boot Quick Checks

```bash
# Health
curl -s localhost:8080/actuator/health | jq .

# Thread dump via actuator (no JDK tools needed)
curl -s localhost:8080/actuator/threaddump | jq .

# Key metrics
curl -s localhost:8080/actuator/metrics/jvm.memory.used | jq .
curl -s localhost:8080/actuator/metrics/hikaricp.connections.active | jq .
```

Actuator port/path may differ — check `management.server.port` and `management.endpoints.web.base-path` in app config. For full actuator reference, runtime log changes, and config discovery, load the [Spring Boot Reference](./references/spring-boot.md).
