# GC & Memory Troubleshooting Reference

Heap dumps, GC log analysis, jstat interpretation, OOM diagnosis, and GC tuning.
See also: [Oracle JVM Tuning Guide](https://docs.oracle.com/en/java/javase/21/gctuning/)

## OutOfMemoryError Types

| Error                            | Cause                           | Action                                                    |
| -------------------------------- | ------------------------------- | --------------------------------------------------------- |
| `Java heap space`                | Heap full                       | Take heap dump, check `-Xmx`, find leaks                  |
| `Metaspace`                      | Class loader leak               | Check `-XX:MaxMetaspaceSize`, find duplicate classloaders |
| `Direct buffer memory`           | NIO buffer exhaustion           | Check `-XX:MaxDirectMemorySize`, find Netty/NIO leaks     |
| `GC overhead limit exceeded`     | >98% time in GC, <2% heap freed | Same as heap space + GC tuning                            |
| `Unable to create native thread` | OS thread limit hit             | Check `ulimit -u`, reduce `-Xss` or thread count          |

## Heap Dumps

```bash
# Take heap dump (pauses JVM)
jmap -dump:format=b,file=/tmp/heap.hprof <pid>
jcmd <pid> GC.heap_dump /tmp/heap.hprof

# Auto-dump on OOM (add to JVM args)
# -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/log/app/

# Quick object histogram (no full dump)
jmap -histo <pid> | head -30
jcmd <pid> GC.class_histogram | head -30

# Current heap usage
jstat -gc <pid>
jstat -gcutil <pid> 1000 5    # 5 samples at 1s intervals
```

## Reading jstat -gcutil Output

| Column         | Meaning                          |
| -------------- | -------------------------------- |
| `S0`, `S1`     | Survivor space 0/1 utilization % |
| `E`            | Eden utilization %               |
| `O`            | Old gen utilization %            |
| `M`            | Metaspace utilization %          |
| `YGC` / `YGCT` | Young GC count / total time      |
| `FGC` / `FGCT` | Full GC count / total time       |
| `GCT`          | Total GC time                    |

**Red flag:** `O` near 100% and `FGC` climbing = heap full, GC thrashing.

## GC Log Analysis

```bash
# Check if GC logging is enabled
jcmd <pid> VM.flags | rg "gc|GC"

# Find GC logs
find / -name "gc*.log*" -o -name "*gc.log*" 2>/dev/null

# Enable GC logging (Java 9+ unified logging, add to JVM args)
# -Xlog:gc*:file=/var/log/app/gc.log:time,uptime,level,tags:filecount=5,filesize=20m

# Check for frequent Full GC or long pauses
rg "Full GC|Pause Full" /path/to/gc.log | tail -20
rg "Pause Young|GC pause" /path/to/gc.log | tail -20
```

## GC Collector Reference

| Collector  | Flag                   | Use case                                  |
| ---------- | ---------------------- | ----------------------------------------- |
| G1GC       | `-XX:+UseG1GC`         | General purpose (default Java 9+)         |
| ZGC        | `-XX:+UseZGC`          | Ultra-low latency (<1ms pauses), Java 15+ |
| Shenandoah | `-XX:+UseShenandoahGC` | Low latency, concurrent compaction        |
| Parallel   | `-XX:+UseParallelGC`   | Max throughput, batch jobs                |

## Key Tuning Flags

```
-Xms / -Xmx                      # Min/max heap (set equal to avoid resize)
-XX:MaxGCPauseMillis=200          # G1GC target pause time
-XX:G1HeapRegionSize=16m          # G1GC region size (1-32m, power of 2)
-XX:NewRatio=2                    # Old:Young gen ratio
-XX:MetaspaceSize=256m            # Initial metaspace
-XX:MaxMetaspaceSize=512m         # Max metaspace
```
