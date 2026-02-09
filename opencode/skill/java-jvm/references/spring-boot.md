# Spring Boot Troubleshooting Reference

Spring Boot diagnostics via Actuator, connection/thread pool issues, startup failures, and config discovery.
See also: [Spring Boot Reference Docs](https://docs.spring.io/spring-boot/reference/)

## Actuator Endpoints

Availability depends on `management.endpoints.web.exposure.include` config.

| Endpoint                   | Purpose                                     |
| -------------------------- | ------------------------------------------- |
| `/actuator/health`         | Health with component details               |
| `/actuator/metrics`        | List metric names                           |
| `/actuator/metrics/{name}` | Specific metric value                       |
| `/actuator/env`            | Environment properties                      |
| `/actuator/configprops`    | All `@ConfigurationProperties` beans        |
| `/actuator/beans`          | All Spring beans                            |
| `/actuator/mappings`       | All `@RequestMapping` paths                 |
| `/actuator/threaddump`     | JVM thread dump (no JDK tools needed)       |
| `/actuator/heapdump`       | Heap dump (.hprof binary)                   |
| `/actuator/loggers`        | Logger levels                               |
| `/actuator/loggers/{name}` | GET/POST to view or change level at runtime |

**Note:** Check `application.properties`/`application.yml` for non-default actuator config:

- `management.server.port` — may differ from app port
- `management.endpoints.web.base-path` — default `/actuator`

### Change Log Level at Runtime

```bash
# View current level
curl -s http://localhost:8080/actuator/loggers/com.example.myapp | jq .

# Set to DEBUG
curl -X POST http://localhost:8080/actuator/loggers/com.example.myapp \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel": "DEBUG"}'

# Reset to default
curl -X POST http://localhost:8080/actuator/loggers/com.example.myapp \
  -H "Content-Type: application/json" \
  -d '{"configuredLevel": null}'
```

## Key Metrics

```bash
# JVM
curl -s localhost:8080/actuator/metrics/jvm.memory.used | jq .
curl -s localhost:8080/actuator/metrics/jvm.gc.pause | jq .

# Tomcat threads
curl -s localhost:8080/actuator/metrics/tomcat.threads.busy | jq '.measurements[0].value'
curl -s localhost:8080/actuator/metrics/tomcat.threads.config.max | jq '.measurements[0].value'

# HikariCP
curl -s localhost:8080/actuator/metrics/hikaricp.connections.active | jq '.measurements[0].value'
curl -s localhost:8080/actuator/metrics/hikaricp.connections.pending | jq '.measurements[0].value'
curl -s localhost:8080/actuator/metrics/hikaricp.connections.timeout | jq '.measurements[0].value'
```

## HikariCP Pool Exhaustion

Symptom: requests hang, `Connection is not available, request timed out after 30000ms`.

```bash
# Check thread dump for blocked threads
jstack <pid> | rg -B2 -A10 "HikariPool|Waiting for connection"
```

Key config:

```properties
spring.datasource.hikari.maximum-pool-size=10          # Default 10
spring.datasource.hikari.minimum-idle=10                # Set equal to max for stability
spring.datasource.hikari.connection-timeout=30000       # Wait for connection (ms)
spring.datasource.hikari.max-lifetime=1800000           # Max connection lifetime (ms)
spring.datasource.hikari.leak-detection-threshold=60000 # Warn if unreturned after 60s
```

Common causes: slow queries, missing `@Transactional`, pool too small, connection leaks.

## Tomcat Thread Pool Exhaustion

Symptom: requests rejected or extremely slow, `tomcat.threads.busy == config.max`.

```bash
jstack <pid> | rg -A 15 "http-nio.*exec"
```

Key config:

```properties
server.tomcat.threads.max=200          # Default 200
server.tomcat.threads.min-spare=10     # Default 10
server.tomcat.accept-count=100         # Queue when all threads busy
```

## Startup Failures

```bash
# Find root cause (usually at bottom of stack trace)
rg "Caused by:|APPLICATION FAILED TO START|Action:" /var/log/app/ | tail -20
```

Common causes: missing config property, database unreachable, port conflict, dependency version mismatch.

## Health Check Failures

```bash
curl -s localhost:8080/actuator/health | jq .
curl -s localhost:8080/actuator/health/db | jq .
curl -s localhost:8080/actuator/health/diskSpace | jq .
```

Enable details:

```properties
management.endpoint.health.show-details=always
management.endpoint.health.show-components=always
```

## Configuration Discovery

```bash
# Find config files
find / -name "application.properties" -o -name "application.yml" \
  -o -name "application-*.yml" -o -name "application-*.properties" 2>/dev/null

# Active profiles
curl -s localhost:8080/actuator/env | jq '.activeProfiles'

# Check specific property
curl -s localhost:8080/actuator/env/spring.datasource.url | jq .

# JVM args
jcmd <pid> VM.command_line
```

## Finding Logs

```bash
rg "logging.file|logging.path" /path/to/application.properties
find /var/log -name "*.log" -path "*app*" -o -name "spring*.log" 2>/dev/null
rg "Exception|ERROR" /var/log/app/ --glob "*.log" -C2 | tail -50
```
