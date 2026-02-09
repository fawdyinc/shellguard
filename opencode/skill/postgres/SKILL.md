---
name: postgres
description: Use when troubleshooting PostgreSQL issues including slow queries, connection problems, replication lag, locks, disk usage, WAL accumulation, or when "postgres" or "pg_" appears in error logs. Also activate when port 5432 is involved.
---

# PostgreSQL Troubleshooting

Diagnose and resolve PostgreSQL performance, connectivity, replication, storage, and locking problems.

## Quick Diagnostics

Run these first to assess overall health:

```bash
# Is Postgres running and accepting connections?
pg_isready -h localhost -p 5432

# Version (affects available features/queries)
psql -c "SELECT version();"

# Connection count vs limit
psql -c "SELECT count(*), max_conn FROM pg_stat_activity, (SELECT setting::int AS max_conn FROM pg_settings WHERE name = 'max_connections') mc GROUP BY max_conn;"

# Long-running queries
psql -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, state, left(query, 80) FROM pg_stat_activity WHERE state != 'idle' AND query NOT LIKE '%pg_stat_activity%' ORDER BY duration DESC LIMIT 10;"

# Blocked queries
psql -c "SELECT pid, pg_blocking_pids(pid) AS blocked_by, wait_event_type, wait_event, left(query, 60) FROM pg_stat_activity WHERE pg_blocking_pids(pid) != '{}';"
```

## Log Locations

| Method                  | Log path                                                 |
| ----------------------- | -------------------------------------------------------- |
| Debian/Ubuntu packages  | `/var/log/postgresql/postgresql-<version>-<cluster>.log` |
| RHEL/CentOS packages    | `/var/lib/pgsql/<version>/data/log/`                     |
| Custom `data_directory` | Check `log_directory` in `postgresql.conf`               |
| Docker                  | `docker logs <container>`                                |

Find active config and log settings:

```bash
psql -c "SHOW config_file;"
psql -c "SHOW data_directory;"
psql -c "SHOW log_directory;"
```

Key log settings -- see [runtime config docs](https://www.postgresql.org/docs/current/runtime-config-logging.html):

- `log_min_duration_statement` -- capture slow queries (e.g., `1000` for >1s)
- `log_lock_waits` -- log queries waiting on locks longer than `deadlock_timeout`
- `log_connections` / `log_disconnections` -- track connection churn
- `log_checkpoints` -- checkpoint performance data

## Slow Query Workflow

1. Check if `pg_stat_statements` is available (see [extension docs](https://www.postgresql.org/docs/current/pgstatstatements.html)):

   ```bash
   psql -c "SELECT * FROM pg_available_extensions WHERE name = 'pg_stat_statements';"
   ```

2. Find top queries by total time -- use the queries in [diagnostic-queries.md](./references/diagnostic-queries.md#performance--pg_stat_statements).

3. Analyze a specific slow query:

   ```bash
   psql -c "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) <query>;"
   ```

4. Read the EXPLAIN output for these signals:
   - **Seq Scan** on large tables -- missing index
   - **Nested Loop** with high row counts -- consider index for hash join
   - **Sort** with high memory -- `work_mem` may need tuning
   - **Buffers: shared read >> shared hit** -- data not in cache

See [EXPLAIN docs](https://www.postgresql.org/docs/current/using-explain.html) for interpreting output.

### Index Usage

```bash
# Tables with low index usage (sequential-scan heavy)
psql -c "SELECT relname, seq_scan, idx_scan, seq_scan - idx_scan AS diff FROM pg_stat_user_tables WHERE seq_scan > 1000 ORDER BY diff DESC LIMIT 10;"

# Unused indexes (removal candidates)
psql -c "SELECT indexrelname, idx_scan, pg_size_pretty(pg_relation_size(indexrelid)) AS size FROM pg_stat_user_indexes WHERE idx_scan = 0 ORDER BY pg_relation_size(indexrelid) DESC LIMIT 10;"
```

More table/index health queries in [diagnostic-queries.md](./references/diagnostic-queries.md#table--index-health).

## Connection Issues

### Pool Exhaustion

Use [diagnostic-queries.md](./references/diagnostic-queries.md#connection-state) for detailed connection breakdowns by state, application, and idle time.

Quick checks:

```bash
# Connections by state
psql -c "SELECT state, count(*) FROM pg_stat_activity GROUP BY state ORDER BY count DESC;"

# Check max_connections
psql -c "SELECT setting FROM pg_settings WHERE name = 'max_connections';"
```

Common causes:

- Application not returning connections to pool
- Pool oversized across multiple app instances
- `idle in transaction` connections holding locks -- set `idle_in_transaction_session_timeout`

See [connection config docs](https://www.postgresql.org/docs/current/runtime-config-connection.html).

### Connection Refused

```bash
# Is Postgres listening on the expected address?
ss -tlnp | grep 5432

# Check listen_addresses and pg_hba.conf
psql -c "SHOW listen_addresses;"
psql -c "SHOW hba_file;"
cat $(psql -tAc "SHOW hba_file;")
```

See [pg_hba.conf docs](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html).

## Locks & Deadlocks

```bash
# Current lock waits
psql -c "SELECT pid, pg_blocking_pids(pid) AS blocked_by, wait_event_type, wait_event, left(query, 60) FROM pg_stat_activity WHERE pg_blocking_pids(pid) != '{}';"

# Lock details
psql -c "SELECT locktype, relation::regclass, mode, granted, pid FROM pg_locks WHERE NOT granted ORDER BY pid;"

# Kill a blocking query (use with caution)
# psql -c "SELECT pg_cancel_backend(<pid>);"       -- graceful
# psql -c "SELECT pg_terminate_backend(<pid>);"    -- forceful
```

Ensure `log_lock_waits = on` and review logs for `LOG: process <pid> still waiting for <lock>` to find historical lock contention. Detailed lock-tree queries in [diagnostic-queries.md](./references/diagnostic-queries.md#locks).

See [explicit locking docs](https://www.postgresql.org/docs/current/explicit-locking.html).

## Replication, Storage & Service Startup

For replication lag diagnostics, disk/WAL/bloat investigation, and service startup failures, see [replication-storage.md](./references/replication-storage.md).

## References

- [Diagnostic Queries](./references/diagnostic-queries.md) -- copy-paste SQL for connections, queries, locks, performance, table health, replication, and configuration review
- [Replication, Storage & Startup](./references/replication-storage.md) -- replication lag, disk/WAL/bloat, and service startup troubleshooting
- [PostgreSQL Official Documentation](https://www.postgresql.org/docs/current/)
- [pg_stat_activity view](https://www.postgresql.org/docs/current/monitoring-stats.html#MONITORING-PG-STAT-ACTIVITY-VIEW)
