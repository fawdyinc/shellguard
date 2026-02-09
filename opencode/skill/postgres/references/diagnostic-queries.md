# PostgreSQL Diagnostic Queries

Copy-paste SQL snippets for common investigations. All queries target PostgreSQL 12+.

## Connection State

```sql
-- Connection summary by state
SELECT state, count(*)
FROM pg_stat_activity
GROUP BY state ORDER BY count DESC;

-- Connections by application and client
SELECT application_name, client_addr, state, count(*)
FROM pg_stat_activity
GROUP BY 1, 2, 3 ORDER BY 4 DESC;

-- Long-idle connections (candidates for cleanup)
SELECT pid, usename, application_name, client_addr,
       now() - state_change AS idle_time
FROM pg_stat_activity
WHERE state = 'idle'
  AND now() - state_change > interval '10 minutes'
ORDER BY idle_time DESC;

-- Idle in transaction (dangerous - holds locks)
SELECT pid, usename, application_name,
       now() - xact_start AS xact_duration,
       left(query, 100) AS last_query
FROM pg_stat_activity
WHERE state = 'idle in transaction'
ORDER BY xact_duration DESC;
```

## Active Queries

```sql
-- Currently running queries sorted by duration
SELECT pid, usename, application_name,
       now() - query_start AS duration,
       wait_event_type, wait_event,
       state, left(query, 120) AS query
FROM pg_stat_activity
WHERE state != 'idle'
  AND pid != pg_backend_pid()
ORDER BY duration DESC;

-- Queries running longer than 1 minute
SELECT pid, usename, now() - query_start AS duration,
       left(query, 200)
FROM pg_stat_activity
WHERE state = 'active'
  AND now() - query_start > interval '1 minute'
ORDER BY duration DESC;
```

## Locks

```sql
-- Blocked queries and what's blocking them
SELECT
  blocked.pid AS blocked_pid,
  blocked.usename AS blocked_user,
  left(blocked.query, 80) AS blocked_query,
  now() - blocked.query_start AS blocked_duration,
  blocking.pid AS blocking_pid,
  blocking.usename AS blocking_user,
  left(blocking.query, 80) AS blocking_query,
  blocking.state AS blocking_state
FROM pg_stat_activity blocked
JOIN pg_locks bl ON bl.pid = blocked.pid
JOIN pg_locks kl ON kl.locktype = bl.locktype
  AND kl.database IS NOT DISTINCT FROM bl.database
  AND kl.relation IS NOT DISTINCT FROM bl.relation
  AND kl.page IS NOT DISTINCT FROM bl.page
  AND kl.tuple IS NOT DISTINCT FROM bl.tuple
  AND kl.pid != bl.pid
JOIN pg_stat_activity blocking ON kl.pid = blocking.pid
WHERE NOT bl.granted;

-- Lock types currently held
SELECT locktype, mode, granted, count(*)
FROM pg_locks
GROUP BY 1, 2, 3
ORDER BY 4 DESC;

-- Advisory locks (application-level)
SELECT pid, classid, objid, granted
FROM pg_locks
WHERE locktype = 'advisory';
```

## Performance / pg_stat_statements

```sql
-- Top queries by total execution time
SELECT calls,
       round(total_exec_time::numeric, 1) AS total_ms,
       round(mean_exec_time::numeric, 1) AS mean_ms,
       round(stddev_exec_time::numeric, 1) AS stddev_ms,
       rows,
       left(query, 120)
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 20;

-- Top queries by mean time (slowest individual executions)
SELECT calls,
       round(mean_exec_time::numeric, 1) AS mean_ms,
       round(total_exec_time::numeric, 1) AS total_ms,
       left(query, 120)
FROM pg_stat_statements
WHERE calls > 10
ORDER BY mean_exec_time DESC
LIMIT 20;

-- Queries with worst cache hit ratio
SELECT calls,
       shared_blks_hit,
       shared_blks_read,
       round(shared_blks_hit::numeric / NULLIF(shared_blks_hit + shared_blks_read, 0) * 100, 1) AS hit_pct,
       left(query, 120)
FROM pg_stat_statements
WHERE shared_blks_hit + shared_blks_read > 100
ORDER BY hit_pct ASC
LIMIT 20;
```

## Table & Index Health

```sql
-- Table sizes with bloat indicators
SELECT schemaname || '.' || relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size,
       pg_size_pretty(pg_relation_size(relid)) AS table_size,
       pg_size_pretty(pg_total_relation_size(relid) - pg_relation_size(relid)) AS index_size,
       n_live_tup,
       n_dead_tup,
       round(n_dead_tup::numeric / NULLIF(n_live_tup, 0) * 100, 1) AS dead_pct,
       last_autovacuum,
       last_autoanalyze
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 20;

-- Index usage rates (low idx_scan = potentially unused index)
SELECT schemaname || '.' || relname AS table_name,
       indexrelname,
       idx_scan,
       pg_size_pretty(pg_relation_size(indexrelid)) AS index_size
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC, pg_relation_size(indexrelid) DESC
LIMIT 20;

-- Tables needing vacuum most urgently
SELECT schemaname || '.' || relname AS table_name,
       n_dead_tup,
       last_autovacuum,
       last_vacuum,
       now() - COALESCE(last_autovacuum, last_vacuum, '1970-01-01'::timestamp) AS since_last_vacuum
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC
LIMIT 10;

-- Cache hit ratio by table
SELECT schemaname || '.' || relname AS table_name,
       heap_blks_read,
       heap_blks_hit,
       round(heap_blks_hit::numeric / NULLIF(heap_blks_hit + heap_blks_read, 0) * 100, 1) AS hit_pct
FROM pg_statio_user_tables
WHERE heap_blks_hit + heap_blks_read > 100
ORDER BY hit_pct ASC
LIMIT 10;
```

## Replication

```sql
-- Primary: replication status
SELECT client_addr, application_name, state,
       sent_lsn, write_lsn, flush_lsn, replay_lsn,
       pg_wal_lsn_diff(sent_lsn, replay_lsn) AS replay_lag_bytes,
       pg_wal_lsn_diff(sent_lsn, write_lsn) AS write_lag_bytes
FROM pg_stat_replication;

-- Replication slots and WAL retention
SELECT slot_name, slot_type, active, restart_lsn,
       pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS retained_bytes,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_pretty
FROM pg_replication_slots
ORDER BY pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) DESC;

-- Replica: recovery status and lag
SELECT pg_is_in_recovery() AS is_replica,
       pg_last_wal_receive_lsn(),
       pg_last_wal_replay_lsn(),
       pg_last_xact_replay_timestamp(),
       now() - pg_last_xact_replay_timestamp() AS replay_lag;
```

## Database-Level Stats

```sql
-- Database sizes
SELECT datname,
       pg_size_pretty(pg_database_size(datname)) AS size,
       numbackends AS connections,
       xact_commit AS commits,
       xact_rollback AS rollbacks,
       blks_read,
       blks_hit,
       round(blks_hit::numeric / NULLIF(blks_hit + blks_read, 0) * 100, 1) AS cache_hit_pct,
       temp_files,
       pg_size_pretty(temp_bytes) AS temp_size,
       deadlocks
FROM pg_stat_database
WHERE datname NOT LIKE 'template%'
ORDER BY pg_database_size(datname) DESC;

-- Overall cache hit ratio (should be > 99%)
SELECT round(
  sum(blks_hit)::numeric / NULLIF(sum(blks_hit) + sum(blks_read), 0) * 100, 2
) AS overall_cache_hit_pct
FROM pg_stat_database;
```

## Configuration Review

```sql
-- Non-default settings (what's been tuned)
SELECT name, setting, unit, source, sourcefile
FROM pg_settings
WHERE source != 'default'
  AND source != 'override'
ORDER BY category, name;

-- Key performance settings
SELECT name, setting, unit,
       CASE WHEN pending_restart THEN 'RESTART NEEDED' ELSE 'ok' END AS status
FROM pg_settings
WHERE name IN (
  'shared_buffers', 'effective_cache_size', 'work_mem',
  'maintenance_work_mem', 'max_connections', 'max_wal_size',
  'checkpoint_completion_target', 'random_page_cost',
  'effective_io_concurrency', 'max_worker_processes',
  'max_parallel_workers_per_gather'
)
ORDER BY name;
```
