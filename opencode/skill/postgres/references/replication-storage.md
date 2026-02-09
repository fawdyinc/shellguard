# Replication, Storage & Service Startup

Diagnostics for replication lag, disk/WAL/bloat issues, and PostgreSQL service startup failures.

## Replication

### Check Status from Primary

```bash
psql -c "SELECT client_addr, state, sent_lsn, write_lsn, flush_lsn, replay_lsn, pg_wal_lsn_diff(sent_lsn, replay_lsn) AS replay_lag_bytes FROM pg_stat_replication;"
```

### Check Status from Replica

```bash
# Is recovery active, and what's the lag?
psql -c "SELECT pg_is_in_recovery(), pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn(), pg_last_xact_replay_timestamp();"

# Lag in seconds
psql -c "SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0 ELSE EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()) END AS lag_seconds;"
```

### Replication Slots

Inactive slots prevent WAL cleanup and **will fill disk**. Check and clean up:

```bash
# List slots and retained WAL
psql -c "SELECT slot_name, slot_type, active, pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS retained_bytes FROM pg_replication_slots;"

# Drop an inactive slot that is no longer needed
# psql -c "SELECT pg_drop_replication_slot('slot_name');"
```

More detailed replication queries in [diagnostic-queries.md](./diagnostic-queries.md#replication).

See [replication docs](https://www.postgresql.org/docs/current/warm-standby.html), [replication slots docs](https://www.postgresql.org/docs/current/warm-standby.html#STREAMING-REPLICATION-SLOTS).

## Disk & Storage

### Database and Table Sizes

```bash
# Database sizes
psql -c "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size FROM pg_database ORDER BY pg_database_size(datname) DESC;"

# Largest tables (including indexes)
psql -c "SELECT schemaname || '.' || tablename AS table, pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS total_size FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC LIMIT 10;"
```

### Bloat and Vacuum

```bash
# Dead tuples needing VACUUM
psql -c "SELECT relname, n_dead_tup, n_live_tup, round(n_dead_tup::numeric / NULLIF(n_live_tup, 0) * 100, 1) AS dead_pct, last_autovacuum FROM pg_stat_user_tables WHERE n_dead_tup > 10000 ORDER BY n_dead_tup DESC LIMIT 10;"
```

More table health queries in [diagnostic-queries.md](./diagnostic-queries.md#table--index-health).

See [routine vacuuming docs](https://www.postgresql.org/docs/current/routine-vacuuming.html).

### WAL Directory

```bash
du -sh $(psql -tAc "SHOW data_directory;")/pg_wal/
```

If WAL is growing, check for inactive replication slots (above) or adjust `max_wal_size` / `wal_keep_size`. See [WAL config docs](https://www.postgresql.org/docs/current/runtime-config-wal.html).

### Temp Files

```bash
psql -c "SELECT datname, temp_files, pg_size_pretty(temp_bytes) AS temp_size FROM pg_stat_database WHERE temp_files > 0 ORDER BY temp_bytes DESC;"
```

High temp file usage indicates queries exceeding `work_mem` -- consider increasing it or optimizing the queries.

## Service Won't Start

```bash
# Check systemd status
systemctl status postgresql
journalctl -u postgresql --since "5 min ago"

# Port conflict?
ss -tlnp | grep 5432

# Data directory permissions
ls -la $(psql -tAc "SHOW data_directory;" 2>/dev/null || echo "/var/lib/postgresql/*/main")

# Stale PID file?
cat $(find /var/lib/postgresql -name postmaster.pid 2>/dev/null)

# Start manually for better error output
sudo -u postgres pg_ctl -D /var/lib/postgresql/<version>/main start
```

Common causes:

- **Stale `postmaster.pid`** -- remove if no process with that PID exists
- **Disk full** -- check `df -h` and WAL directory size
- **Corrupted `pg_control`** -- inspect with `pg_controldata`
- **Wrong permissions** on data directory -- must be owned by `postgres`, mode `0700`

See [server setup docs](https://www.postgresql.org/docs/current/runtime.html).
