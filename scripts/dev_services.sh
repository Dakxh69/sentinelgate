#!/usr/bin/env bash
# Local no-root dev services (PostgreSQL 16.4 + Redis 7.4.1).
# Installed by environment prep — see specs/README.md environment notes.
# Usage: scripts/dev_services.sh {start|stop|status}
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SVC="$ROOT/.local-services"
PGBIN="$SVC/bin"
PGDATA="$SVC/pgdata"
PGPORT=5432
REDIS="$SVC/redis/bin"
REDIS_PORT=6379

pg_running() { "$PGBIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; }
redis_running() { "$REDIS/redis-cli" -p "$REDIS_PORT" ping >/dev/null 2>&1; }

start() {
  if pg_running; then
    echo "postgres: already running"
  else
    "$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGDATA/pg.log" -o "-p $PGPORT -k /tmp" start
  fi
  if redis_running; then
    echo "redis: already running"
  else
    "$REDIS/redis-server" --daemonize yes --port "$REDIS_PORT" \
      --dir "$SVC" --logfile redis.log --save "" --appendonly no
    sleep 1
  fi
  status
}

stop() {
  if pg_running; then "$PGBIN/pg_ctl" -D "$PGDATA" stop; else echo "postgres: not running"; fi
  if redis_running; then "$REDIS/redis-cli" -p "$REDIS_PORT" shutdown nosave; else echo "redis: not running"; fi
}

status() {
  if pg_running; then
    echo "postgres: RUNNING (127.0.0.1:$PGPORT, db=sentinelgate, user=postgres, trust auth — local dev only)"
  else
    echo "postgres: STOPPED"
  fi
  if redis_running; then
    echo "redis:    RUNNING (127.0.0.1:$REDIS_PORT, persistence off — local dev only)"
  else
    echo "redis:    STOPPED"
  fi
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  *) echo "usage: $0 {start|stop|status}" >&2; exit 2 ;;
esac
