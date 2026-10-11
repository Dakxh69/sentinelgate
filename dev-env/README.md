# SentinelGate development environments

You can run this project in two ways, and they use slightly different env files.
Pick the file that matches how you started the services, then follow the matching
section of TESTING-GUIDE.md.

## Bare-metal local run (the path most contributors use in tests)

The gateway, backend, Postgres and Redis all run on the same host.

```bash
cp .env.dev .env        # if you want a ready-made dev file, otherwise .env.example → .env
```

`.env.dev` is tuned for a single-host dev environment:
- `BACKEND_URL=http://127.0.0.1:8001` — the internal backend is on the same host.
- `DATABASE_URL` / `REDIS_URL` point to localhost (override if your PG/Redis live elsewhere).

The gateway code itself now defaults to `http://127.0.0.1:8001` (see
`backend/app/core/config.py`), so a clone that followed the `Path B` walkthrough
in TESTING-GUIDE.md works without any environment surgery.

## Docker Compose deploy

Use `.env.docker` (or edit `.env.example`'s production-style values) and override these in `.env`:
- `BACKEND_URL=http://backend:8001` — the Docker service name, not localhost.
- `DATABASE_URL` / `REDIS_URL` pointing at the Compose services (postgres / redis).

Run `docker compose up -d`. The gateway only publishes port 8000; the backend stays
private on the isolated Docker network for zero-trust boundary enforcement.
