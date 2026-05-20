# Deployment Guide

## Requirements

- Docker 24+ and Docker Compose v2
- PostgreSQL 15+ (provided via Compose)
- Redis 7+ (provided via Compose)

## Quick Start (Docker Compose)

```bash
cp .env.example .env
# Edit .env — at minimum set JWT_SECRET and FRONTEND_URL

# Generate a secure JWT_SECRET:
python -c "import secrets; print(secrets.token_hex(32))"

docker compose up -d
```

Access:
- API: `http://localhost/api/v1/`
- Docs: `http://localhost/api/docs`
- Health: `http://localhost/health`

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `JWT_SECRET` | **Yes** | — | Min 32 chars, cryptographically random |
| `DATABASE_URL` | Yes in prod | SQLite | PostgreSQL for production |
| `REDIS_URL` | Yes | `redis://localhost:6379` | ARQ task queue + rate limiting |
| `APP_ENV` | No | `development` | `development` / `staging` / `production` |
| `REQUIRE_AUTH` | No | `false` | Set `true` in staging/production |
| `FRONTEND_URL` | No | `http://localhost:5173` | CORS origin |
| `STORAGE_BACKEND` | No | `local` | `local` or `s3` |

See `.env.example` for full documentation of all variables.

## Production Checklist

- [ ] `JWT_SECRET` is ≥32 random chars (not in any examples)
- [ ] `DATABASE_URL` points to PostgreSQL (not SQLite)
- [ ] `REQUIRE_AUTH=true`
- [ ] `APP_ENV=production`
- [ ] TLS termination in front of nginx
- [ ] `FRONTEND_URL` set to actual frontend domain
- [ ] All OIDC secrets rotated from defaults

## Database Migrations

```bash
# Apply all migrations
alembic upgrade head

# Check current revision
alembic current

# Generate new migration after model changes
alembic revision --autogenerate -m "description"
```

## Scaling

- **API**: stateless — run multiple replicas behind load balancer
- **Worker**: stateless — run multiple `arq core.worker.WorkerSettings` replicas
- **PostgreSQL**: use managed service (RDS, Cloud SQL, Supabase) in production
- **Redis**: use managed service (ElastiCache, Redis Cloud) in production
- **Storage**: set `STORAGE_BACKEND=s3` with S3/MinIO for shared file access across replicas

## Optional Components

### S3-compatible storage (MinIO locally)

Uncomment the `minio` service in `docker-compose.yml`, then:

```bash
STORAGE_BACKEND=s3
S3_BUCKET=vulnaudit-scans
S3_ENDPOINT_URL=http://minio:9000
S3_ACCESS_KEY_ID=minioadmin
S3_SECRET_ACCESS_KEY=minioadmin
```

### Stripe billing

```bash
pip install "vulnerability-detector[billing]"

STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO_MONTHLY=price_...
STRIPE_PRICE_ENTERPRISE_MONTHLY=price_...
```

### SSO / OIDC

See [auth.md](auth.md#oidc-sso).
