# Auth Service

Authentication service built with Go, running on Kubernetes with PostgreSQL.

## Prerequisites

- Docker
- Minikube
- kubectl
- Go 1.26+
- Make

## Quick Start

```bash
# 1. Start minikube
minikube start

# 2. Copy and configure secrets
cp k8s/configmap.sample.yaml k8s/configmap.yaml
# Edit k8s/configmap.yaml with your values

# 3. First time setup (builds image inside minikube + deploys)
make setup

# 4. Start development
make dev-watch
```

Access:

- **API**: http://localhost:8080
- **API Docs**: http://localhost:8080/swagger
- **Database**: localhost:5432
- **Dashboard**: `make minikube-dashboard`

## Development Workflow

```bash
# Make code changes
vim internal/service/auth_service.go

# Deploy changes (builds inside minikube, restarts auth-service only, DB stays running)
make deploy

# Restore port-forwards and watch logs
make dev-watch
```

> After `make deploy` the pod restarts and port-forwards drop. Re-run `make dev-watch` to restore them.

## Key Commands

| Command              | Description                                        |
| -------------------- | -------------------------------------------------- |
| `make setup`         | First time setup (build inside minikube + deploy)  |
| `make deploy`        | Build + restart auth-service (DB untouched)        |
| `make dev-watch`     | Start port-forwards + live logs                    |
| `make unit-test`     | Run unit tests                                     |
| `make coverage`      | Run tests and open HTML coverage in browser        |
| `make coverage-cli`  | Run tests and browse coverage in terminal          |
| `make status`        | Show all resource statuses                         |
| `make logs`          | Follow pod logs                                    |
| `make db-shell`      | Open psql shell in database pod                    |
| `make clean`         | Delete all Kubernetes resources                    |
| `make help`          | Show all commands                                  |

## Project Structure

```
.
├── api/
│   └── openapi.yaml          # OpenAPI 3.0 spec (embedded into binary)
├── cmd/server/               # Application entry point
├── internal/
│   ├── app/                  # Router setup
│   ├── db/
│   │   ├── store.go          # pgxpool connection
│   │   ├── migrations/       # goose SQL migrations
│   │   ├── queries/          # sqlc SQL queries
│   │   └── sqlc/             # Generated Go DB code
│   ├── handler/              # HTTP handlers (thin layer)
│   ├── middleware/           # HTTP middleware (logging)
│   └── service/              # Business logic
├── k8s/                      # Kubernetes manifests
│   ├── configmap.yaml        # Configuration (gitignored)
│   └── *.yaml                # Deployments, services, etc.
├── Dockerfile                # Multi-stage build
└── Makefile                  # Development commands
```

## Architecture

```
┌──────────────┐     ┌─────────────┐
│ auth-service │────▶│   auth-db   │
│   (Go API)   │     │ (PostgreSQL)│
└──────────────┘     └─────────────┘
       │
       └─ ConfigMap (env vars)
```

Request flow:

```
HTTP Request → Middleware → Handler → Service → DB (sqlc + pgx)
```

## Configuration

All configuration is in `k8s/configmap.yaml`:

- Application port
- Database credentials and connection details

**Note:** `configmap.yaml` is gitignored. Use `configmap.sample.yaml` as template.

## Database

- **Type**: PostgreSQL 18.3
- **Storage**: 256Mi persistent volume
- **Connection**: `psql -h localhost -p 5432 -U authuser -d authdb`

## API

Full interactive docs available at `http://localhost:8080/swagger` when the service is running.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Health check |
| `POST` | `/v1/auth/signup` | Create a new user |
| `POST` | `/v1/auth/login` | Authenticate user and create session |
| `POST` | `/v1/auth/logout` | Logout from current session (requires auth) |

## Local Development Tools

### sqlc — SQL to Go code generator

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
sqlc version

# Regenerate Go code after editing queries in internal/db/queries/
sqlc generate
```

### goose — Database migrations

```bash
go install github.com/pressly/goose/v3/cmd/goose@latest
goose -version
```

Requires DB port-forward running (`make dev-watch` or `make port-forward-db-bg`):

```bash
# Run all pending migrations
goose -dir internal/db/migrations postgres \
  "host=localhost port=5432 user=authuser password=<password> dbname=authdb sslmode=disable" up

# Roll back the last migration
goose -dir internal/db/migrations postgres \
  "host=localhost port=5432 user=authuser password=<password> dbname=authdb sslmode=disable" down
```

### gocovsh — Terminal coverage browser (optional)

```bash
go install github.com/orlangure/gocovsh@latest
make coverage-cli
```

## Notes

- `make deploy` builds the image **inside minikube's Docker daemon** — no `minikube image load` needed
- Database data persists across pod restarts (PersistentVolume)
- Port-forwards stop when the pod restarts — re-run `make dev-watch` to restore
