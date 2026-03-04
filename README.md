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

# 3. Setup (first time only)
make setup

# 4. Start development
make dev-watch
```

Access:
- **API**: http://localhost:8080
- **Database**: localhost:5432
- **Dashboard**: `make minikube-dashboard`

## Development Workflow

```bash
# Make code changes
vim internal/handler/health_handler.go

# Deploy changes (rebuilds only auth-service, DB stays running)
make deploy

# Watch logs
make dev-watch
```

## Key Commands

| Command | Description |
|---------|-------------|
| `make setup` | First time setup (build + deploy everything) |
| `make deploy` | Deploy code changes (auth-service only) |
| `make dev-watch` | Port-forward + live logs |
| `make status` | Show all resources status |
| `make logs` | Follow pod logs |
| `make db-shell` | Open psql shell in database |
| `make clean` | Delete all resources |
| `make help` | Show all commands |

## Project Structure

```
.
├── cmd/server/           # Application entry point
├── internal/
│   ├── app/              # Router configuration
│   └── handler/          # HTTP handlers
├── k8s/                  # Kubernetes manifests
│   ├── configmap.yaml    # Configuration (gitignored)
│   └── *.yaml            # Deployments, services, etc.
├── Dockerfile            # Multi-stage build
└── Makefile              # Development commands
```

## Configuration

All configuration is in `k8s/configmap.yaml`:
- Application port
- Database credentials
- Database connection details

**Note:** `configmap.yaml` is gitignored. Use `configmap.sample.yaml` as template.

## Database

- **Type**: PostgreSQL 18.3
- **Storage**: 256Mi persistent volume
- **Connection**: `psql -h localhost -p 5432 -U authuser -d authdb`

## Architecture

```
┌──────────────┐     ┌─────────────┐
│ auth-service │────▶│   auth-db   │
│   (Go API)   │     │ (PostgreSQL)│
└──────────────┘     └─────────────┘
       │
       └─ ConfigMap (env vars)
```

## Endpoints

- `GET /v1/health` - Health check
- `GET /v1/err` - Error endpoint (testing)

## Notes

- Database data persists across pod restarts
- `make deploy` only restarts auth-service (database keeps running)
- Port-forwards stop when you exit `dev-watch` (restart with `make dev-watch`)
