# Auth Service

Authentication service built with Go, running on Kubernetes with PostgreSQL.

## Prerequisites

- Docker
- Minikube
- kubectl
- Go 1.26+
- Make
- OpenSSL (for RSA key generation)

## Quick Start

```bash
# 1. Start minikube
minikube start

# 2. Copy and configure secrets
cp k8s/configmap.sample k8s/configmap.yaml
# Edit k8s/configmap.yaml with your values

# 3. First time setup (generates RSA keys, creates K8s secret, builds image, deploys)
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

# Deploy changes (builds inside minikube, applies manifests including keys secret)
make deploy

# Restore port-forwards and watch logs
make dev-watch
```

> After `make deploy` the pod restarts and port-forwards drop. Re-run `make dev-watch` to restore them.

## Key Commands

| Command              | Description                                           |
| -------------------- | ----------------------------------------------------- |
| `make setup`         | First time setup (generate keys + build + deploy)     |
| `make deploy`        | Build + apply keys + apply manifests                  |
| `make dev-watch`     | Start port-forwards + live logs                       |
| `make generate-keys` | Generate RSA key pair for JWT signing                 |
| `make apply-keys`    | Create/update K8s secret from RSA keys                |
| `make sqlc-generate` | Run sqlc generate                                     |
| `make unit-test`     | Run unit tests                                        |
| `make coverage`      | Run tests and open HTML coverage in browser           |
| `make coverage-cli`  | Run tests and browse coverage in terminal             |
| `make status`        | Show all resource statuses                            |
| `make logs`          | Follow pod logs                                       |
| `make db-shell`      | Open psql shell in database pod                       |
| `make clean`         | Delete all Kubernetes resources                       |
| `make help`          | Show all commands                                     |

## Project Structure

```
.
├── api/
│   └── openapi.yaml          # OpenAPI 3.0 spec (embedded into binary)
├── cmd/server/               # Application entry point
├── docs/
│   └── API-Documentation.md  # Detailed API documentation
├── internal/
│   ├── app/                  # Router setup
│   ├── db/
│   │   ├── store.go          # pgxpool connection
│   │   ├── migrations/       # goose SQL migrations
│   │   ├── queries/          # sqlc SQL queries
│   │   └── sqlc/             # Generated Go DB code
│   ├── handler/              # HTTP handlers (thin layer)
│   ├── keyutil/              # RSA key loading utilities
│   ├── middleware/           # HTTP middleware (logging, auth)
│   └── service/              # Business logic
├── keys/                     # RSA key pair (gitignored)
├── k8s/                      # Kubernetes manifests
│   ├── configmap.yaml        # Configuration (gitignored)
│   ├── jwt-keys-secret.yaml  # RSA keys K8s secret
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
       ├─ ConfigMap (env vars)
       └─ Secret (RSA keys mounted at /keys)
```

Request flow:

```
HTTP Request → Middleware → Handler → Service → DB (sqlc + pgx)
```

## Authentication

- **JWT Signing**: RS256 (RSA 2048-bit key pair)
- **Private key**: Loaded from `/keys/private.pem` (signs access tokens)
- **Public key**: Loaded from `/keys/public.pem` (verifies access tokens in auth middleware)
- **Access token expiry**: 15 minutes
- **Session expiry**: 24 hours
- **Refresh token expiry**: 30 days

Keys are generated locally in `keys/` and mounted into the pod via a Kubernetes Secret (`jwt-rsa-keys`).

## Configuration

All configuration is in `k8s/configmap.yaml`:

- Application port
- Database credentials and connection details
- JWT key file paths (`JWT_PRIVATE_KEY_PATH`, `JWT_PUBLIC_KEY_PATH`)

**Note:** `configmap.yaml` is gitignored. Use `configmap.sample.yaml` as template.

## Database

- **Type**: PostgreSQL 18.3
- **Storage**: 256Mi persistent volume
- **Connection**: `psql -h localhost -p 5432 -U authuser -d authdb`

## API

Full interactive docs available at `http://localhost:8080/swagger` when the service is running.

Detailed API documentation: [docs/API-Documentation.md](docs/API-Documentation.md)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/health` | Health check |
| `POST` | `/v1/auth/signup` | Create a new user (validates app, email, password) |
| `POST` | `/v1/auth/login` | Authenticate user and create session (validates app, email) |
| `POST` | `/v1/auth/token/refresh` | Rotate refresh token and issue new access token |
| `POST` | `/v1/auth/logout` | Logout from current session (requires auth) |
| `POST` | `/v1/auth/logout-all` | Logout from all devices (requires auth) |
| `POST` | `/v1/auth/password/change` | Change password (requires auth) |
| `GET` | `/v1/auth/sessions` | List all sessions (requires auth) |
| `DELETE` | `/v1/auth/sessions/{session_id}` | Revoke a specific session (requires auth) |
| `GET` | `/v1/auth/users/{user_id}/roles` | List roles for a user (requires auth) |
| `POST` | `/v1/auth/users/{user_id}/roles` | Assign a role to a user (requires auth) |
| `DELETE` | `/v1/auth/users/{user_id}/roles/{role_id}` | Remove a role from a user (requires auth) |

## Local Development Tools

### sqlc — SQL to Go code generator

```bash
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
sqlc version

# Regenerate Go code after editing queries in internal/db/queries/
make sqlc-generate
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
