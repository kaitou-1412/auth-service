# Makefile for Auth Service Development

.PHONY: help build restart deploy dev clean logs status test unit-test coverage port-forward port-forward-bg port-forward-db-bg stop-port-forward dev-watch describe shell db-shell minikube-status minikube-dashboard

# Variables
IMAGE_NAME := auth-service
IMAGE_TAG := latest
FULL_IMAGE := $(IMAGE_NAME):$(IMAGE_TAG)

help: ## Show this help message
	@echo "Auth Service - Development Commands"; \
	echo ""; \
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build Docker image directly inside minikube's Docker daemon (no image load needed)
	@echo "Building Docker image inside minikube..."; \
	eval $$(minikube docker-env) && docker build -t $(FULL_IMAGE) . && \
	echo "✓ Image built inside minikube: $(FULL_IMAGE)"

restart: ## Restart auth-service deployment only (not database)
	@echo "Restarting auth-service deployment..."; \
	kubectl rollout restart deployment auth-service && \
	echo "✓ Auth-service deployment restarted (database unchanged)" && \
	echo "Waiting for rollout to complete..." && \
	(kubectl rollout status deployment auth-service || echo "Rollout interrupted or failed")

deploy: build restart ## Deploy code changes (build inside minikube + restart)
	@echo ""; \
	echo "✓ Deployment complete! (auth-service updated, database unchanged)"; \
	echo "Run 'make dev-watch' to watch logs and enable port-forwarding"

dev: deploy ## Alias for deploy (use after code changes)

clean: ## Delete all Kubernetes resources
	@echo "Deleting Kubernetes resources..."; \
	kubectl delete -f k8s/ --ignore-not-found=true && \
	echo "✓ Resources deleted"

apply: ## Apply Kubernetes manifests (first time setup)
	@echo "Applying Kubernetes manifests..."; \
	kubectl apply -f k8s/ && \
	echo "✓ Manifests applied" && \
	echo "Waiting for deployment..." && \
	(kubectl rollout status deployment auth-service || echo "Rollout interrupted or failed")

setup: build apply ## First time setup: build inside minikube + apply manifests
	@echo ""; \
	echo "✓ Setup complete!"; \
	echo "Run 'make port-forward' to access at localhost:8080"

logs: ## Show pod logs (last 50 lines, follow mode)
	@echo "=== Following logs (Press Ctrl+C to exit) ==="; \
	echo ""; \
	kubectl logs -l app=auth-service --tail=50 -f || true; \
	echo ""; \
	echo "Log streaming stopped"

status: ## Show deployment status
	@echo "=== Auth Service Status ==="; \
	kubectl get deployment auth-service || true; \
	echo ""; \
	kubectl get pods -l app=auth-service || true; \
	echo ""; \
	kubectl get svc auth-service || true; \
	echo ""; \
	echo "=== Database Status ==="; \
	kubectl get deployment auth-db || true; \
	echo ""; \
	kubectl get pods -l app=auth-db || true; \
	echo ""; \
	kubectl get svc auth-db || true; \
	echo ""; \
	kubectl get pvc postgres-data || true

test: ## Test the health endpoint
	@echo "Testing health endpoint..."; \
	curl -s http://localhost:8080/v1/health || echo "Error: Make sure port-forward is running (make port-forward)"

unit-test: ## Run unit tests
	@echo "Running unit tests..."; \
	go test -v ./...

coverage: ## Run unit tests and open HTML coverage report in browser
	@echo "Running tests with coverage..."; \
	go test ./... -coverprofile=coverage.out && \
	go tool cover -html=coverage.out

coverage-cli: ## Run unit tests and browse coverage in terminal (requires: go install github.com/orlangure/gocovsh@latest)
	@echo "Running tests with coverage..."; \
	go test ./... -coverprofile=coverage.out && \
	gocovsh

port-forward: ## Forward service to localhost:8080 (blocking)
	@echo "Forwarding localhost:8080 -> service:80 -> pods:8080"; \
	echo "Press Ctrl+C to stop"; \
	echo ""; \
	kubectl port-forward svc/auth-service 8080:80 || true; \
	echo ""; \
	echo "Port forwarding stopped"

port-forward-bg: ## Start port-forward in background
	@echo "Starting port-forward in background..."; \
	nohup kubectl port-forward svc/auth-service 8080:80 > /dev/null 2>&1 & \
	PID=$$!; \
	echo $$PID > /tmp/auth-service-pf.pid; \
	sleep 2; \
	if [ -f /tmp/auth-service-pf.pid ] && ps -p $$PID > /dev/null 2>&1; then \
		echo "✓ Port-forward running in background (PID: $$PID)"; \
		echo "  Access at: http://localhost:8080"; \
		echo "  Stop with: make stop-port-forward"; \
	else \
		echo "✗ Failed to start port-forward"; \
		echo "  Check if service exists: kubectl get svc auth-service"; \
		rm -f /tmp/auth-service-pf.pid; \
		exit 1; \
	fi

port-forward-db-bg: ## Start DB port-forward in background
	@echo "Starting DB port-forward in background..."; \
	nohup kubectl port-forward svc/auth-db 5432:5432 > /dev/null 2>&1 & \
	PID=$$!; \
	echo $$PID > /tmp/auth-db-pf.pid; \
	sleep 2; \
	if [ -f /tmp/auth-db-pf.pid ] && ps -p $$PID > /dev/null 2>&1; then \
		echo "✓ DB port-forward running in background (PID: $$PID)"; \
		echo "  Access at: localhost:5432"; \
		echo "  Connection: psql -h localhost -p 5432 -U authuser -d authdb"; \
		echo "  Stop with: make stop-port-forward"; \
	else \
		echo "✗ Failed to start DB port-forward"; \
		echo "  Check if service exists: kubectl get svc auth-db"; \
		rm -f /tmp/auth-db-pf.pid; \
		exit 1; \
	fi

stop-port-forward: ## Stop all background port-forwards
	@echo "Stopping all port-forwards..."; \
	STOPPED=0; \
	if [ -f /tmp/auth-service-pf.pid ]; then \
		PID=$$(cat /tmp/auth-service-pf.pid); \
		if ps -p $$PID > /dev/null 2>&1; then \
			kill $$PID && echo "✓ Auth-service port-forward stopped (PID: $$PID)" && STOPPED=1; \
		fi; \
		rm -f /tmp/auth-service-pf.pid; \
	fi; \
	if [ -f /tmp/auth-db-pf.pid ]; then \
		PID=$$(cat /tmp/auth-db-pf.pid); \
		if ps -p $$PID > /dev/null 2>&1; then \
			kill $$PID && echo "✓ DB port-forward stopped (PID: $$PID)" && STOPPED=1; \
		fi; \
		rm -f /tmp/auth-db-pf.pid; \
	fi; \
	if [ $$STOPPED -eq 0 ]; then \
		echo "No port-forward PID files found"; \
		echo "Attempting to kill any kubectl port-forward processes..."; \
		pkill -f "kubectl port-forward" && echo "✓ Killed port-forward processes" || echo "No processes found"; \
	fi

dev-watch: ## Start port-forwards and watch logs (re-run after make deploy to restore port-forwards)
	@echo "Starting development environment..."; \
	make -s stop-port-forward 2>/dev/null || true; \
	make -s port-forward-bg && make -s port-forward-db-bg; \
	if [ $$? -eq 0 ]; then \
		echo ""; \
		echo "=== Live Server Logs (Press Ctrl+C to stop) ==="; \
		echo "Tip: after 'make deploy', run 'make dev-watch' again to restore port-forwards"; \
		echo ""; \
		sleep 1; \
		kubectl logs -l app=auth-service --tail=50 -f || true; \
		echo ""; \
		echo "✓ Dev-watch stopped"; \
		echo ""; \
		echo "To resume:"; \
		echo "  make dev-watch             # Restart everything"; \
		echo "  make port-forward-bg       # Just auth-service"; \
		echo "  make port-forward-db-bg    # Just database"; \
		echo "  make logs                  # Just logs"; \
		rm -f /tmp/auth-service-pf.pid /tmp/auth-db-pf.pid; \
	else \
		echo "Failed to start port-forwards. Check if pods are running: make status"; \
		make -s stop-port-forward 2>/dev/null || true; \
		exit 1; \
	fi

describe: ## Describe pods (useful for debugging)
	@echo "=== Pod Details ==="; \
	kubectl describe pods -l app=auth-service || true

shell: ## Open shell in auth-service pod
	@POD=$$(kubectl get pod -l app=auth-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null); \
	if [ -z "$$POD" ]; then \
		echo "Error: No pods found. Check if deployment is running: make status"; \
		exit 1; \
	fi; \
	echo "Opening shell in pod: $$POD"; \
	echo "Type 'exit' or press Ctrl+D to close the shell"; \
	echo ""; \
	kubectl exec -it $$POD -- sh || true; \
	echo ""; \
	echo "Shell session closed"

db-shell: ## Open psql shell in database pod
	@POD=$$(kubectl get pod -l app=auth-db -o jsonpath='{.items[0].metadata.name}' 2>/dev/null); \
	if [ -z "$$POD" ]; then \
		echo "Error: No database pods found. Check if deployment is running: make status"; \
		exit 1; \
	fi; \
	echo "Opening psql shell in pod: $$POD"; \
	echo "Database: authdb, User: authuser"; \
	echo "Type '\\q' or press Ctrl+D to close"; \
	echo ""; \
	kubectl exec -it $$POD -- psql -U authuser -d authdb || true; \
	echo ""; \
	echo "Database shell session closed"

minikube-status: ## Check if minikube is running
	@minikube status || true

minikube-dashboard: ## Open Minikube dashboard
	@echo "Opening Minikube dashboard..."; \
	echo "Dashboard will open in your browser"; \
	echo "Press Ctrl+C to stop"; \
	minikube dashboard --url
