CLUSTER := northwind
MANIFESTS := cluster/northwind

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk -F':.*?## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: check-deps ## Create the k3d cluster and deploy Northwind
	k3d cluster create --config cluster/k3d.yaml
	@echo "Waiting for the cluster to accept workloads..."
	kubectl wait --for=condition=Ready nodes --all --timeout=120s
	$(MAKE) deploy
	@echo
	@echo "Northwind is up. It is deliberately insecure — see cluster/attack.md."
	@echo "Front end: http://northwind.localhost:8080"

.PHONY: deploy
deploy: ## Apply the Northwind manifests to the current context
	kubectl apply -f $(MANIFESTS)/
	kubectl -n northwind-web rollout status deploy/web --timeout=120s
	kubectl -n northwind-orders rollout status deploy/orders --timeout=120s
	kubectl -n northwind-orders rollout status deploy/postgres --timeout=120s
	kubectl -n northwind-tracking rollout status deploy/tracking --timeout=120s

.PHONY: down
down: ## Delete the cluster and everything in it
	k3d cluster delete $(CLUSTER)

.PHONY: validate
validate: ## Parse the manifests offline (no cluster needed)
	@go run ./cmd/stathe check --manifests $(MANIFESTS)

.PHONY: validate-schema
validate-schema: ## Validate against a live API server (needs a cluster)
	kubectl apply --dry-run=server -f $(MANIFESTS)/ >/dev/null && \
		echo "manifests validate against the API server"

.PHONY: findings
findings: ## List the deliberate weaknesses and where they live
	@grep -rho 'stathe.io/findings: "[^"]*"' $(MANIFESTS) | \
		sed 's|stathe.io/findings: "||;s/"//' | tr ',' '\n' | sort -u | \
		while read id; do \
			printf "  %-7s %s\n" "$$id" "$$(grep -rl "$$id" $(MANIFESTS) | tr '\n' ' ')"; \
		done

.PHONY: check-deps
check-deps:
	@for t in docker k3d kubectl; do \
		command -v $$t >/dev/null 2>&1 || { echo "missing: $$t"; exit 1; }; \
	done
	@docker info >/dev/null 2>&1 || { echo "the docker daemon is not running"; exit 1; }

.PHONY: test
test: ## Run the test suite
	go test ./...

.PHONY: install
install: ## Install the stathe binary into $$GOPATH/bin
	go install ./cmd/stathe
