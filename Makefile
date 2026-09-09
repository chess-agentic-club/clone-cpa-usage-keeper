.PHONY: verify verify-backend verify-frontend verify-docker

# The parent integration repository owns the Open WebUI demo and cross-app E2E;
# this target intentionally verifies every backend/frontend artifact in Keeper.
verify: verify-backend verify-frontend

verify-backend:
	go test ./cmd/... ./internal/...

verify-frontend:
	npm --prefix ./web ci
	npm --prefix ./web run test
	npm --prefix ./web run lint
	npm --prefix ./web run typecheck
	npm --prefix ./web run build

verify-docker:
	docker build -t cpa-usage-keeper:ci .
