ifneq (,$(wildcard ./.env))
include .env
export
endif

COMPOSE_FILE ?= compose.yaml
POSTGRES_SERVICE ?= postgres

.PHONY: run migrate tidy deps-up deps-down deps-logs wait-postgres

run:
	go run ./cmd/server

migrate: deps-up wait-postgres
	MIGRATE_ONLY=1 go run ./cmd/server

deps-up:
	docker compose -f $(COMPOSE_FILE) up -d $(POSTGRES_SERVICE)

wait-postgres:
	@echo "Waiting for Postgres to be ready..."
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60; do \
		docker compose -f $(COMPOSE_FILE) exec -T $(POSTGRES_SERVICE) pg_isready -U ghapp_demo -d ghapp_demo >/dev/null 2>&1 && exit 0; \
		sleep 1; \
	done; \
	echo "Postgres did not become ready in time"; \
	exit 1

deps-down:
	docker compose -f $(COMPOSE_FILE) down

deps-logs:
	docker compose -f $(COMPOSE_FILE) logs $(POSTGRES_SERVICE)

tidy:
	go mod tidy
