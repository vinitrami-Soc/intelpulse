.PHONY: help install dev test test-web test-ui lint audit artifact feeds seed up down logs clean

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install: ## create a venv and install backend dependencies
	cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

dev: ## run the API with reload on :8000
	cd backend && .venv/bin/uvicorn app.main:app --reload --port 8000

test: ## run the test suite
	cd backend && .venv/bin/pytest -q

test-web: ## engine parity + design-system guards (needs node >= 18)
	node --test web/tests/engine.test.mjs web/tests/tokens.test.mjs

test-ui: ## browser security + UX tests (needs playwright; serve web/ on :8123 first)
	node web/tests/ui.spec.mjs

lint: ## ruff check
	cd backend && .venv/bin/ruff check app tests

audit: ## check dependencies against the vulnerability database
	cd backend && .venv/bin/pip-audit -r requirements.txt

artifact: ## build the shareable demo bundle into dist/artifact
	node scripts/build-artifact.mjs

feeds: ## import every offline dataset (needs internet)
	cd backend && .venv/bin/python -m app.cli feeds --all

seed: ## load the bundled sample feed so an offline demo has hits
	cd backend && .venv/bin/python -m app.cli seed

up: ## docker compose up
	docker compose up --build -d

down: ## docker compose down
	docker compose down

logs: ## follow api + worker logs
	docker compose logs -f api worker

clean: ## remove local databases and caches
	rm -f backend/data/*.db
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
