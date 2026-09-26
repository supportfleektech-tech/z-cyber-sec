# CYBER-SEC lab — one place for every routine action.
#
# `make lab` is the whole thing: virtualenv, dependencies, SPA build, seeded
# database, app on http://localhost:8080. Everything else is a single step of it
# (or a check to run after). Nothing here deletes data: `make reseed` and
# `make clean` say what they remove.
#
# Requires: python3.11+, node 20+, docker (only for the lab range targets).

SHELL := /bin/bash
ROOT  := $(CURDIR)
BE    := $(ROOT)/app/backend
FE    := $(ROOT)/app/frontend
VENV  := $(BE)/.venv
PY    := $(VENV)/bin/python
PIP   := $(VENV)/bin/pip
PORT  ?= 8080
BASE_URL ?= http://127.0.0.1:$(PORT)
LAB_COMPOSE := $(ROOT)/infra/lab/docker-compose.yml
LAB_PROFILES ?= --profile juice --profile api

.DEFAULT_GOAL := help
.PHONY: help lab setup venv deps spa seed reseed-reset run test lint rules smoke \
        accept doctor lab-up lab-down lab-status backup-drill loadtest clean

help:  ## this list
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

lab: setup seed-keep spa  ## full local lab: deps, DB (seeded if empty), SPA, then `make run`
	@echo "==> ready. Start it with: make run   (login admin / CyberSecAdmin1!)"

setup: venv deps  ## create the virtualenv and install backend + frontend deps

venv:
	@test -d $(VENV) || python3 -m venv $(VENV)

deps: venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -r $(BE)/requirements.txt

spa:  ## build the SPA the backend serves
	cd $(FE) && (test -d node_modules || npm ci) && npm run build

seed:  ## seed a fresh database (refuses if users already exist; use reseed-reset to start over)
	cd $(BE) && $(VENV)/bin/python -m app.seed.seed_demo

seed-keep:  ## seed only if the database does not exist yet
	@test -f $(BE)/data/cybersec.db || $(MAKE) --no-print-directory seed

reseed-reset:  ## DESTRUCTIVE: delete the database and backups under app/backend/data, then reseed
	@read -p "delete app/backend/data/cybersec.db* and backups/? [y/N] " ans; \
	  [[ $$ans == y || $$ans == Y ]] || { echo "aborted"; exit 1; }
	rm -f $(BE)/data/cybersec.db*
	$(MAKE) --no-print-directory seed

run:  ## serve the app + SPA on $(PORT) (Ctrl-C to stop)
	cd $(BE) && $(VENV)/bin/uvicorn app.main:app --host 0.0.0.0 --port $(PORT)

test:  ## full pytest suite
	cd $(BE) && $(VENV)/bin/python -m pytest -q

lint:  ## ruff over app/, scripts/, tests/
	cd $(BE) && $(VENV)/bin/ruff check app/ scripts/ tests/

rules:  ## every detection rule must be able to fire (SEC-074)
	cd $(BE) && $(VENV)/bin/python -m scripts.lint_rules

smoke:  ## live surface + RBAC against a running instance (SEC-114b)
	cd $(BE) && $(VENV)/bin/python -m scripts.smoke_check --base-url $(BASE_URL)

accept:  ## acceptance clauses of planning/acceptance-criteria.md (SEC-118)
	cd $(BE) && $(VENV)/bin/python -m scripts.acceptance_check --base-url $(BASE_URL)

doctor:  ## the app's own self-diagnosis (SEC-116)
	cd $(BE) && $(VENV)/bin/python -m scripts.doctor_report --base-url $(BASE_URL)

backup-drill:  ## backup/restore rehearsal, both modes (SEC-063)
	cd $(BE) && $(VENV)/bin/python -m scripts.backup_rehearsal

loadtest:  ## capacity measurement against a running instance (SEC-043)
	cd $(BE) && $(VENV)/bin/python -m scripts.load_test --base-url $(BASE_URL)

lab-up:  ## start the vulnerable range targets (loopback-only; needs docker)
	docker compose -f $(LAB_COMPOSE) $(LAB_PROFILES) up -d

lab-down:  ## stop the range targets
	docker compose -f $(LAB_COMPOSE) down

lab-status:  ## what the range is doing, straight from the platform
	@echo "containers:"; docker compose -f $(LAB_COMPOSE) ps 2>/dev/null || true
	@echo; echo "registration + cross-checks (needs a session):"
	@echo "  curl -s $(BASE_URL)/api/lab/coverage -b cookie.txt | jq '.ok, .counts'"

clean:  ## remove build artifacts only (no data, no dependencies)
	rm -rf $(FE)/dist $(BE)/.pytest_cache $(BE)/tests/.testdata
	find $(BE) -name __pycache__ -type d -prune -exec rm -rf {} +
