# HaltSQL developer tasks. Run `make help` for a list.

DUNE          ?= opam exec -- dune
OPAM          ?= opam
OCAMLFORMAT_VERSION := $(shell sed -n 's/^version *= *//p' .ocamlformat 2>/dev/null)
IMAGE         ?= ghcr.io/haltsql/haltsql
VERSION       ?= $(shell sed -n 's/^(version \(.*\))/\1/p' dune-project)
LAB_DIR       ?= lab
PYTHON        ?= python3
DIAGRAMS_VENV ?= deploy/diagrams/.venv

# The lab is owned by lab/. Prefer lab/Makefile; fall back to lab/run.sh.
ifneq ($(wildcard $(LAB_DIR)/Makefile),)
LAB = $(MAKE) -C $(LAB_DIR)
else
LAB = $(LAB_DIR)/run.sh
endif

.DEFAULT_GOAL := build
.PHONY: help deps build test fmt fmt-check doc coverage bench diagrams lab-up lab-down lab-run docker smoke e2e e2e-up e2e-down clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Install OCaml dependencies, test dependencies and the pinned ocamlformat
	$(OPAM) install . --deps-only --with-test --yes
	$(OPAM) install --yes ocamlformat.$(OCAMLFORMAT_VERSION) bisect_ppx

build: ## Build everything
	$(DUNE) build

test: ## Run all tests
	$(DUNE) test

fmt: ## Format OCaml and dune files in place
	-$(DUNE) build @fmt --auto-promote
	@echo "Formatted."

fmt-check: ## Fail if any file is not formatted
	$(DUNE) build @fmt

doc: ## Build the API reference with odoc; HTML in _build/default/_doc/_html/
	$(DUNE) build @doc

diagrams: ## Regenerate the cloud architecture PNGs in docs/assets/cloud/ (needs Graphviz)
	@command -v dot >/dev/null || { echo "Graphviz 'dot' is required: brew install graphviz / apt-get install graphviz"; exit 1; }
	@test -x $(DIAGRAMS_VENV)/bin/python || $(PYTHON) -m venv $(DIAGRAMS_VENV)
	$(DIAGRAMS_VENV)/bin/pip install --quiet -r deploy/diagrams/requirements.txt
	@for f in deploy/diagrams/[a-z]*.py; do echo "  $$f"; $(DIAGRAMS_VENV)/bin/python $$f || exit 1; done

coverage: ## Run tests with bisect_ppx; HTML report in _coverage/
	rm -rf _coverage
	find . -name 'bisect*.coverage' -not -path './_opam/*' -delete
	$(DUNE) runtest --instrument-with bisect_ppx --force
	opam exec -- bisect-ppx-report html -o _coverage
	opam exec -- bisect-ppx-report summary --per-file

bench: ## Run benchmarks (dune alias @bench), if any are defined
	@if grep -rqsE '\((alias|name) bench\)' --include=dune test bench 2>/dev/null; then \
	  $(DUNE) build @bench --force; \
	else \
	  echo "No benchmarks defined yet (expected a dune rule with alias 'bench')."; \
	fi

lab-up: ## Start the enterprise lab (Docker Compose)
	$(LAB) up

lab-run: ## Run lab scenarios; report is written under lab/out/
	$(LAB) run

lab-down: ## Stop the lab and remove its containers and volumes
	$(LAB) down

docker: ## Build the container image locally (also tagged haltsql-local:dev for scripts/docker-smoke.sh)
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):dev -t haltsql-local:dev .

smoke: ## Smoke-test the haltsql-local:dev image (scripts/docker-smoke.sh; run `make docker` first)
	scripts/docker-smoke.sh

e2e: ## End-to-end suite (test/e2e): stack up, pytest, stack down; KEEP=1 keeps the stack, E2E_ARGS for pytest
	$(DUNE) build ./bin/haltsql/main.exe ./bin/server/main.exe ./bin/proxy/main.exe
	KEEP=$(KEEP) test/e2e/stack.sh run $(E2E_ARGS)

e2e-up: ## Start the end-to-end stack (Docker Compose project haltsql-e2e) and leave it running
	test/e2e/stack.sh up

e2e-down: ## Stop the end-to-end stack and delete its volumes
	test/e2e/stack.sh down

clean: ## Remove build and coverage outputs
	$(DUNE) clean
	rm -rf _coverage
	find . -name 'bisect*.coverage' -not -path './_opam/*' -delete
