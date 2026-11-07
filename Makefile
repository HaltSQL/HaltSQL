# HaltSQL developer tasks. Run `make help` for a list.

DUNE          ?= opam exec -- dune
OPAM          ?= opam
OCAMLFORMAT_VERSION := $(shell sed -n 's/^version *= *//p' .ocamlformat 2>/dev/null)
IMAGE         ?= ghcr.io/ardada2468/haltsql
VERSION       ?= $(shell sed -n 's/^(version \(.*\))/\1/p' dune-project)
LAB_DIR       ?= lab

# The lab is owned by lab/. Prefer lab/Makefile; fall back to lab/run.sh.
ifneq ($(wildcard $(LAB_DIR)/Makefile),)
LAB = $(MAKE) -C $(LAB_DIR)
else
LAB = $(LAB_DIR)/run.sh
endif

.DEFAULT_GOAL := build
.PHONY: help deps build test fmt fmt-check coverage bench lab-up lab-down lab-run docker clean

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

docker: ## Build the container image locally
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):dev .

clean: ## Remove build and coverage outputs
	$(DUNE) clean
	rm -rf _coverage
	find . -name 'bisect*.coverage' -not -path './_opam/*' -delete
