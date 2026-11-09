# haltlab — see README.md.  Usage: make up; make smoke; make down
PY      ?= .venv/bin/python
COMPOSE ?= docker compose -f infra/compose/docker-compose.yml
PROFILE ?=
SCENARIO ?= scenarios/pr-smoke.yaml

.PHONY: venv up down run smoke proxy-smoke selftest matrix compat-up compat compat-down validate test test-integration clean \
	catalog-tier3 catalog-tier3-example

venv:
	test -x $(PY) || (python3 -m venv .venv && .venv/bin/pip install -q -r requirements-dev.txt)

up:
	$(COMPOSE) $(if $(PROFILE),--profile $(PROFILE)) up -d --wait

down:
	$(COMPOSE) --profile matrix --profile chaos down -v

run: venv
	$(PY) -m harness run $(SCENARIO)

smoke: venv
	$(PY) -m harness run scenarios/pr-smoke.yaml

# Sends every generated query through a live haltsql-proxy (see proxy/README.md).
proxy-smoke: venv
	$(PY) -m proxy run proxy/scenarios/proxy-smoke.yaml

selftest: venv
	$(PY) -m harness run scenarios/oracle-selftest.yaml --fake-verifier allow

matrix: venv
	$(MAKE) up PROFILE=matrix
	$(PY) -m harness run scenarios/matrix-pg13-17.yaml

# Postgres flavour compatibility runs (compat/run.sh, docs/compatibility.md).
# ENGINES: engine names or "all" (default), e.g. make compat ENGINES="pg18 citus".
ENGINES ?= all

compat-up:
	compat/run.sh up

compat: venv
	compat/run.sh local $(ENGINES)

compat-down:
	compat/run.sh down

# Tier-3 check for data-catalog integrations (catalogs/README.md): PII tagged in
# the manifest must be blocked against real Postgres, and a negative control
# without the tags must leak. make catalog-tier3 PII=path/to/pii.json
PII ?=
FIXTURE ?= saas_shared
MODE ?= both
TIER3_ARGS ?=

catalog-tier3: venv
	@test -n "$(PII)" || (echo "usage: make catalog-tier3 PII=path/to/pii.json [FIXTURE=saas_shared] [MODE=both|positive|negative]" >&2; exit 2)
	$(PY) -m catalogs.tier3 $(foreach p,$(PII),--pii $(abspath $(p))) --fixture $(FIXTURE) --mode $(MODE) $(TIER3_ARGS)

# The same check on the sample dbt export (examples/metadata/dbt_manifest.json).
HALTSQL ?= $(or $(HALTSQL_BIN),../_build/default/bin/haltsql/main.exe)

catalog-tier3-example: venv
	mkdir -p out/catalog-tier3
	$(HALTSQL) schema import --from dbt ../examples/metadata/dbt_manifest.json -o out/catalog-tier3/pii.dbt.json
	$(MAKE) catalog-tier3 PII=out/catalog-tier3/pii.dbt.json

validate: venv
	$(PY) -m harness validate scenarios/*.yaml

test: venv
	$(PY) -m pytest -q -m "not integration"

test-integration: venv
	$(PY) -m pytest -q -m integration

clean:
	rm -rf out .pytest_cache
