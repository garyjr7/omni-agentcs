# Prefer the project venv when it exists: a bare `ruff`/`python3` on PATH made
# `make lint` fail with exit 2 even though the tools were installed.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
RUFF ?= $(if $(wildcard .venv/bin/ruff),.venv/bin/ruff,ruff)
.PHONY: test test-unit test-offline test-postgres lint typecheck syntax doctor

# Base for the incremental type gate. Override it to typecheck a branch/PR:
#   make typecheck TYPECHECK_BASE=origin/main
#   make typecheck FILES="nexus_core/kernel/models.py"
TYPECHECK_BASE ?= HEAD
FILES ?=

test:
	$(PYTHON) -m pytest nexus_core/tests -q

test-unit:
	$(PYTHON) -m pytest nexus_core/tests/unit -q

test-offline:
	$(PYTHON) -m unittest nexus_core.tests.unit.test_kernel_offline -v

test-postgres:
	$(PYTHON) -m nexus_core.tests.integration.postgres_smoke

lint:
	$(RUFF) check nexus_core omni.py nexus_worker.py --select F,E9

# Incremental typing gate (V1-9): the Python files changed since
# $(TYPECHECK_BASE) plus the new ones, test files included on purpose (excluding
# them would hide exactly where new code lacks types).
typecheck:
	@files="$(FILES)"; \
	if [ -z "$$files" ]; then \
	  git rev-parse --verify --quiet "$(TYPECHECK_BASE)^{commit}" >/dev/null \
	    || { echo "typecheck: TYPECHECK_BASE=$(TYPECHECK_BASE) no resuelve a un commit"; exit 2; }; \
	  files="$$( { git diff --name-only --diff-filter=ACMR $(TYPECHECK_BASE) -- '*.py'; \
	             git ls-files --others --exclude-standard -- '*.py'; } | sort -u | tr '\n' ' ')"; \
	fi; \
	if [ -z "$$files" ]; then echo "typecheck: no changed .py files vs $(TYPECHECK_BASE)"; exit 0; fi; \
	echo "typecheck: $$files"; \
	$(PYTHON) -m mypy $$files

syntax:
	$(PYTHON) -m compileall -q nexus_core omni.py nexus_worker.py
	bash -n scripts/install_msfrpcd_service.sh scripts/list_models.sh

doctor:
	$(PYTHON) omni.py --doctor --no-wizard
