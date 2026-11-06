# Prefer the project venv when it exists: a bare `ruff`/`python3` on PATH made
# `make lint` fail with exit 2 even though the tools were installed.
PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
RUFF ?= $(if $(wildcard .venv/bin/ruff),.venv/bin/ruff,ruff)
.PHONY: test test-unit test-offline test-postgres lint typecheck typecheck-strict audit test-coverage syntax doctor lock

# Base for the incremental type gate. Override it to typecheck a branch/PR:
#   make typecheck TYPECHECK_BASE=origin/main
#   make typecheck FILES="nexus_core/kernel/models.py"
TYPECHECK_BASE ?= HEAD
FILES ?=

test:
	$(PYTHON) -m pytest nexus_core/tests -q

# Coverage gate (V1-12). COVERAGE_MIN is a measured floor, not an aspiration:
# 86.2 % on 2026-11-06 over 314 product files (36,871 of 42,787 lines). It was
# measured by tracing the suite in chunks because one full traced run does not
# fit in 3.8 GB of RAM; the chunks that could be traced cover every package, and
# the group that could not (some TUI tests) only adds lines. CI traces the whole
# suite in one run, so its number is >= this one. Raise the floor in the same
# change that raises coverage; never lower it to let a change through.
COVERAGE_MIN ?= 86
test-coverage:
	$(PYTHON) -m pytest nexus_core/tests -q --cov=nexus_core \
		--cov-report=term-missing --cov-report=xml:coverage.xml \
		--cov-fail-under=$(COVERAGE_MIN)

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

# Full typing measurement for the security-critical core: no diff base, so every
# file in these packages is checked on every run. It is NOT a CI gate yet: on
# 2026-11-06 it reports 84 errors in 21 files (179 checked, 4.4 s) that the
# incremental gate never saw, because those files have not changed since it
# existed. 56 are [union-attr] on the Sliver/Metasploit clients being `X | None`
# and 6 are argv [list-item] in nopac (a `str | None` in argv is a real
# TypeError waiting for a missing flag). Wiring a gate that is red is
# decoration, so the ci.yml job lands in the change that takes the count to 0.
TYPECHECK_STRICT_PATHS ?= nexus_core/kernel nexus_core/tools nexus_core/scope
typecheck-strict:
	$(PYTHON) -m mypy $(TYPECHECK_STRICT_PATHS)

# SEC-11: dependency audit, blocking in CI. The only accepted advisory lives in
# AUDIT_IGNORES and is justified in SECURITY.md §4.1; anything else fails.
AUDIT_IGNORES ?= --ignore-vuln PYSEC-2026-2858
audit:
	$(PYTHON) -m pip_audit -r requirements-dev.lock --progress-spinner off $(AUDIT_IGNORES)

syntax:
	$(PYTHON) -m compileall -q nexus_core omni.py nexus_worker.py
	bash -n scripts/install_msfrpcd_service.sh scripts/list_models.sh

doctor:
	$(PYTHON) omni.py --doctor --no-wizard

# SEC-10: freeze the resolution CI installs (hashes de todos los artefactos
# publicados, no solo el wheel de esta máquina). Necesita red.
lock:
	$(PYTHON) scripts/lock_requirements.py requirements-dev.txt requirements-dev.lock --pypi-hashes
