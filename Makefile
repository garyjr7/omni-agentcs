PYTHON ?= python3
RUFF ?= ruff
.PHONY: test test-unit test-offline test-postgres lint syntax doctor

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

syntax:
	$(PYTHON) -m compileall -q nexus_core omni.py nexus_worker.py
	bash -n scripts/install_msfrpcd_service.sh scripts/list_models.sh

doctor:
	$(PYTHON) omni.py --doctor --no-wizard
