.PHONY: test test-offline test-api test-mcp test-postgres lint typecheck syntax frontend-build

test-offline:
	python3 -m unittest nexus_core.tests.unit.test_kernel_offline -v

test:
	python3 -m pytest nexus_core/tests -q

test-api:
	python3 -m nexus_api.tests.api_smoke

test-mcp:
	python3 -m nexus_mcp.tests.smoke

test-postgres:
	python3 -m nexus_core.tests.integration.postgres_smoke

lint:
	ruff check --select E4,E7,E9,F,I \
		nexus_core/kernel nexus_core/evolution nexus_core/llm/abstraction.py \
		nexus_api/auth nexus_api/config.py nexus_api/main.py \
		nexus_api/routes/a2a.py nexus_api/routes/approvals.py \
		nexus_api/routes/connectors.py nexus_api/routes/directory.py \
		nexus_api/routes/evolution.py nexus_api/routes/packages.py \
		nexus_api/routes/policies.py nexus_mcp nexus_cli.py nexus_worker.py nexus_connector.py \
		nexus_api/routes/sovereign.py nexus_core/kernel/runtime.py nexus_core/kernel/knowledge.py

typecheck:
	mypy --ignore-missing-imports --follow-imports=skip \
		nexus_core/kernel/models.py nexus_core/kernel/schema_validation.py \
		nexus_core/kernel/policy.py nexus_core/kernel/memory.py \
		nexus_core/kernel/workflows.py nexus_core/kernel/connectors.py \
		nexus_core/kernel/packages.py nexus_core/kernel/artifacts.py \
		nexus_core/kernel/audit.py nexus_core/kernel/approvals.py \
		nexus_core/kernel/directory.py nexus_core/kernel/migrations.py \
		nexus_core/kernel/runtime.py nexus_core/kernel/knowledge.py \
		nexus_connector.py nexus_mcp

syntax:
	python3 -m compileall -q nexus_api nexus_core nexus_mcp nexus_cli.py nexus_worker.py
	bash -n install.sh
	bash -n nexus_start.sh

frontend-build:
	npm --prefix nexus_frontend ci
	npm --prefix nexus_frontend run lint
	npm --prefix nexus_frontend run build
