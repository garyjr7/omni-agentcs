"""End-to-end test of the ``omni`` CLI. Opt-in via NEXUS_E2E=1.

Drives the real entry point (``omni.py``) as a subprocess: live model, live
nmap against the authorized ``scanme.nmap.org`` engagement and the real REPL
rendering. Skipped unless a real provider, the ``nmap`` binary and NEXUS_E2E=1
are all present, matching ``test_react_e2e.py``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore

ROOT = Path(__file__).resolve().parents[3]
ENTRY_POINT = ROOT / "omni.py"

try:  # keep the E2E opt-in but self-contained when a .env exists
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env", override=False)
except Exception:  # noqa: BLE001 - dotenv is optional here
    pass

E2E_ENABLED = os.getenv("NEXUS_E2E") == "1"
REAL_PROVIDER_CONFIGURED = any(
    os.getenv(name)
    for name in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "OLLAMA_BASE_URL")
)
SKIP_UNLESS_E2E = pytest.mark.skipif(
    not E2E_ENABLED, reason="set NEXUS_E2E=1 to run the live CLI test"
)
SKIP_WITHOUT_MODEL = pytest.mark.skipif(
    not REAL_PROVIDER_CONFIGURED, reason="no real LLM provider configured"
)
SKIP_WITHOUT_NMAP = pytest.mark.skipif(
    shutil.which("nmap") is None, reason="nmap binary is not installed"
)

SCANME_IPV4 = "45.33.32.156"
SCANME_IPV6 = "2600:3c01::f03c:91ff:fe18:bb2f"
OBJECTIVE = (
    "Escanea scanme.nmap.org en los puertos 22 y 80 usando nexus.recon.nmap "
    "y luego declara la tarea completa con los puertos encontrados."
)


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _create_engagement(database: Path) -> None:
    store = ControlStore(database)
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-scanme",
            tenant_id="system",
            name="scanme-test",
            client="nmap",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=(f"{SCANME_IPV4}/32", f"{SCANME_IPV6}/128"),
            domains=("scanme.nmap.org",),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )


@SKIP_UNLESS_E2E
@SKIP_WITHOUT_MODEL
@SKIP_WITHOUT_NMAP
def test_cli_one_shot_objective_completes(tmp_path):
    database = tmp_path / "cli-e2e.db"
    _create_engagement(database)
    environment = {**os.environ, "NEXUS_DB_PATH": str(database), "NEXUS_ENV": "development"}

    completed = subprocess.run(
        [
            sys.executable,
            str(ENTRY_POINT),
            "--tenant",
            "system",
            "--engagement",
            "eng-scanme",
            "--max-iterations",
            "6",
            "--no-color",
            "--objective",
            OBJECTIVE,
        ],
        cwd=str(ROOT),
        env=environment,
        capture_output=True,
        text=True,
        timeout=900,
    )
    stdout = completed.stdout
    assert "eng-scanme" in stdout, stdout
    assert "nexus.recon.nmap" in stdout, stdout
    # The successful nmap observation is rendered from its own evidence.
    assert "host(s) up" in stdout, stdout
    assert "puerto(s) abierto(s)" in stdout, stdout
    assert completed.returncode == 0, f"{stdout}\n{completed.stderr}"

    store = ControlStore(database)
    store.initialize()
    conversations = store.list_conversations("system", "omni")
    assert conversations, "the CLI did not persist a ReAct conversation"
    messages = store.list_messages("system", conversations[0]["id"], limit=500)
    assert messages[0]["metadata"].get("kind") == "react.system"
    assert any(message["metadata"].get("kind") == "react.observation" for message in messages)
