import asyncio
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dotenv import load_dotenv

# override=True porque el shell puede tener vars stale
load_dotenv(ROOT / ".env", override=True)

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import build_default_registry, ExecutionContext
from nexus_core.scope import EngagementScope, EngagementStore

store = ControlStore("/tmp/react_e2e.db")
store.initialize()
EngagementStore(store).create(EngagementScope(
    engagement_id="eng-scanme",
    tenant_id="system",
    name="scanme-test",
    client="NEXUS",
    owner_id="test",
    valid_from="2025-01-01T00:00:00+00:00",
    valid_until="2030-01-01T00:00:00+00:00",
    cidrs=("45.33.32.156/32", "2600:3c01::f03c:91ff:fe18:bb2f/128"),
    domains=("scanme.nmap.org",),
    urls=(),
    exclusions=(),
    notes="",
))

run = store.create_run("system", {"source": "manual-e2e"}, "e2e-react-1")
task = store.enqueue_task(
    tenant_id="system",
    run_id=run["id"],
    task_type="react.run",
    payload={
        "objective": "Escanea scanme.nmap.org en puertos 22 y 80",
        "engagement_id": "eng-scanme",
        "max_iterations": 4,
        "identity": {"subject_id": "test", "roles": ["operator"]},
    },
)
claimed = store.claim_task("worker-e2e")
print(f"Task claimed: {claimed['id']}")

ctx = ExecutionContext(store=store, task=claimed, worker_id="worker-e2e")
result = asyncio.run(build_default_registry().execute(claimed, ctx))

print("=" * 60)
print(f"STATUS:     {result['status']}")
print(f"ITERATIONS: {result['iterations']}")
print(f"SUMMARY:    {(result.get('summary') or '(none)')[:400]}")
print("ACTIONS:")
for a in result.get("actions", []):
    tool = a.get("tool_id", "?")
    ok = a.get("success", a.get("status", "?"))
    print(f"  [{a.get('iteration')}] {tool} -> {ok}")
