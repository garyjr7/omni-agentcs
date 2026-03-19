from fastapi import APIRouter
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
router = APIRouter()

@router.post("/scan/full")
async def full_scan():
    from nexus_core.agents.generated.guardian_agent import full_security_scan, init_incidents_table
    init_incidents_table()
    return full_security_scan()

@router.post("/scan/secrets")
async def scan_secrets():
    from nexus_core.agents.generated.guardian_agent import scan_for_secrets, init_incidents_table
    init_incidents_table()
    incidents = scan_for_secrets()
    return {"incidents_found": len(incidents), "incidents": incidents}

@router.post("/scan/bandit")
async def bandit_scan():
    from nexus_core.agents.generated.guardian_agent import run_bandit_scan, init_incidents_table
    init_incidents_table()
    return run_bandit_scan()

@router.post("/scan/commits")
async def scan_commits():
    from nexus_core.agents.generated.guardian_agent import scan_recent_commits, init_incidents_table
    init_incidents_table()
    return scan_recent_commits()

@router.get("/incidents")
async def get_incidents():
    from nexus_core.agents.generated.guardian_agent import get_open_incidents, init_incidents_table
    init_incidents_table()
    incidents = get_open_incidents()
    return {"total": len(incidents), "incidents": incidents}
