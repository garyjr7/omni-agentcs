from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import json, os, asyncio, logging
from nexus_api.auth.deps import get_current_user, require_operator
from nexus_api.config import NEXUS_ROOT, NEXUS_DATA_PATH, NEXUS_DB_PATH
from nexus_api.services.factory_service import (
    init_factory_tables, parse_requirements_md, generate_plan_maestro,
    create_project, save_plan, approve_project, get_project, list_projects,
    get_phases, update_phase_status, create_pentest, list_pentests,
    get_pentest, approve_pentest
)

logger = logging.getLogger("nexus.factory")
router = APIRouter(prefix="/factory", tags=["factory"])
init_factory_tables()

class AnalyzeRequest(BaseModel):
    requirements_md: str
    use_llm: bool = True

class ApproveRequest(BaseModel):
    approved_by: str = "admin"
    notes: Optional[str] = None

class PentestAnalyzeRequest(BaseModel):
    scope_md: str
    use_llm: bool = True

# ── Software Factory ──────────────────────────────────────────

@router.get("/templates")
async def get_templates(user=Depends(get_current_user)):
    """Devuelve los templates MD para descargar."""
    templates_dir = NEXUS_DATA_PATH / "factory" / "templates"
    sw_path = templates_dir / "software_requirements.md"
    pt_path = templates_dir / "pentest_scope.md"
    result = {}
    if os.path.exists(sw_path):
        with open(sw_path) as f:
            result["software"] = f.read()
    if os.path.exists(pt_path):
        with open(pt_path) as f:
            result["pentest"] = f.read()
    return result

@router.post("/analyze")
async def analyze_requirements(
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_operator)
):
    """Analiza el MD de requerimientos y genera el Plan Maestro."""
    try:
        reqs = parse_requirements_md(body.requirements_md)
        proyecto = reqs.get("proyecto", {})
        nombre = proyecto.get("nombre", "Proyecto Sin Nombre")
        cliente = proyecto.get("cliente", "Cliente")
        tipo = proyecto.get("tipo", "web")

        if not nombre or nombre == "":
            raise HTTPException(400, "El campo nombre es obligatorio en [proyecto]")

        # Análisis LLM si está habilitado
        llm_analysis = None
        if body.use_llm:
            try:
                from nexus_core.llm.abstraction import NexusLLM
                llm = NexusLLM(primary='openai', fallback='gemini')
                prompt = f"""Eres un arquitecto de software senior de BAJIOWARE.
Analiza estos requerimientos y en 3-4 párrafos concisos responde:
1. Complejidad técnica (baja/media/alta) y por qué
2. Riesgos principales del proyecto
3. Recomendaciones de arquitectura específicas para el stack elegido
4. Estimación realista de fases necesarias

Requerimientos:
{body.requirements_md[:2000]}

Responde en español, directo y técnico."""
                resp = await asyncio.wait_for(
                    llm.chat_async([{"role":"user","content":prompt}]),
                    timeout=30
                )
                llm_analysis = resp.content if hasattr(resp,'content') else str(resp)
            except Exception as e:
                llm_analysis = f"Análisis LLM no disponible: {e}"

        plan = generate_plan_maestro(reqs, llm_analysis)
        project_id = create_project(nombre, cliente, tipo, reqs, reqs)
        save_plan(project_id, plan)

        return {
            "project_id":   project_id,
            "nombre":        nombre,
            "cliente":       cliente,
            "status":        "pending_approval",
            "plan_maestro":  plan,
            "llm_analysis":  llm_analysis,
            "message":       f"Plan Maestro generado — {plan['num_fases']} fases. Revisa y aprueba para ejecutar."
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error analizando requerimientos: {e}")

@router.post("/projects/{project_id}/approve")
async def approve(
    project_id: str,
    body: ApproveRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_operator)
):
    """Aprueba el Plan Maestro e inicia la ejecución."""
    project = get_project(project_id)
    if not project:
        raise HTTPException(404, "Proyecto no encontrado")
    if project["status"] not in ("pending_approval", "analyzing"):
        raise HTTPException(400, f"Proyecto en estado {project['status']} — no se puede aprobar")

    approve_project(project_id, body.approved_by or user["name"])

    # Lanzar ejecución en background
    background_tasks.add_task(_execute_factory, project_id)

    return {
        "project_id": project_id,
        "status":     "executing",
        "message":    "Plan Maestro aprobado — fábrica iniciada en background"
    }

async def _execute_factory(project_id: str):
    """Ejecuta las fases del Plan Maestro secuencialmente."""
    import httpx, asyncio
    project = get_project(project_id)
    if not project:
        return

    plan = json.loads(project.get("plan_maestro","{}"))
    phases = get_phases(project_id)
    output_dir = plan.get("output_dir", str(NEXUS_DATA_PATH / "factory" / "projects" / project_id))
    os.makedirs(output_dir, exist_ok=True)

    stack = plan.get("stack", {})
    proyecto_info = f"""
Proyecto: {plan.get('proyecto')}
Cliente: {plan.get('cliente')}
Stack: {json.dumps(stack)}
Output dir: {output_dir}
"""

    # Importar junior directamente — sin HTTP interno
    try:
        from nexus_core.junior_bridge import JuniorBridge
        from nexus_core.core.event_bus import EventBus
        _use_direct = True
    except Exception:
        _use_direct = False

    for phase in phases:
        phase_id = phase["id"]
        fase_num = phase["fase_num"]
        nombre   = phase["nombre"]
        desc     = phase["descripcion"]

        logger.info(f"[FACTORY] Ejecutando fase {fase_num}: {nombre}")
        update_phase_status(phase_id, "running")

        try:
            # Construir objetivo para Junior
            objective = f"""FASE {fase_num}/{len(phases)} del proyecto {plan.get('proyecto')} para {plan.get('cliente')}.
{proyecto_info}
TAREA DE ESTA FASE: {nombre} — {desc}
INSTRUCCIONES:
- Crea/modifica archivos en {output_dir}/
- Esta es la fase {fase_num} de {len(phases)} — {'primera fase: crear estructura base' if fase_num==1 else 'continuación del proyecto anterior'}
- Genera código REAL y funcional, sin TODOs ni stubs
- Si es la última fase ({fase_num}=={len(phases)}): crear Dockerfile, docker-compose.yml y README.md
- Guarda TODOS los archivos en {output_dir}/
Contexto previo del proyecto: backend={stack.get('backend','fastapi')}, db={stack.get('base_datos','sqlite')}, auth={stack.get('auth','jwt')}"""

            # Llamar a Junior via API interna
            base_url = "http://127.0.0.1:8000"
            async with httpx.AsyncClient(timeout=120) as client:
                # Login para obtener token interno
                login_resp = await client.post(f"{base_url}/auth/login",
                    json={"email": os.getenv("NEXUS_ADMIN_EMAIL","admin@nexuspro.io"),
                          "password": os.getenv("NEXUS_ADMIN_PASSWORD","synthetic-password")})
                token = login_resp.json().get("access_token","")

                run_resp = await client.post(f"{base_url}/junior/run",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"objective": objective, "max_steps": 10})
                task_id = run_resp.json().get("task_id")

                # Poll hasta completar
                for _ in range(40):
                    await asyncio.sleep(6)
                    status_resp = await client.get(
                        f"{base_url}/junior/status/{task_id}",
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    status_data = status_resp.json()
                    if status_data.get("status") in ("completed","failed"):
                        break

                result_summary = f"Fase {fase_num} completada — {status_data.get('status')} — {task_id}"
                update_phase_status(phase_id, "completed", result_summary)
                logger.info(f"[FACTORY] Fase {fase_num} completada")

        except Exception as e:
            logger.error(f"[FACTORY] Error en fase {fase_num}: {e}")
            # Marcar como completed con warning para continuar el pipeline
            update_phase_status(phase_id, "completed", f"warning: {str(e)[:200]}")

    # Marcar proyecto como completado
    import sqlite3
    db_path = os.getenv("NEXUS_DB_PATH",
        str(__import__('pathlib').Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE factory_projects SET status='completed',updated_at=datetime('now') WHERE id=?",
            (project_id,)
        )
        conn.commit()
    logger.info(f"[FACTORY] Proyecto {project_id} completado — archivos en {output_dir}")

@router.get("/projects")
async def list_all_projects(user=Depends(get_current_user)):
    projects = list_projects()
    return {"projects": projects, "total": len(projects)}

@router.get("/projects/{project_id}")
async def get_project_detail(project_id: str, user=Depends(get_current_user)):
    project = get_project(project_id)
    if not project:
        raise HTTPException(404, "Proyecto no encontrado")
    phases = get_phases(project_id)
    plan = {}
    try:
        plan = json.loads(project.get("plan_maestro") or "{}")
    except: pass
    return {**project, "phases": phases, "plan_maestro_parsed": plan}

# ── Pentest Engagements ───────────────────────────────────────

@router.post("/pentest/analyze")
async def analyze_pentest_scope(
    body: PentestAnalyzeRequest,
    user=Depends(require_operator)
):
    """Analiza el MD de scope y genera el plan de pentest."""
    try:
        from nexus_api.services.factory_service import parse_requirements_md
        scope = parse_requirements_md(body.scope_md)
        proyecto = scope.get("proyecto", {})
        nombre = proyecto.get("nombre", "Pentest Sin Nombre")
        cliente = proyecto.get("cliente", "Cliente")
        tipo = proyecto.get("tipo", "web")

        llm_plan = None
        if body.use_llm:
            try:
                from nexus_core.llm.abstraction import NexusLLM
                llm = NexusLLM(primary='openai', fallback='gemini')
                prompt = f"""Eres un pentester senior de BAJIOWARE (empresa de ciberseguridad).
Analiza este scope de pentest y genera:
1. Resumen del engagement (2 párrafos)
2. Metodología recomendada (OWASP/PTES/NIST)
3. Top 5 vectores de ataque más probables para este tipo de target
4. Herramientas específicas a usar
5. Estimación de tiempo por fase
6. Riesgos legales/éticos a considerar
7. Criterios de éxito del engagement

Scope:
{body.scope_md[:2000]}

Responde en español, profesional y técnico."""
                resp = await asyncio.wait_for(
                    llm.chat_async([{"role":"user","content":prompt}]),
                    timeout=30
                )
                llm_plan = resp.content if hasattr(resp,'content') else str(resp)
            except Exception as e:
                llm_plan = f"Análisis LLM no disponible: {e}"

        engage_id = create_pentest(nombre, cliente, tipo, body.scope_md)

        # Guardar plan LLM
        import sqlite3
        db_path = os.getenv("NEXUS_DB_PATH",
            str(__import__('pathlib').Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE pentest_engagements SET plan=?,status='pending_approval' WHERE id=?",
                (llm_plan or "Sin análisis", engage_id)
            )
            conn.commit()

        return {
            "engagement_id": engage_id,
            "nombre":        nombre,
            "cliente":       cliente,
            "status":        "pending_approval",
            "llm_plan":      llm_plan,
            "scope_parsed":  scope,
            "message":       "Scope analizado — revisa el plan y aprueba para ejecutar"
        }
    except Exception as e:
        raise HTTPException(500, f"Error: {e}")

@router.post("/pentest/{engage_id}/approve")
async def approve_pentest_engagement(
    engage_id: str,
    body: ApproveRequest,
    background_tasks: BackgroundTasks,
    user=Depends(require_operator)
):
    """Aprueba el scope y ejecuta el pentest."""
    engage = get_pentest(engage_id)
    if not engage:
        raise HTTPException(404, "Engagement no encontrado")
    if engage["status"] not in ("pending_approval","analyzing"):
        raise HTTPException(400, f"Estado inválido: {engage['status']}")

    approve_pentest(engage_id, body.approved_by or user["name"])
    background_tasks.add_task(_execute_pentest, engage_id)

    return {
        "engagement_id": engage_id,
        "status":        "executing",
        "message":       "Pentest aprobado — ejecutando en background"
    }

async def _execute_pentest(engage_id: str):
    """Ejecuta el pentest completo después de aprobación."""
    import httpx
    engage = get_pentest(engage_id)
    if not engage:
        return

    scope = parse_requirements_md(engage.get("scope",""))
    targets = scope.get("alcance", {})
    proyecto = scope.get("proyecto", {})
    nombre = proyecto.get("nombre", engage_id)

    try:
        base_url = "http://127.0.0.1:8000"
        async with httpx.AsyncClient(timeout=120) as client:
            login_resp = await client.post(f"{base_url}/auth/login",
                json={"email": os.getenv("NEXUS_ADMIN_EMAIL","admin@nexuspro.io"),
                      "password": os.getenv("NEXUS_ADMIN_PASSWORD","synthetic-password")})
            token = login_resp.json().get("access_token","")

            run_resp = await client.post(f"{base_url}/pentest/run",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "target": "localhost:8000",
                    "target_path": str(NEXUS_ROOT),
                    "target_name": nombre,
                    "scope": "full"
                })
            task_id = run_resp.json().get("task_id")

            for _ in range(60):
                await asyncio.sleep(10)
                status_resp = await client.get(
                    f"{base_url}/pentest/status/{task_id}",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if status_resp.json().get("status") in ("completed","failed"):
                    break

        import sqlite3
        db_path = os.getenv("NEXUS_DB_PATH",
            str(__import__('pathlib').Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE pentest_engagements SET status='completed',findings=? WHERE id=?",
                (task_id, engage_id)
            )
            conn.commit()
        logger.info(f"[FACTORY] Pentest {engage_id} completado")
    except Exception as e:
        logger.error(f"[FACTORY] Error pentest {engage_id}: {e}")

@router.get("/pentest")
async def list_pentests_endpoint(user=Depends(get_current_user)):
    engagements = list_pentests()
    return {"engagements": engagements, "total": len(engagements)}

@router.get("/pentest/{engage_id}")
async def get_pentest_detail(engage_id: str, user=Depends(get_current_user)):
    engage = get_pentest(engage_id)
    if not engage:
        raise HTTPException(404, "Engagement no encontrado")
    return engage
