"""PLAN MODE: draft ``loot/ENGAGEMENT_PLAN.md`` before the first attack turn.

The loop is an ACT loop: every turn it asks the model for one action. That works
until the run decides it is done, and the run decides *that* with whatever
context it has (run v8 closed on the first flag: ``run_a00cddfa…``). The missing
piece is a planning turn with a different question -"what does this engagement
have to prove?"- whose answer is written to the workspace and becomes the
contract the ACT turns are checked against.

Three properties matter, and they are why this is a separate module:

* **It is a property of an engagement, not of a chat.** A question or an
  objective that only needs reasoning never gets a plan
  (:func:`nexus_core.agent.engagement_plan.is_engagement_objective`); ``/ask``
  does not even reach this module.
* **It cannot lose the run.** One provider call, and on any failure the
  deterministic seed (:func:`nexus_core.agent.engagement_plan.seed_todos`) is
  written instead. A run always starts with a contract.
* **It never overwrites the model's own plan.** A resumed engagement keeps the
  file it already committed to; the model refines it with
  ``nexus.orchestrator.update_plan``.
"""

from __future__ import annotations

import json
import re
from typing import Any

from nexus_core.llm.abstraction import LLMMessage

from .engagement_plan import (
    EngagementPlan,
    is_engagement_objective,
    load_plan_for,
    new_plan,
    save_plan,
    seed_todos,
    todo_from_mapping,
)

#: Ceiling on the TODOs a single planning answer may carry. More than this is not
#: a plan, it is a dictation of the whole kill chain for every service.
PLAN_MAX_TODOS = 20

PLAN_SYSTEM_PROMPT = """Eres el planificador de un engagement de pentesting.
Recibirás el objetivo del engagement y debes devolver su PLAN como una lista de
TODOs verificables. No ejecutas herramientas: solo planificas.

Reglas:
- 1 a 3 TODOs: recon, acceso inicial y, si el enunciado lo exige, el objetivo
  final (root/flag). NO escribas la cadena intermedia a ciegas: enumeración,
  escalada y loot se añaden con update_plan cuando la evidencia abra el vector.
- `description` es una acción concreta y comprobable, no una intención vaga.
- `fact_types` son los hechos VERIFICADOS que cierran el TODO. Valores válidos:
  host, service, web_app, endpoint, user, email, credential, access, privilege,
  vulnerability, session, artifact, loot, hint, route, flag, report.
  Usa "flag" para la captura de una flag, "loot" para el primer archivo robado,
  "privilege" para uid=0/Administrador, "session"/"credential" para acceso, y
  deja `fact_types` vacío SOLO para el informe final.
- Si el plan incluye un PIVOTE hacia otra red, declara `fact_types:["route"]` y
  una `condition` que fije el destino: {"route":{"value.to_host":"10.0.0.5"}}. El
  TODO lo cierra el hecho route verificado, no que el modelo diga que abrió un
  túnel.
- `condition` es opcional y sirve para no cerrar un TODO con el hecho de otro:
  {"credential":{"source":"apk_decompile","key_matches":"synthetic-user*"}}.
- `evidence` describe la prueba esperada (tool + condición), en una línea.
- Un TODO por objetivo real del enunciado: si pide comprometer, escalar y capturar
  flags, el plan DEBE incluir acceso, escalada y cada flag.

Responde ONLY con un objeto JSON válido:
{"todos":[{"id":"recon","description":"...","evidence":"...","fact_types":["host","service"]}]}"""

PLAN_USER_PROMPT = """OBJETIVO DEL ENGAGEMENT:
{objective}

Objetivo del engagement: {engagement}

Devuelve el plan como JSON."""

_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_plan_json(text: str) -> dict[str, Any] | None:
    """The JSON object of a planning answer, tolerating fences and prose."""
    raw = str(text or "").strip()
    if not raw:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        match = _JSON_OBJECT_RE.search(raw)
        candidate = match.group(0) if match else None
    if candidate is None:
        return None
    try:
        payload = json.loads(candidate)
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def todos_from_payload(payload: Any) -> list[Any]:
    """Validate the TODOs of a planning answer, or raise ``ValueError``.

    The answer is model output: the same validation the tool applies is applied
    here, so a plan that reaches the file is always a legal plan.
    """
    if not isinstance(payload, dict):
        raise ValueError("the planning answer must be a JSON object")
    raw = payload.get("todos")
    if not isinstance(raw, list) or not raw:
        raise ValueError("the planning answer must contain a non-empty 'todos' list")
    if len(raw) > PLAN_MAX_TODOS:
        raise ValueError(f"too many todos: {len(raw)} > {PLAN_MAX_TODOS}")
    todos = [todo_from_mapping(item) for item in raw]
    ids = [todo.id for todo in todos]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate todo ids in the planning answer")
    return todos


async def draft_engagement_plan(
    *,
    llm_client: Any,
    objective: str,
    engagement_id: str | None,
    workspace: str | None = None,
    store: Any | None = None,
    tenant_id: str = "system",
) -> EngagementPlan | None:
    """Create or reuse the engagement plan before the loop starts.

    Returns ``None`` only when the objective needs no plan (a question, a
    reasoning-only objective). Never raises: a planning failure is written as the
    deterministic seed, so the engagement always has a contract.
    """
    if not is_engagement_objective(objective):
        return None
    existing = load_plan_for(
        engagement_id, workspace, store=store, tenant_id=tenant_id
    )
    if existing is not None and existing.todos:
        # Resume: the model already committed to this plan. Rewriting it from the
        # objective would erase every tick the evidence earned.
        return existing
    try:
        response = await llm_client.complete(
            [
                LLMMessage(role="system", content=PLAN_SYSTEM_PROMPT),
                LLMMessage(
                    role="user",
                    content=PLAN_USER_PROMPT.format(
                        objective=objective, engagement=engagement_id or "(sin engagement)"
                    ),
                ),
            ]
        )
        payload = _extract_plan_json(str(getattr(response, "content", "") or ""))
        plan = new_plan(
            objective,
            engagement_id,
            todos_from_payload(payload),
            source="model",
        )
    except Exception:  # noqa: BLE001 - planning must never kill the run
        plan = new_plan(
            objective,
            engagement_id,
            seed_todos(objective),
            source="seed",
        )
    save_plan(plan, workspace, store=store, tenant_id=tenant_id)
    return plan


__all__ = [
    "PLAN_MAX_TODOS",
    "PLAN_SYSTEM_PROMPT",
    "PLAN_USER_PROMPT",
    "draft_engagement_plan",
    "todos_from_payload",
]
