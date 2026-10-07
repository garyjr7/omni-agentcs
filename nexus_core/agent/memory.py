"""Durable history for the ReAct loop, backed by kernel_conversations/messages.

No new tables: the loop reuses the conversation APIs of the control store.
Because ``kernel_messages`` is append-only, history compaction is *logical*:
the compaction writes a ``react.history_summary`` marker and
:func:`load_history` collapses everything the marker supersedes while keeping
the leading system prompt and the most recent messages intact.
"""

from __future__ import annotations

from typing import Any

from nexus_core.llm.abstraction import LLMMessage

from .prompts import render_summary_prompt

REACT_CONVERSATION_PREFIX = "react:"
SYSTEM_MESSAGE_KIND = "react.system"
HISTORY_SUMMARY_KIND = "react.history_summary"

#: Message kinds that only carry prompt scaffolding, never conversation turns.
COMPACTION_KINDS = frozenset({SYSTEM_MESSAGE_KIND, HISTORY_SUMMARY_KIND})

#: Number of trailing messages that compaction never touches.
PRESERVED_TAIL_MESSAGES = 10

_ALLOWED_ROLES = {"system", "user", "assistant", "tool"}


def react_conversation_title(run_id: str) -> str:
    """Deterministic conversation title, so a retried loop finds its history."""
    return f"{REACT_CONVERSATION_PREFIX}{run_id}"


def message_kind(message: dict[str, Any]) -> str:
    """Return the ``metadata.kind`` marker of a persisted message."""
    metadata = message.get("metadata") or {}
    if isinstance(metadata, dict):
        return str(metadata.get("kind") or "")
    return ""


def _leading_system_messages(messages: list[dict[str, Any]]) -> int:
    count = 0
    for message in messages:
        if message_kind(message) == SYSTEM_MESSAGE_KIND:
            count += 1
        else:
            break
    return count


def _last_summary_index(messages: list[dict[str, Any]]) -> int | None:
    index: int | None = None
    for position, message in enumerate(messages):
        if message_kind(message) == HISTORY_SUMMARY_KIND:
            index = position
    return index


def _collapse_summaries(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop messages superseded by the newest compaction marker.

    The marker records how many body messages it replaced, so the leading
    system prompt and the preserved tail survive the collapse.
    """
    last = _last_summary_index(messages)
    if last is None:
        return list(messages)
    marker = messages[last]
    metadata = marker.get("metadata") or {}
    try:
        covered = max(0, int(metadata.get("covers") or 0))
    except (TypeError, ValueError):
        covered = 0
    head = _leading_system_messages(messages[:last])
    covered = min(covered, last - head)
    return messages[:head] + [marker] + messages[head + covered :]


def latest_summary(messages: list[dict[str, Any]]) -> str:
    """Return the newest compaction summary text, if any."""
    index = _last_summary_index(messages)
    if index is None:
        return ""
    return str(messages[index].get("content") or "")


def estimate_tokens(messages: list[dict[str, Any]]) -> int:
    """Cheap, provider-independent token estimate (≈4 characters per token)."""
    total = 0
    for message in messages:
        content = str(message.get("content") or "")
        total += 4 + max(1, len(content) // 4)
    return total


def ensure_conversation(store: Any, tenant_id: str, run_id: str, owner_id: str) -> str:
    """Create (or recover) the ReAct conversation bound to ``run_id``.

    Recovery relies on the deterministic title ``react:<run_id>`` so a worker
    that dies mid-loop finds the partial history instead of starting over.
    """
    title = react_conversation_title(run_id)
    for conversation in store.list_conversations(tenant_id, owner_id):
        if conversation.get("title") == title:
            return str(conversation["id"])
    created = store.create_conversation(tenant_id, owner_id, title, agent_id=owner_id)
    return str(created["id"])


WORK_SESSION_PREFIX = "work:"
ASK_SOURCE = "ask"


def work_session_title(engagement_id: str | None) -> str:
    """Deterministic title of the durable conversation shared by an engagement."""
    return f"{WORK_SESSION_PREFIX}{engagement_id or 'no-engagement'}"


def find_work_conversation(
    store: Any, tenant_id: str, owner_id: str, engagement_id: str | None
) -> str | None:
    """Return the newest ``work:<engagement>`` conversation, if it exists."""
    wanted = work_session_title(engagement_id)
    for conversation in store.list_conversations(tenant_id, owner_id):
        if conversation.get("title") == wanted:
            return str(conversation["id"])
    return None


def ensure_work_conversation(
    store: Any, tenant_id: str, owner_id: str, engagement_id: str | None
) -> str:
    """Return (creating if needed) the work conversation of the engagement."""
    existing = find_work_conversation(store, tenant_id, owner_id, engagement_id)
    if existing:
        return existing
    return start_work_conversation(store, tenant_id, owner_id, engagement_id)


def start_work_conversation(
    store: Any, tenant_id: str, owner_id: str, engagement_id: str | None
) -> str:
    """Create a fresh work conversation (``/clear`` rotates to a new one).

    Rotation keeps the previous conversation in the store: it is simply no
    longer the most recently updated one, so it becomes an archive.
    """
    created = store.create_conversation(
        tenant_id, owner_id, work_session_title(engagement_id), agent_id=owner_id
    )
    return str(created["id"])


def _redact_arguments(arguments: dict[str, Any] | None) -> dict[str, Any] | None:
    """Redact credentials from a tool-arguments dict before it is persisted.

    The ReAct loop records the model's requested arguments in the durable
    history *before* the handler runs. Those arguments can carry AD
    credentials (``password``, ``hash``, ...), so they are scrubbed with the
    same field-name policy the audit writer uses. The real execution path keeps
    the original values; only the persisted copy is redacted.
    """
    if not arguments:
        return arguments
    from nexus_core.kernel.audit import AuditWriter

    return AuditWriter._sanitize(arguments)


def _sanitize_content_for_persistence(content: str) -> str:
    from nexus_core.kernel.redaction import sanitize_text

    return sanitize_text(content)


# Compatibility for existing callers/tests.
_redact_content = _sanitize_content_for_persistence


def append_step(
    store: Any,
    tenant_id: str,
    conversation_id: str,
    role: str,
    content: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Append one message to the ReAct history and return its id."""
    if role not in _ALLOWED_ROLES:
        raise ValueError(f"unsupported ReAct message role: {role}")
    metadata = dict(metadata or {})
    run_id = metadata.pop("run_id", None)
    # Sanitize structured credentials at the history write boundary.
    from nexus_core.kernel.audit import AuditWriter

    metadata = AuditWriter._sanitize(metadata)
    content = _redact_content(content)
    message = store.append_message(
        tenant_id,
        conversation_id,
        role,
        content,
        run_id=str(run_id) if run_id else None,
        metadata=metadata,
    )
    return str(message["id"])


def load_history(
    store: Any,
    tenant_id: str,
    conversation_id: str,
    limit: int = 40,
) -> list[dict[str, Any]]:
    """Return the latest ``limit`` messages in chronological order.

    Messages already superseded by the newest compaction marker are removed,
    except the leading system prompt.
    """
    messages = store.list_messages(tenant_id, conversation_id, limit=max(1, int(limit)))
    return _collapse_summaries(messages)


def prior_objectives(
    messages: list[dict[str, Any]], current_run_id: str | None
) -> list[str]:
    """Objectives already recorded in this work session, oldest first.

    A shared work session accumulates one ``react.system`` message per run so
    durable traceability is preserved. The ReAct loop surfaces those earlier
    objectives to the model so it can build on the engagement's prior work;
    the objective of the run being executed is excluded because it is already
    the focus of the current prompt.
    """
    objectives: list[str] = []
    wanted = str(current_run_id or "")
    for message in messages:
        if message_kind(message) != SYSTEM_MESSAGE_KIND:
            continue
        if str(message.get("run_id") or "") == wanted:
            continue
        metadata = message.get("metadata") or {}
        objective = str((metadata if isinstance(metadata, dict) else {}).get("objective") or "")
        objective = objective.strip()
        if objective and objective not in objectives:
            objectives.append(objective)
    return objectives


async def summarize_history_if_large(
    store: Any,
    tenant_id: str,
    conversation_id: str,
    client: Any,
    max_tokens: int = 8000,
    force: bool = False,
    run_id: str | None = None,
) -> str:
    """Compact the history with one LLM call when it grows too large.

    Returns the summary text (and persists it as a compaction marker), or an
    empty string when no compaction was needed. The system prompt and the
    trailing :data:`PRESERVED_TAIL_MESSAGES` messages are never summarized.

    ``run_id`` scopes the compaction to one run of a shared work session
    (B8.2.1): a run must never fold another run's turns into *its* context, both
    because the model would then reason over stale evidence and because it would
    pay for a compaction call it did not need. The marker inherits the ``run_id``
    so the summary is only ever re-read by the run that produced it.
    """
    messages = _collapse_summaries(
        store.list_messages(tenant_id, conversation_id, limit=500)
    )
    if run_id is not None:
        wanted = str(run_id)
        messages = [
            message
            for message in messages
            if message_kind(message) == SYSTEM_MESSAGE_KIND
            or str(message.get("run_id") or "") == wanted
        ]
    if not force and estimate_tokens(messages) <= max_tokens:
        return ""

    head = _leading_system_messages(messages)
    body = messages[head:]
    tail = body[-PRESERVED_TAIL_MESSAGES:]
    middle = body[: len(body) - PRESERVED_TAIL_MESSAGES]

    # One existing summary marker plus nothing new is not worth a model call.
    if len(middle) < 2 and not force:
        return ""
    if not middle:
        return ""

    history_text = "\n".join(
        f"[{message.get('role')}] {str(message.get('content') or '')[:2000]}"
        for message in middle
    )
    response = await client.complete(
        [
            LLMMessage(role="system", content="Eres un compresor de contexto preciso."),
            LLMMessage(role="user", content=render_summary_prompt(history_text)),
        ]
    )
    summary = str(getattr(response, "content", "") or "").strip()
    if not summary:
        return ""
    metadata: dict[str, Any] = {
        "kind": HISTORY_SUMMARY_KIND,
        "covers": len(middle),
        "preserved_tail": len(tail),
    }
    if run_id is not None:
        metadata["run_id"] = run_id
    append_step(
        store,
        tenant_id,
        conversation_id,
        "system",
        summary,
        metadata,
    )
    return summary
