"""Bounded parallel tool execution for one ReAct turn.

The loop used to spend one turn per tool: ``nmap`` finished, the model read the
result, and only then could ``gobuster`` start. Two *independent* scans cost two
round trips through the provider even though nothing about the second depends on
the first. This module runs that batch concurrently and hands the loop **one**
consolidated observation, so the model sees ``nmap`` and ``gobuster`` together in
the very next turn.

Three invariants, because a parallel turn must not become a way around the
governance of the gateway:

* **Every call is governed on its own.** Scope, RoE, approvals and the audit
  trail live in :class:`nexus_core.kernel.tool_gateway.ToolGateway`, which is
  invoked once per call. Nothing here batches a decision.
* **The batch is bounded twice.** At most
  :data:`PARALLEL_MAX_CONCURRENCY` calls run at once (a Kali box is also running
  Metasploit) and each call carries its own timeout, so one hung ``nmap -p-``
  never holds the others.
* **A failure is local.** An exception or a timeout in one call becomes that
  call's result; the rest keep running and the loop decides what the whole batch
  means.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

#: How many calls of one batch may run at the same time. Three scans already
#: saturate a laptop's uplink and CPU; the ceiling is per turn, not per run.
PARALLEL_MAX_CONCURRENCY = 3
#: Operator override (``NEXUS_PARALLEL_TOOL_LIMIT=1`` turns the feature off
#: without touching the code).
PARALLEL_LIMIT_ENV = "NEXUS_PARALLEL_TOOL_LIMIT"
#: Per-call wall-clock ceiling. Unset keeps the loop's own
#: ``timeout_per_tool_seconds``, which is what a single call already had.
PARALLEL_TIMEOUT_ENV = "NEXUS_PARALLEL_CALL_TIMEOUT"
#: Characters of one call's ``output`` kept in the consolidated observation. The
#: full payload of a single tool is still available from its own journal entry;
#: this bound is only about the *next prompt* not being three nmap XMLs long.
RESULT_OUTPUT_CHARS = 2_000


def parallel_limit() -> int:
    """Concurrent calls allowed in one turn (>= 1; 1 means "sequential")."""
    raw = os.getenv(PARALLEL_LIMIT_ENV, "")
    try:
        value = int(raw) if str(raw).strip() else PARALLEL_MAX_CONCURRENCY
    except ValueError:
        return PARALLEL_MAX_CONCURRENCY
    return max(1, min(value, PARALLEL_MAX_CONCURRENCY))


def call_timeout(default: float) -> float:
    """Per-call ceiling: the loop's own budget unless the operator set one."""
    raw = os.getenv(PARALLEL_TIMEOUT_ENV, "")
    try:
        value = float(raw) if str(raw).strip() else float(default)
    except (TypeError, ValueError):
        return float(default)
    return value if value > 0 else float(default)


@dataclass
class CallExecution:
    """Raw outcome of one call, before the loop interprets it."""

    index: int
    tool_id: str
    arguments: dict[str, Any] = field(default_factory=dict)
    invocation: dict[str, Any] | None = None
    error: BaseException | None = None
    cancelled: bool = False
    duration_ms: float = 0.0

    @property
    def raised(self) -> bool:
        return self.error is not None


Executor = Callable[[dict[str, Any], float, Any], Awaitable[tuple[Any, bool]]]


async def execute_calls(
    calls: Sequence[Mapping[str, Any]],
    *,
    execute: Executor,
    limit: int,
    timeout: float,
    cancel_event: Any = None,
) -> list[CallExecution]:
    """Run every prepared call concurrently, bounded by ``limit``.

    ``calls`` are ``{index, tool_id, arguments, payload}`` mappings. ``execute``
    receives ``(payload, timeout, cancel_event)`` and returns the loop's usual
    ``(invocation, cancelled)`` tuple. Nothing raises: a failure is carried in
    :attr:`CallExecution.error` so the other calls of the batch finish.
    """
    semaphore = asyncio.Semaphore(max(1, int(limit)))
    results: dict[int, CallExecution] = {}

    async def one(call: Mapping[str, Any]) -> None:
        outcome = CallExecution(
            index=int(call["index"]),
            tool_id=str(call["tool_id"]),
            arguments=dict(call.get("arguments") or {}),
        )
        started = asyncio.get_running_loop().time()
        async with semaphore:
            try:
                invocation, cancelled = await asyncio.wait_for(
                    execute(call["payload"], timeout, cancel_event), timeout=timeout
                )
                outcome.invocation = invocation if isinstance(invocation, dict) else None
                outcome.cancelled = bool(cancelled)
                if outcome.invocation is None and not outcome.cancelled:
                    outcome.error = RuntimeError("tool returned no structured output")
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - one call never kills the batch
                # Deliberately ``Exception``: KeyboardInterrupt/SystemExit belong
                # to the operator and must keep travelling.
                outcome.error = error
        outcome.duration_ms = (asyncio.get_running_loop().time() - started) * 1000
        results[outcome.index] = outcome

    if calls:
        await asyncio.gather(*(one(call) for call in calls))
    return [results[key] for key in sorted(results)]


def bounded_result(result: Mapping[str, Any], *, limit: int = RESULT_OUTPUT_CHARS) -> dict[str, Any]:
    """One call's entry of ``parallel.results``, with its output kept readable.

    ``evidence`` and ``assertions`` are never trimmed: they are what the plan and
    the completion gates read. Only the free-form ``output`` is bounded, and it
    says so, so the model knows the payload was cut rather than empty.
    """
    entry = dict(result)
    output = entry.get("output")
    if output is not None:
        try:
            text = json.dumps(output, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(output)
        if len(text) > limit:
            entry["output"] = {
                "truncated": True,
                "chars": len(text),
                "preview": text[:limit],
            }
    return entry


def consolidate(results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """The single observation a parallel turn leaves for the model."""
    entries = [bounded_result(result) for result in results]
    total = len(entries)
    succeeded = sum(1 for entry in entries if entry.get("success"))
    failed = total - succeeded
    observation: dict[str, Any] = {
        "success": bool(total) and failed == 0,
        "parallel": True,
        "tool_calls": total,
        "succeeded": succeeded,
        "failed": failed,
        "results": entries,
    }
    if failed:
        names = ", ".join(
            f"`{entry.get('tool_id')}`" for entry in entries if not entry.get("success")
        )
        observation["guidance"] = (
            f"{failed} de {total} llamadas en paralelo fallaron ({names}). "
            "Lee `results`: cada entrada trae su propio `outcome`, `error` y "
            "`guidance`. Las que sí terminaron ya aportaron su evidencia: no las "
            "repitas, trabaja sobre ellas y cambia de estrategia solo para las que "
            "fallaron."
        )
    else:
        observation["guidance"] = (
            f"{total} llamadas en paralelo terminaron correctamente. Lee `results` "
            "y decide el siguiente paso con toda la evidencia junta."
        )
    return observation


__all__ = [
    "PARALLEL_LIMIT_ENV",
    "PARALLEL_MAX_CONCURRENCY",
    "PARALLEL_TIMEOUT_ENV",
    "RESULT_OUTPUT_CHARS",
    "CallExecution",
    "bounded_result",
    "call_timeout",
    "consolidate",
    "execute_calls",
    "parallel_limit",
]
