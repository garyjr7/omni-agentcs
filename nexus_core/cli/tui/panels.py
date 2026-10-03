"""Side panel: live engagement plan and blackboard breakdown.

Rendered as a prompt_toolkit ``Float`` overlay so it never becomes a fifth
layout region (the four-region invariant is part of the UI contract) and never
touches the durable scrollback.
"""

from __future__ import annotations

from typing import Any

#: Fact types surfaced in the panel, in reading order.
PANEL_FACT_ORDER = (
    "service",
    "host",
    "endpoint",
    "user",
    "credential",
    "access",
    "privilege",
    "vulnerability",
    "loot",
)


def _safe(value: Any) -> str:
    return "".join(c if c.isprintable() else " " for c in str(value))


def _wrap(text: str, width: int) -> list[str]:
    text = _safe(text)
    if width < 1:
        return [text]
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            while len(word) > width:
                lines.append(word[:width])
                word = word[width:]
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def panel_lines(plan: dict[str, Any] | None, *, width: int = 44) -> list[tuple[str, str]]:
    """Render the panel as ``(style, text)`` fragments (one entry per line)."""
    if not isinstance(plan, dict):
        return [("class:panel", " sin plan de engagement activo")]

    inner = max(1, width - 2)
    fragments: list[tuple[str, str]] = [("class:panel-title", " PLAN DE ENGAGEMENT")]
    done, total = plan.get("done"), plan.get("total")
    current = _safe(plan.get("current_label") or plan.get("current") or "?")
    fragments.append(("class:panel-current", f" fase: {current} ({done}/{total})"))
    for item in plan.get("phases") or []:
        if not isinstance(item, dict):
            continue
        status = item.get("status")
        mark = {"done": "✓", "current": "▶", "pending": "·"}.get(status, "·")
        style = {
            "done": "class:panel-done",
            "current": "class:panel-current",
            "pending": "class:panel-pending",
        }.get(status, "class:panel-pending")
        label = _safe(item.get("label") or item.get("id") or "?")
        suffix = " (opcional)" if item.get("optional") else ""
        fragments.append((style, f"  {mark} {label}{suffix}"))
    hint = plan.get("next_hint")
    if hint:
        fragments.append(("class:panel-title", " SIGUIENTE PASO"))
        fragments.extend(("class:panel", f"  {line}") for line in _wrap(str(hint), inner))
    counts = plan.get("counts") if isinstance(plan.get("counts"), dict) else {}
    if counts:
        shown = [f"{kind}:{counts[kind]}" for kind in PANEL_FACT_ORDER if counts.get(kind)]
        extra = {
            key: value
            for key, value in counts.items()
            if key not in PANEL_FACT_ORDER and value
        }
        shown.extend(f"{key}:{value}" for key, value in sorted(extra.items()))
        if shown:
            fragments.append(("class:panel-title", " BLACKBOARD"))
            for line in _wrap("  " + " ".join(shown), width):
                fragments.append(("class:panel", line))
    return fragments


def panel_style() -> dict[str, str]:
    """prompt_toolkit style rules used by :func:`panel_lines`."""
    return {
        "panel": "bg:#0d1117 #d0d4da",
        "panel-title": "bg:#0d1117 #00e5ff bold",
        "panel-current": "bg:#0d1117 #ffc950 bold",
        "panel-done": "bg:#0d1117 #56e696",
        "panel-pending": "bg:#0d1117 #6a6f76",
    }


def approval_lines(payload: dict[str, Any] | None, *, width: int = 62) -> list[tuple[str, str]]:
    """Render a HIGH/DESTRUCTIVE approval request as (style, text) fragments.

    Shows the exact tool, its declared risk, the reason and every argument —
    the durable-approval contract requires the operator to see what they sign.
    """
    inner = max(1, width - 2)
    fragments: list[tuple[str, str]] = [
        ("class:approval-title", " ⚠ APROBACIÓN HUMANA REQUERIDA")
    ]
    if not isinstance(payload, dict):
        fragments.append(("class:approval", " (solicitud no disponible)"))
        return fragments
    tool_id = _safe(payload.get("tool_id") or "?")
    risk = _safe(payload.get("risk") or "normal")
    fragments.append(("class:approval", f" tool:   {tool_id}"))
    fragments.append(("class:approval-risk", f" riesgo: {risk}"))
    reason = payload.get("reason")
    if reason:
        fragments.extend(("class:approval", line) for line in _wrap(f" motivo: {reason}", inner))
    arguments = payload.get("arguments") if isinstance(payload.get("arguments"), dict) else {}
    if arguments:
        fragments.append(("class:approval-title", " argumentos"))
        for key in sorted(arguments):
            fragments.extend(
                ("class:approval", line)
                for line in _wrap(f"  {key}: {arguments[key]}", inner)
            )
    fragments.append(
        ("class:approval-options", " [y] aprobar  [n] rechazar  [e] editar  [?] definición")
    )
    return fragments


def approval_style() -> dict[str, str]:
    """prompt_toolkit style rules used by :func:`approval_lines`."""
    return {
        "approval": "bg:#1a0d11 #e0e4ea",
        "approval-title": "bg:#1a0d11 #ffc950 bold",
        "approval-risk": "bg:#1a0d11 #ff4054 bold",
        "approval-options": "bg:#1a0d11 #00e5ff",
    }


__all__ = [
    "PANEL_FACT_ORDER",
    "panel_lines",
    "panel_style",
    "approval_lines",
    "approval_style",
]
