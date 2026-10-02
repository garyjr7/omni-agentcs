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
        "panel": "bg:#1c1c1c #d0d0d0",
        "panel-title": "bg:#1c1c1c #00afff bold",
        "panel-current": "bg:#1c1c1c #ffff5f bold",
        "panel-done": "bg:#1c1c1c #5fd75f",
        "panel-pending": "bg:#1c1c1c #808080",
    }


__all__ = ["PANEL_FACT_ORDER", "panel_lines", "panel_style"]
