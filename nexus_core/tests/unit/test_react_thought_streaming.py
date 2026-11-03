"""The streamed ``thought`` reaches the live reasoning row, delta by delta.

A provider that streams does not hand over a finished JSON object: the loop
extracts the growing ``thought`` value from the partial document and pushes it
to the UI hook. This pins the whole path -prompt order, deltas, live row- with
a simulated provider, so it runs without a network or a key.
"""

from __future__ import annotations

import json
from typing import Any

from nexus_core.agent.react import ReActConfig, _complete_turn
from nexus_core.agent.react_support import extract_partial_thought
from nexus_core.llm.abstraction import LLMConfig, LLMProvider

#: One ReAct answer split where the model actually writes it: the thought is
#: emitted before the action, and the provider cuts the stream mid-string.
DELTAS = (
    '{"thought": "Analizo los 8 puertos. ',
    "El 445/tcp responde SMB y el 80/tcp es HTTP. ",
    'Decido enumerar SMB antes de atacar la web.", ',
    '"action": "task_complete", "summary": "ok", "findings": []}',
)


class _DeltaProvider:
    supports_streaming = True

    def __init__(self) -> None:
        self.config = LLMConfig(provider=LLMProvider.FAKE, model="fake", api_key="x")

    async def stream(self, messages: Any, **kwargs: Any):
        for chunk in DELTAS:
            yield chunk

    async def complete(self, messages: Any, **kwargs: Any):  # pragma: no cover
        raise AssertionError("the streaming path must not fall back to complete()")


def test_the_prompt_puts_the_thought_before_the_action():
    from nexus_core.agent.prompts import REACT_SYSTEM_PROMPT

    example = REACT_SYSTEM_PROMPT.split('"action": "tool_call"', 1)[0]
    # The example the model copies lists the reasoning before the action.
    assert '"thought"' in example
    assert example.rindex('"thought"') > example.rindex("Para invocar una herramienta")


def test_extract_partial_thought_reads_the_growing_value():
    assert extract_partial_thought(DELTAS[0]).startswith("Analizo los 8 puertos.")
    assert "445/tcp" in extract_partial_thought("".join(DELTAS[:2]))
    assert "atacar la web" not in extract_partial_thought("".join(DELTAS[:2]))


async def test_each_delta_reaches_the_live_reasoning_row(tui_factory):
    ui = tui_factory(enable_completion=False).session
    snapshots: list[str] = []

    def on_thought(text: str) -> None:
        ui.set_thought(text)
        snapshots.append("".join(part[1] for part in ui._thought_formatted()))

    config = ReActConfig(on_thought=on_thought, on_thought_done=ui.end_thought)
    response = await _complete_turn(_DeltaProvider(), [], config)

    # The row was live during the stream, with the label and the partial text.
    assert snapshots and all(line.startswith("Razonando") for line in snapshots)
    assert "Analizo los 8 puertos" in snapshots[0]
    assert "445/tcp" in snapshots[-1]
    # Growth is monotonic and each update is a real change, not a repaint.
    assert len(snapshots) == len({text for text in snapshots})
    # The turn closed: no overlay left and the answer is the whole document.
    assert ui.thought_active is False
    assert json.loads(response.content)["action"] == "task_complete"
