"""The tool-call example in the system prompt must be valid JSON."""

import json
from pathlib import Path

PROMPTS = Path(__file__).parents[2] / "agent" / "prompts.py"


def _thought_example() -> str:
    source = PROMPTS.read_text(encoding="utf-8")
    marker = "Para invocar una herramienta:"
    start = source.index(marker) + len(marker)
    opening = source.index("{{", start)
    closing = source.index("}}\n", opening)
    return source[opening:closing + 2].replace("{{", "{").replace("}}", "}")


def test_the_thought_json_example_parses():
    example = _thought_example()
    data = json.loads(example)
    assert data["action"] == "tool_call"
    assert data["thought"].startswith("Antes de actuar razona")
    assert "EVIDENCIA" in data["thought"] and "DECISIÓN" in data["thought"]
