"""Context-sensitive completions from a snapshot of the CLI catalogs."""

import re

from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.document import Document


class OmniCompleter(Completer):
    def __init__(self, *, commands: dict, tools: dict, engagements: list[str]):
        self.commands = {
            name: ((getattr(handler, "__doc__", "") or "").strip().splitlines() or [""])[0]
            for name, handler in commands.items()
        }
        self.tools = {}
        for name, entry in tools.items():
            definition = entry[0] if isinstance(entry, tuple) else entry
            schema = definition if isinstance(definition, dict) else getattr(definition, "input_schema", {})
            self.tools[name] = dict(schema.get("properties", {}))
        self.engagements = tuple(sorted(set(engagements)))
        self.paths = PathCompleter(expanduser=True)

    @staticmethod
    def _matches(candidates, prefix):
        for name, description in sorted(candidates.items()):
            if name.startswith(prefix):
                yield Completion(name, start_position=-len(prefix), display_meta=description)

    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        if not text.strip():
            return
        # Paths inside an open quote keep their spaces and quote boundary.
        quoted = re.search(r'''(?:^|[\s=])(["'])([^"']*)$''', text)
        if quoted:
            yield from self._paths(quoted.group(2), complete_event)
            return
        word = re.split(r"\s", text)[-1]
        if word.startswith("/") and text.strip() == word and "/" not in word[1:]:
            matches = list(self._matches(self.commands, word))
            yield from matches
            if not matches:
                yield from self._paths(word, complete_event)
            return
        if word.startswith("nexus."):
            yield from self._matches(dict.fromkeys(self.tools, "Herramienta durable"), word)
            return
        if word.startswith("@"):
            yield from self._matches({"@" + name: "Engagement" for name in self.engagements}, word)
            return
        words = text.split()
        tool = next((part for part in reversed(words[:-1] if word else words) if part in self.tools), None)
        if tool and "=" not in word and not word.startswith(("/", "./", "../", "~/")):
            used = set(re.findall(r"\b([\w]+)=", text))
            fields = {
                key + "=": str(value.get("description") or value.get("type") or "argumento")
                for key, value in self.tools[tool].items() if key not in used
            }
            yield from self._matches(fields, word)
            return
        yield from self._paths(word.split("=", 1)[-1], complete_event)

    def _paths(self, word, event):
        if word.startswith(("/", "./", "../", "~/")):
            yield from self.paths.get_completions(Document(word), event)
