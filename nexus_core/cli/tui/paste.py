"""Typed input. Object positions, never marker regexes, identify paste content."""
from dataclasses import dataclass, asdict
import json
import os
from pathlib import Path
import time
from .history import atomic_private

OBJECT = '\ufffc'

@dataclass(frozen=True)
class Text:
    content: str

@dataclass(frozen=True)
class PasteRef:
    id: int
    content: str
    lines: int

    @property
    def label(self):
        return f'[Pegado #{self.id} · {len(self.content)} caracteres · {self.lines} líneas]'


class InputDocument:
    max_bytes = 2 * 1024 * 1024
    def __init__(self, *, path=None):
        self.path = Path(path) if path else None
        self.text = ''
        self.refs = {}
        self.next_id = 1
        if self.path and self.path.exists():
            if self.path.stat().st_size > self.max_bytes * 6:
                raise ValueError('paste storage size limit')
            data = json.loads(self.path.read_text())
            if data['version'] != 1:
                raise ValueError('unsupported paste version')
            self.text = data['text']
            self.refs = {int(p): PasteRef(**ref) for p, ref in data['refs'].items()}
            if any(p < 0 or p >= len(self.text) or self.text[p] != OBJECT for p in self.refs):
                raise ValueError('invalid paste reference')
            self.next_id = max((r.id for r in self.refs.values()), default=0)+1
            self._check(self.text, self.refs)

    @property
    def segments(self):
        result, start = [], 0
        for pos, ref in sorted(self.refs.items()):
            if pos > start:
                result.append(Text(self.text[start:pos]))
            result.append(ref)
            start = pos + 1
        if start < len(self.text):
            result.append(Text(self.text[start:]))
        return result

    def reconstruct(self):
        return ''.join(segment.content for segment in self.segments)

    def render(self):
        return ''.join(segment.label if isinstance(segment, PasteRef) else segment.content for segment in self.segments)

    def _check(self, text, refs):
        if len(text.encode()) + sum(len(ref.content.encode()) for ref in refs.values()) > self.max_bytes:
            raise ValueError('paste/input size limit exceeded (2 MiB)')

    def _commit(self, text, refs):
        self._check(text, refs)
        if self.path:
            atomic_private(self.path, json.dumps({'version':1,'text':text,'refs':{str(p):asdict(r) for p,r in refs.items()}},ensure_ascii=False).encode())
        self.text, self.refs = text, refs

    def synchronize(self, new):
        if new == self.text:
            return
        old = self.text
        start = 0
        while start < min(len(old),len(new)) and old[start] == new[start]:
            start += 1
        end = 0
        while end < min(len(old)-start,len(new)-start) and old[len(old)-1-end] == new[len(new)-1-end]:
            end += 1
        stop = len(old)-end
        delta = len(new)-len(old)
        refs = {p if p < start else p+delta:r for p,r in self.refs.items() if p < start or p >= stop}
        self._commit(new, refs)

    def insert_paste(self, position, content):
        self._check(self.text+content, self.refs)
        ref = PasteRef(self.next_id, content, content.count('\n')+1)
        refs = {p if p < position else p+1:r for p,r in self.refs.items()}
        refs[position] = ref
        self._commit(self.text[:position]+OBJECT+self.text[position:], refs)
        self.next_id += 1

    def replace_ref(self, position, *, expand):
        ref = self.refs[position]
        replacement = ref.content if expand else ''
        delta = len(replacement)-1
        refs = {p if p < position else p+delta:r for p,r in self.refs.items() if p != position}
        self._commit(self.text[:position]+replacement+self.text[position+1:], refs)
        return position + len(replacement)


def paste_threshold(content):
    chars = max(1, int(os.getenv('NEXUS_PASTE_CHARS', '1000')))
    lines = max(1, int(os.getenv('NEXUS_PASTE_LINES', '4')))
    return len(content) > chars or content.count('\n')+1 > lines


def prune_drafts(directory, *, keep=32, days=7):
    paths = sorted(directory.glob('*.draft.json'), key=lambda p:p.stat().st_mtime, reverse=True)
    for index, path in enumerate(paths):
        if index >= keep or time.time()-path.stat().st_mtime > days*86400:
            path.unlink(missing_ok=True)


from prompt_toolkit.layout.processors import Processor, Transformation

class PasteProcessor(Processor):
    def __init__(self, ui):
        self.ui = ui

    def apply_transformation(self, ti):
        from prompt_toolkit.formatted_text import fragment_list_to_text
        text = fragment_list_to_text(ti.fragments)
        offset = ti.document.translate_row_col_to_index(ti.lineno, 0)
        refs = self.ui.input_document.refs if not self.ui._secret_mode else {}
        fragments, source_map, display_map = [], [], []
        display = 0
        for col, char in enumerate(text):
            ref = refs.get(offset+col)
            label = ref.label if ref else char
            source_map.append(display)
            display_map.extend([col]*len(label))
            fragments.append(('class:paste' if ref else '', label))
            display += len(label)
        source_map.append(display)
        display_map.append(len(text))
        return Transformation(fragments, lambda i: source_map[min(i,len(source_map)-1)],
                              lambda i: display_map[min(i,len(display_map)-1)])
