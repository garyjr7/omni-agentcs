"""Private, bounded, versioned input history shared by TUI and readline."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile

from prompt_toolkit.history import History

HEADER = {'version': 1, 'format': 'omni-history'}


def history_path() -> Path:
    from nexus_core.config.xdg import resolve_xdg_paths
    return resolve_xdg_paths().state_dir / 'history'


def ensure_history_dir() -> None:
    history_path().parent.mkdir(parents=True, exist_ok=True, mode=0o700)


def atomic_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def history_lock(path):
    import fcntl
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


class JsonHistory(History):
    def __init__(self, path, *, max_entries=1000, max_bytes=16*1024*1024):
        super().__init__()
        self.path = Path(path)
        self.max_entries = max_entries
        self.max_bytes = max_bytes

    def _read(self):
        if not self.path.exists():
            return []
        # Bound reads even when another application supplied the file.
        if self.path.stat().st_size > self.max_bytes:
            raise ValueError('history size limit exceeded; original preserved')
        raw = self.path.read_bytes()
        lines = raw.decode('utf-8').splitlines()
        if not lines:
            return []
        try:
            header = json.loads(lines[0])
        except ValueError:
            header = None
        if isinstance(header, dict) and header.get('format') == 'omni-history' and header != HEADER:
            raise ValueError('unsupported history version; original preserved')
        if header != HEADER:
            # Exact backup precedes migration; old lost newlines cannot be recovered.
            backup = self.path.with_suffix('.legacy.bak')
            if not backup.exists():
                atomic_private(backup, raw)
            self._write(lines[-self.max_entries:])
            return lines[-self.max_entries:]
        entries = []
        for line in lines[1:]:
            try:
                item = json.loads(line)
                if item['version'] != 1 or not isinstance(item['text'], str):
                    raise ValueError()
                entries.append(item['text'])
            except (ValueError, KeyError, TypeError) as exc:
                raise ValueError('invalid history record; original preserved') from exc
        return entries[-self.max_entries:]

    def _write(self, entries):
        header = json.dumps(HEADER) + '\n'
        records = [json.dumps({'version': 1, 'text': text}, ensure_ascii=False)+'\n' for text in entries[-self.max_entries:]]
        while records and len((header + ''.join(records)).encode()) > self.max_bytes:
            records.pop(0)
        atomic_private(self.path, (header + ''.join(records)).encode('utf-8'))

    def load_history_strings(self):
        with history_lock(self.path):
            entries = self._read()
        yield from reversed(entries)

    def store_string(self, string):
        size = len((json.dumps(HEADER) + json.dumps({'version': 1, 'text': string}, ensure_ascii=False) + '\n\n').encode())
        if size > self.max_bytes:
            raise ValueError('history entry size limit exceeded')
        with history_lock(self.path):
            entries = self._read()
            self._write(entries + [string])


def file_history(path: Path):
    return JsonHistory(path)
