"""XDG history shared by readline and prompt_toolkit."""

from pathlib import Path
import os


def history_path() -> Path:
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().state_dir / "history"


def ensure_history_dir() -> None:
    history_path().parent.mkdir(parents=True, exist_ok=True, mode=0o700)


def file_history(path: Path):
    """FileHistory adapter retaining the existing one-command-per-line format.

    Standard FileHistory adds timestamps and '+' prefixes, which readline
    would interpret as commands. Keep the existing format in both directions.
    """
    from prompt_toolkit.history import FileHistory

    class ReadlineHistory(FileHistory):
        def load_history_strings(self):
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except FileNotFoundError:
                return
            yield from reversed(lines[-1000:])

        def store_string(self, string):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                # Bracketed paste can contain newlines even in a single-line UI.
                stream.write(string.replace("\n", " ") + "\n")

    return ReadlineHistory(str(path))
