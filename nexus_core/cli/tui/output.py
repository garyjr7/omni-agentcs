"""One output boundary shared by renderers and background event streams."""
from __future__ import annotations

import threading
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import Any, Callable, Iterator, ParamSpec, Protocol, TypeVar, cast

P = ParamSpec("P")
R = TypeVar("R")


class OutputRouter(Protocol):
    def write(self, text: str, *, end: str = "\n") -> None: ...
    def flush(self) -> None: ...


class PlainOutput:
    def write(self, text: str, *, end: str = "\n") -> None:
        print(text, end=end)

    def flush(self) -> None:
        import sys

        sys.stdout.flush()


class TuiOutput:
    def __init__(self, session: Any) -> None:
        self._session = session

    def write(self, text: str, *, end: str = "\n") -> None:
        self._session.print(text, end=end)

    def flush(self) -> None:
        self._session.flush()


_OUTPUT: ContextVar[OutputRouter | None] = ContextVar("omni_output", default=None)


@contextmanager
def route_output(output: Any) -> Iterator[Any]:
    token = _OUTPUT.set(output)
    try:
        yield
    finally:
        _OUTPUT.reset(token)


def write(*values: Any, sep: Any=" ", end: Any="\n", flush: Any=False) -> None:
    output = _OUTPUT.get() or PlainOutput()
    output.write(sep.join(str(value) for value in values), end=end)
    if flush:
        output.flush()


class RoutedSession(Protocol):
    _output: OutputRouter


def routed(method: Callable[P, R]) -> Callable[P, R]:
    """Bind a session's router for this call, including its asyncio children."""
    @wraps(method)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        owner = args[0] if args else kwargs.get("session", kwargs.get("self"))
        with route_output(cast(RoutedSession, owner)._output):
            return method(*args, **kwargs)
    return wrapper


class TuiStreamProxy:
    """Write-through proxy that keeps the TUI as the only terminal writer.

    ``capture_output`` swaps ``sys.stdout``/``sys.stderr`` for this object while
    the REPL runs: any library, logging handler or warning that writes to the
    current stream lands in the scrollback buffer instead of the physical
    terminal. The original stream stays available for read-only introspection
    (``isatty``, ``fileno``, ``encoding``) and is restored by the context
    manager, even when the REPL exits through an exception.
    """

    def __init__(self, session: Any, stream_name: str, original: Any) -> None:
        self._tui = session
        self._name = stream_name
        self._original = original
        self._lock = threading.Lock()

    def write(self, text: str) -> int:
        if not text:
            return 0
        with self._lock:
            self._tui.append_scrollback(str(text))
        return len(text)

    def flush(self) -> None:
        self._tui.flush()

    def isatty(self) -> bool:
        return bool(self._original.isatty())

    def fileno(self) -> Any:
        return self._original.fileno()

    def __getattr__(self, name: Any) -> Any:
        return getattr(self._original, name)


@contextmanager
def capture_exceptions() -> Iterator[Any]:
    """Route uncaught tracebacks through the current stderr, not the raw one."""
    import sys
    import traceback

    original = sys.excepthook

    def hook(exc_type: Any, exc_value: Any, exc_tb: Any) -> Any:
        if issubclass(exc_type, KeyboardInterrupt):
            return original(exc_type, exc_value, exc_tb)
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        try:
            sys.stderr.write(f"\n✗ Excepción no capturada:\n{text}\n")
        except Exception:  # noqa: BLE001 - never hide the original failure
            original(exc_type, exc_value, exc_tb)

    sys.excepthook = hook
    try:
        yield
    finally:
        sys.excepthook = original


@contextmanager
def capture_output(session: Any) -> Iterator[Any]:
    """Route incidental stdout/stderr and tracebacks into the region buffer.

    Only installed for the TUI: the fallback path keeps writing to the real
    terminal exactly as before.
    """
    import sys
    from contextlib import redirect_stderr, redirect_stdout

    stdout = TuiStreamProxy(session, "stdout", sys.stdout)
    stderr = TuiStreamProxy(session, "stderr", sys.stderr)
    with redirect_stdout(stdout), redirect_stderr(stderr), capture_exceptions():
        yield
