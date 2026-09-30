"""One output boundary shared by renderers and background event streams."""

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from typing import Protocol


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
    def __init__(self, session):
        self._session = session

    def write(self, text: str, *, end: str = "\n") -> None:
        self._session.print(text, end=end)

    def flush(self) -> None:
        self._session.flush()


_OUTPUT: ContextVar[OutputRouter | None] = ContextVar("omni_output", default=None)


@contextmanager
def route_output(output):
    token = _OUTPUT.set(output)
    try:
        yield
    finally:
        _OUTPUT.reset(token)


def write(*values, sep=" ", end="\n", flush=False):
    output = _OUTPUT.get() or PlainOutput()
    output.write(sep.join(str(value) for value in values), end=end)
    if flush:
        output.flush()


def routed(method):
    """Bind a session's router for this call, including its asyncio children."""
    @wraps(method)
    def wrapper(session, *args, **kwargs):
        with route_output(session._output):
            return method(session, *args, **kwargs)
    return wrapper


@contextmanager
def capture_output(session):
    """Route incidental stdout/stderr into the region buffer without suspension."""
    import sys
    from contextlib import redirect_stdout, redirect_stderr

    class Stream:
        def __init__(self, original):
            self.original = original

        def write(self, text):
            session.append_scrollback(text)
            return len(text)

        def flush(self):
            session.flush()

        def __getattr__(self, name):
            return getattr(self.original, name)

    with redirect_stdout(Stream(sys.stdout)), redirect_stderr(Stream(sys.stderr)):
        yield
