"""Readline-compatible input without optional terminal dependencies."""


def fallback_prompt(prompt_text: str) -> str:
    """Read one line; propagate EOFError and KeyboardInterrupt unchanged."""
    try:
        import readline  # noqa: F401
    except ImportError:
        pass
    return input(prompt_text)
