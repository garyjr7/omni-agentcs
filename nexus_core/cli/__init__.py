"""Interactive ``omni`` CLI: ReAct REPL, live stream and human approval."""

from __future__ import annotations

from .approval import make_approval_callback
from .main import PROGRAM_VERSION, main
from .session import OmniSession, build_llm_client

__version__ = PROGRAM_VERSION

__all__ = [
    "OmniSession",
    "build_llm_client",
    "main",
    "make_approval_callback",
]
