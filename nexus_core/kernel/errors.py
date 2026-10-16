"""Typed termination boundaries shared by interactive, worker and headless."""


class ApprovalRequired(PermissionError):
    """Execution is paused until a durable human decision exists."""


#: Kinds a :class:`ProviderFailure` may declare (Fase 3b).
PROVIDER_FAILURE_KINDS = frozenset({"unavailable", "fatal"})


class ProviderFailure(RuntimeError):
    """The LLM or the backend of a tool failed.

    ``kind`` separates two consequences that used to be the same one (Fase 3b).
    Measured in run_434f5eeadb104b11ba0c80bce16f8d08: a dead MSF RPC ended the
    whole mission with ``termination_reason=provider_error``.

    * ``"unavailable"``: the backend/dependency is not serving *right now*
      (MSF RPC down, Sliver team server down, dead MCP stdio, missing RPC
      credentials). Recoverable: the tool reports ``outcome="unavailable"`` -or
      the loop materializes it as one- and the loop counts it like any other tool
      failure, so the tool is retired after repeated attempts and the agent can
      pivot to the rest of the phase.
    * ``"fatal"``: an irrecoverable protocol/invariant failure. It still ends the
      run with ``status=provider_error``. Keep it rare: it is the default so that
      an unclassified failure is never silently degraded.
    """

    def __init__(self, message: str = "", *, kind: str = "fatal") -> None:
        if kind not in PROVIDER_FAILURE_KINDS:
            raise ValueError(
                f"unknown provider failure kind {kind!r}; "
                f"declare one of {sorted(PROVIDER_FAILURE_KINDS)}"
            )
        super().__init__(message)
        self.kind = kind


class BudgetExceeded(RuntimeError):
    """A durable token reservation would oversubscribe a shared tree budget."""


class LeaseLost(PermissionError):
    """The supplied task lease expired or no longer owns this generation."""
