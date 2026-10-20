"""Typed termination boundaries shared by interactive, worker and headless."""


class ApprovalRequired(PermissionError):
    """Execution is paused until a durable human decision exists."""


class ToolInputError(ValueError):
    """The tool refused its own arguments before anything ran.

    It is a ``ValueError`` so the handlers and their callers keep the old
    contract, and a distinct type so the gateway can tell *"this call never
    started"* from *"this call may have had an effect"*. The difference decides
    the journal state: ``failed`` (retry freely) versus ``unknown`` (a replay
    needs an operator).

    Measured in Brute It v6 (2026-10-20, iterations 11-17): ``_resolve_wordlist``
    rejected a path before hydra was spawned, the gateway journaled the
    invocation ``unknown``, and the model's own retry of the *same step* was
    answered with ``unknown invocation requires human approval`` -the run closed
    as ``blocked`` (exit 2) over a path that never touched the target.

    Only raise it when the failure is provably before the effect: argument
    parsing, schema/spec building, resolving a local path. A handler that has
    already spawned its process must keep raising ``ValueError``, because there
    the outcome really is unknown.
    """


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
