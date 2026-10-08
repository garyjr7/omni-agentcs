"""Typed termination boundaries shared by interactive, worker and headless."""


class ApprovalRequired(PermissionError):
    """Execution is paused until a durable human decision exists."""


class ProviderFailure(RuntimeError):
    """The LLM or an external RPC provider failed or timed out."""


class BudgetExceeded(RuntimeError):
    """A durable token reservation would oversubscribe a shared tree budget."""
