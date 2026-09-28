"""Hard gate for pre-kernel tools that do not yet use ToolGateway/SandboxRuntime."""

import os


def legacy_execution_enabled() -> bool:
    return (
        os.getenv("NEXUS_ENV", "development").lower() != "production"
        and os.getenv("NEXUS_ENABLE_LEGACY_EXECUTION", "false").lower() == "true"
    )


def require_legacy_execution() -> None:
    if not legacy_execution_enabled():
        raise PermissionError(
            "Legacy direct execution is disabled; register this operation through ToolGateway"
        )
