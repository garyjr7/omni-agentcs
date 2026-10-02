"""Read-only module catalog queries over RPC; no engagement required."""

import re

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.tools.parsers.metasploit import parse_msf_search

# LLMs routinely fill optional filters with empty or placeholder values; those
# must behave as "no filter" instead of failing the strict pattern checks.
_OPTIONAL_FILTERS = ("module_type", "platform", "cve")
_PLACEHOLDER_FILTER_VALUES = {"", "none", "null", "n/a", "na"}


def _drop_placeholder_filters(arguments: dict) -> dict:
    """Return a copy with empty/placeholder optional filters removed."""
    cleaned = dict(arguments)
    for key in _OPTIONAL_FILTERS:
        value = cleaned.get(key)
        if isinstance(value, str) and value.strip().lower() in _PLACEHOLDER_FILTER_VALUES:
            cleaned.pop(key, None)
    return cleaned


def msf_search_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.exploit.msf_search",
        name="Search Metasploit modules",
        description="Search the local Metasploit module catalog without executing modules.",
        tenant_id=tenant_id,
        risk=RiskLevel.READ_ONLY,
        scope_required=False,
        required_permissions=["execute:tool"],
        timeout_seconds=100,
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "maxLength": 1024},
                "module_type": {
                    "type": "string",
                    "enum": [
                        "exploit",
                        "auxiliary",
                        "post",
                        "payload",
                        "encoder",
                        "nop",
                        "evasion",
                    ],
                },
                "platform": {"type": "string", "pattern": "^[A-Za-z0-9_.-]+$"},
                "cve": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
        },
    )


async def msf_search_handler(arguments: dict, context: RunContext) -> ToolResult:
    arguments = _drop_placeholder_filters(arguments)
    validate(arguments, msf_search_definition().input_schema)
    limit = arguments.get("limit", 50)
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    for key, pattern in (("cve", r"CVE-\d{4}-\d{4,}"), ("platform", r"[A-Za-z0-9_.-]+")):
        if key in arguments and not re.fullmatch(pattern, arguments[key]):
            raise ValueError(f"invalid {key}")
    try:
        config = MetasploitConfig.from_env()
        if not config.password:
            return ToolResult(verification_method="msf_credentials_missing")
        async with MetasploitClient(config) as client:
            if not await client.is_available():
                return ToolResult(verification_method="msf_unavailable")
            raw = await client.search_modules(**arguments)
            parsed = parse_msf_search(raw, arguments.get("query", ""))
            return ToolResult(
                output=client.redact(parsed.to_dict()),
                verified=True,
                verification_method="msf_search_rpc_parsed",
                evidence={"count": len(parsed.modules), "raw_sha256": parsed.raw_sha256},
            )
    except MetasploitError as exc:
        return ToolResult(
            verification_method="msf_rpc_failed", evidence={"error_type": type(exc).__name__}
        )
    except (ValueError, TypeError):
        return ToolResult(verification_method="msf_response_invalid")
