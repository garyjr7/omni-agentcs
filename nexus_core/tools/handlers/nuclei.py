"""Durable ``nexus.web.nuclei`` handler: template-based vulnerability scanning.

nuclei sends real (but bounded) test payloads, so the risk is MEDIUM. The noise
level is derived from the requested severities, and interactsh/OAST callbacks,
DAST mode, headless templates and code templates are disabled by default.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.nuclei import parse_nuclei_jsonl

from ._exec import (
    MAX_BATCH_TARGETS,
    RECON_ALLOWED_PROGRAMS,
    append_repeated,
    normalize_targets,
    run_in_sandbox,
)

NUCLEI_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
NUCLEI_DEFAULT_TIMEOUT_SECONDS = 120
NUCLEI_MAX_TIMEOUT_SECONDS = 1800

#: Template directory used when the model does not select templates.
#: Overridable with ``NEXUS_NUCLEI_TEMPLATES``.
DEFAULT_NUCLEI_TEMPLATES = "/opt/nuclei-templates"

#: Caps for the explicit selections accepted from the model.
NUCLEI_MAX_EXPLICIT_TEMPLATES = 10
NUCLEI_MAX_TAGS = 10

#: Tags must start with an alphanumeric/underscore so they can never be
#: smuggled into the argv as if they were a flag.
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")

#: Flags the model may add, mapped to ``(baseline_noise, requires_value)``.
NUCLEI_ALLOWED_FLAGS: dict[str, tuple[str, bool]] = {
    "-severity": ("medium", True),
    "-s": ("medium", True),
    "-tags": ("medium", True),
    "-exclude-tags": ("low", True),
    "-etags": ("low", True),
    "-rl": ("low", True),
    "-rate-limit": ("low", True),
    "-c": ("low", True),
    "-concurrency": ("low", True),
    "-timeout": ("low", True),
    "-silent": ("low", False),
    "-jsonl": ("low", False),
    "-no-color": ("low", False),
    "-no-interactsh": ("low", False),
    "-omit-raw": ("low", False),
}

#: Flags that are never accepted from the model: OAST callbacks, intrusive
#: protocols, target overrides (they would bypass the scope check), or output
#: redirection (it would break parsing).
NUCLEI_FORBIDDEN_FLAGS: set[str] = {
    "-iserver",
    "-interactsh-server",
    "-itoken",
    "-interactsh-token",
    "-dast",
    "-dts",
    "-dast-server",
    "-fuzz",
    "-headless",
    "-code",
    "-file",
    "-pt",
    "-type",
    "-ept",
    "-exclude-type",
    "-u",
    "-target",
    "-l",
    "-list",
    "-targets-inline",
    "-im",
    "-input-mode",
    "-t",
    "-templates",
    "-turl",
    "-template-url",
    "-w",
    "-workflows",
    "-wurl",
    "-workflow-url",
    "-config",
    "-rc",
    "-report-config",
    "-H",
    "-header",
    "-V",
    "-var",
    "-r",
    "-resolvers",
    "-proxy",
    "-o",
    "-je",
    "-json-export",
    "-jle",
    "-jsonl-export",
    "-me",
    "-markdown-export",
    "-se",
    "-sarif-export",
    "-rdb",
    "-report-db",
    "-sresp",
    "-store-resp",
    "-srd",
    "-store-resp-dir",
    "-ai",
    "-prompt",
    "-sign",
    "-resume",
    "-eh",
    "-exclude-hosts",
    "-irr",
    "-include-rr",
    "-sa",
    "-scan-all-ips",
    "-fr",
    "-follow-redirects",
    "-mr",
    "-max-redirects",
}

#: Flags the handler always sets itself; user copies are dropped as no-ops.
#: ``-duc`` disables the automatic nuclei/templates update check: a sandboxed
#: run must not reach out to the network on its own, and the check is pure
#: latency when templates are already installed.
NUCLEI_MANAGED_ARGV: tuple[str, ...] = (
    "-jsonl",
    "-silent",
    "-nc",
    "-no-interactsh",
    "-duc",
)
NUCLEI_MANAGED_FLAGS: set[str] = {
    "-jsonl",
    "-j",
    "-silent",
    "-no-color",
    "-nc",
    "-no-interactsh",
    "-ni",
}

#: Default template tags excluded to keep the scan non-intrusive.
NUCLEI_DEFAULT_EXCLUDE_TAGS = "intrusive,fuzz,fuzzing,dos,brute-force"

#: Per-request timeout handed to nuclei itself.
NUCLEI_REQUEST_TIMEOUT_SECONDS = 10

#: Severities scanned when the model does not pick any.
NUCLEI_DEFAULT_SEVERITIES = ("low", "medium")

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")


def _nuclei_templates_dir() -> str:
    """Return the configured nuclei templates directory.

    ``NEXUS_NUCLEI_TEMPLATES`` overrides the packaged default
    :data:`DEFAULT_NUCLEI_TEMPLATES`.
    """
    return os.getenv("NEXUS_NUCLEI_TEMPLATES", DEFAULT_NUCLEI_TEMPLATES)


#: Public alias: the resolver is part of the handler contract now.
nuclei_templates_dir = _nuclei_templates_dir


def validate_template_paths(templates: list[str] | None, base_dir: str) -> list[str]:
    """Resolve explicit template selections and keep them inside ``base_dir``.

    The model may narrow a scan to concrete templates, but pointing nuclei at
    arbitrary local files would turn it into an arbitrary-file reader, so every
    entry must live inside the configured templates directory. Raises
    ``ValueError`` for empty, out-of-tree, missing or over-limit selections.
    """
    if not templates:
        return []
    if len(templates) > NUCLEI_MAX_EXPLICIT_TEMPLATES:
        raise ValueError(
            f"too many nuclei templates: {len(templates)} > {NUCLEI_MAX_EXPLICIT_TEMPLATES}"
        )
    root = Path(base_dir).resolve()
    resolved: list[str] = []
    for entry in templates:
        text = str(entry).strip()
        if not text:
            raise ValueError("empty nuclei template path is not allowed")
        candidate = Path(text)
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError(f"nuclei template must live inside {base_dir}: {text!r}")
        if not candidate.exists():
            raise ValueError(f"nuclei template does not exist: {text!r}")
        if str(candidate) not in resolved:
            resolved.append(str(candidate))
    return resolved


def validate_tags(tags: list[str] | None) -> list[str]:
    """Validate and de-duplicate template tags requested by the model."""
    if not tags:
        return []
    if len(tags) > NUCLEI_MAX_TAGS:
        raise ValueError(f"too many nuclei tags: {len(tags)} > {NUCLEI_MAX_TAGS}")
    cleaned: list[str] = []
    for tag in tags:
        text = str(tag).strip()
        if not _TAG_RE.match(text):
            raise ValueError(f"invalid nuclei tag: {tag!r}")
        if text not in cleaned:
            cleaned.append(text)
    return cleaned


def nuclei_noise_level(severities: list[str] | tuple[str, ...]) -> str:
    """Map requested severities to the aggregate noise level.

    ``info``/``low``/``unknown`` → ``low``; ``medium`` → ``medium``;
    ``high``/``critical`` → ``high``. An empty selection means the handler
    default (``low,medium``).
    """
    normalized = {str(item).strip().lower() for item in severities if str(item).strip()}
    if not normalized:
        return "medium"
    if normalized & {"high", "critical"}:
        return "high"
    if "medium" in normalized:
        return "medium"
    return "low"


def validate_and_canonicalize_nuclei_flags(
    raw_flags: list[str],
) -> tuple[list[str], str, set[str]]:
    """Validate model-provided nuclei flags.

    Returns ``(canonical_flags, noise_level, warnings)``. Raises ``ValueError``
    for empty, malformed, unknown or forbidden flags.
    """
    canonical: list[str] = []
    warnings: set[str] = set()
    noise_rank = 0
    severity_values: list[str] = []
    index = 0
    while index < len(raw_flags):
        token = str(raw_flags[index]).strip()
        index += 1
        if not token:
            raise ValueError("empty nuclei flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"nuclei flag must start with '-': {token!r}")

        name, separator, inline_value = token.partition("=")
        if token in NUCLEI_FORBIDDEN_FLAGS or name in NUCLEI_FORBIDDEN_FLAGS:
            raise ValueError(f"nuclei flag is forbidden: {token!r}")

        spec = NUCLEI_ALLOWED_FLAGS.get(token) or NUCLEI_ALLOWED_FLAGS.get(name)
        if spec is None:
            raise ValueError(f"nuclei flag is not allowed: {token!r}")
        level, requires_value = spec
        noise_rank = max(noise_rank, NOISE_LEVELS[level])

        if requires_value:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw_flags):
                    raise ValueError(f"nuclei flag requires a value: {token!r}")
                value = str(raw_flags[index]).strip()
                index += 1
            if not value or value.startswith("-"):
                raise ValueError(f"invalid value for nuclei flag {token!r}: {value!r}")
            if name in {"-severity", "-s"}:
                severity_values.extend(
                    part.strip().lower() for part in value.split(",") if part.strip()
                )
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"nuclei flag does not take a value: {token!r}")
            canonical.append(name)

    noise = nuclei_noise_level(severity_values) if severity_values else NOISE_NAMES[noise_rank]
    if severity_values and noise == "high":
        warnings.add("high-severity templates can be intrusive and loud")
    return canonical, noise, warnings


def nuclei_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.nuclei``."""
    return ToolDefinition(
        tool_id="nexus.web.nuclei",
        name="Nuclei template vulnerability scan",
        tenant_id=tenant_id,
        description=(
            "Escaneo de vulnerabilidades con templates de nuclei "
            f"({DEFAULT_NUCLEI_TEMPLATES}; sin interactsh, sin dast, sin headless)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 3, "maxLength": 2048},
                    "minItems": 1,
                    "maxItems": MAX_BATCH_TARGETS,
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 128},
                    "maxItems": 20,
                },
                "templates": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": 1024},
                    "maxItems": NUCLEI_MAX_EXPLICIT_TEMPLATES,
                    "description": (
                        "Subset de templates a usar. Default: todos los de "
                        f"{DEFAULT_NUCLEI_TEMPLATES}."
                    ),
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 64},
                    "maxItems": NUCLEI_MAX_TAGS,
                    "description": "Filtra templates por tag (tech, cve, misconfig...).",
                },
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 1800},
            },
            "required": ["targets"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.web.nuclei"],
        timeout_seconds=600,
        max_output_bytes=5_000_000,
        scope_target_field="targets",
        scope_required=True,
    )


async def nuclei_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted nuclei scan through the sandbox."""
    targets = normalize_targets(arguments.get("targets"))
    flags, flag_noise, warnings = validate_and_canonicalize_nuclei_flags(
        list(arguments.get("flags") or [])
    )

    # Fail closed: without a template directory nuclei would try to download
    # templates and hang until the sandbox timeout kills it.
    templates_dir = _nuclei_templates_dir()
    if not Path(templates_dir).is_dir():
        return ToolResult(
            output={
                "error": "nuclei templates directory not found",
                "templates_dir": templates_dir,
            },
            verified=False,
            verification_method="nuclei_templates_missing",
        )
    # nuclei does not follow a symlinked template *directory*, so the run gets
    # the canonical path (``/opt/nuclei-templates -> /…`` on this host).
    resolved_templates_dir = str(Path(templates_dir).resolve())
    selected_templates = validate_template_paths(arguments.get("templates"), templates_dir)
    tags = validate_tags(arguments.get("tags"))
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        NUCLEI_MAX_TIMEOUT_SECONDS,
        max(
            10,
            int(requested_timeout)
            if requested_timeout
            else NUCLEI_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    # Managed flags are always set by the handler; user copies are dropped
    # (they are all boolean, so dropping them cannot orphan a value token).
    user_flags = [token for token in flags if token not in NUCLEI_MANAGED_FLAGS]
    if any(token in {"-severity", "-s"} for token in user_flags):
        noise_level = flag_noise
    else:
        # The handler injects the default severities, so the noise level must be
        # derived from what will actually run, not from the empty user input.
        noise_level = nuclei_noise_level(NUCLEI_DEFAULT_SEVERITIES)
        user_flags = ["-severity", ",".join(NUCLEI_DEFAULT_SEVERITIES), *user_flags]
    if not any(token in {"-exclude-tags", "-etags"} for token in user_flags):
        user_flags = [*user_flags, "-exclude-tags", NUCLEI_DEFAULT_EXCLUDE_TAGS]
    if tags and "-tags" not in user_flags:
        user_flags = ["-tags", ",".join(tags), *user_flags]
    if "-timeout" not in user_flags:
        user_flags = ["-timeout", str(NUCLEI_REQUEST_TIMEOUT_SECONDS), *user_flags]

    # ``-t`` is always present: the stable directory by default, the explicit
    # selection when the model narrowed the scan.
    template_targets = selected_templates or [resolved_templates_dir]
    template_flags: list[str] = []
    for template in template_targets:
        template_flags.extend(["-t", template])

    effective_flags = [*NUCLEI_MANAGED_ARGV, *template_flags, *user_flags]
    argv = ["nuclei", *effective_flags]
    argv.extend(append_repeated("-u", targets))

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=NUCLEI_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_NUCLEI_IMAGE",
        default_image="projectdiscovery/nuclei",
    )

    evidence: dict = {
        "noise_level": noise_level,
        "targets_requested": len(targets),
        "timeout_seconds": timeout_seconds,
        "interactsh": False,
        "templates_dir": resolved_templates_dir,
        "templates": list(template_targets),
        "tags": list(tags),
        "flags": list(effective_flags),
        "warnings": sorted(warnings),
    }
    if result.timed_out:
        return ToolResult(
            output={
                "error": "nuclei run timed out",
                "targets_requested": len(targets),
                "noise_level": noise_level,
            },
            verified=False,
            verification_method="nuclei_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        scan = parse_nuclei_jsonl(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={
                "error": str(exc),
                "targets_requested": len(targets),
                "noise_level": noise_level,
            },
            verified=False,
            verification_method="nuclei_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "count": len(scan.findings),
            "severity_counts": dict(scan.severity_counts),
            "raw_sha256": scan.raw_sha256,
            "malformed_lines": scan.malformed_lines,
        }
    )
    # No finding is a valid outcome: the scan completed and matched nothing.
    return ToolResult(
        output={
            "targets_requested": len(targets),
            "noise_level": noise_level,
            "count": len(scan.findings),
            "findings": [finding.to_dict() for finding in scan.findings],
        },
        verified=result.exit_code in {0, 1},
        verification_method="nuclei_jsonl_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
