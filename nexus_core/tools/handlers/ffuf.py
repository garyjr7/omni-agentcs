"""Durable ``nexus.web.ffuf`` handler: content/path fuzzing.

ffuf is loud by nature: it hammers a URL with wordlist entries. The risk is
MEDIUM, the noise level is derived from the thread count (default HIGH), and a
rate limit is always applied because ffuf defaults to unlimited requests.
"""

from __future__ import annotations

import os
from pathlib import Path

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import SANDBOX_HOME_DIRNAME, sandbox_for_environment
from nexus_core.tools.parsers.ffuf import parse_ffuf_output

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox

FFUF_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
FFUF_DEFAULT_TIMEOUT_SECONDS = 120
FFUF_MAX_TIMEOUT_SECONDS = 900

FFUF_DEFAULT_THREADS = 10
FFUF_MAX_THREADS = 50
#: ffuf defaults `-rate` to 0 (unlimited); the handler never allows that.
FFUF_DEFAULT_RATE = 50
FFUF_MAX_RATE = 200
FFUF_DEFAULT_METHOD = "GET"
FFUF_ALLOWED_METHODS = ("GET", "POST", "HEAD")

#: Per-request HTTP timeout handed to ffuf itself.
FFUF_REQUEST_TIMEOUT_SECONDS = 10

#: Read-only system directories whose wordlists the tools may reference. The
#: wordlist path is attacker-influenced, so the default rule is "inside the
#: workspace"; but on a normal Kali the installed wordlists live under
#: /usr/share and the tools were therefore unusable (E2E #5 burned three
#: iterations on it). Allowing these read-only dirs keeps the boundary (still no
#: arbitrary file reads) while letting the agent use a real wordlist. Override
#: with NEXUS_WORDLIST_DIRS (os.pathsep-separated).
WORDLIST_DIRS_ENV = "NEXUS_WORDLIST_DIRS"
DEFAULT_SYSTEM_WORDLIST_DIRS = (
    "/usr/share/dirb/wordlists",
    "/usr/share/seclists",
    "/usr/share/wordlists",
)


def system_wordlist_dirs() -> tuple[Path, ...]:
    """Resolved, allowlisted system wordlist directories."""
    raw = os.getenv(WORDLIST_DIRS_ENV)
    values = raw.split(os.pathsep) if raw else DEFAULT_SYSTEM_WORDLIST_DIRS
    return tuple(Path(value).resolve() for value in values if str(value).strip())


def _inside(candidate: Path, root: Path) -> bool:
    return candidate == root or root in candidate.parents

#: Structural flags. They are always built by the handler from the validated
#: arguments (never supplied by the model) because they define the target, the
#: input file and the request volume of the run.
FFUF_STRUCTURAL_FLAGS: dict[str, tuple[str, bool]] = {
    "-u": ("high", True),
    "-w": ("high", True),
    "-t": ("high", True),
    "-X": ("high", True),
    "-e": ("high", True),
    "-o": ("low", True),
    "-of": ("low", True),
}

#: Non-structural flags the model may add: ``(baseline_noise, requires_value)``.
FFUF_ALLOWED_FLAGS: dict[str, tuple[str, bool]] = {
    "-mc": ("low", True),
    "-fc": ("low", True),
    "-rate": ("low", True),
    "-p": ("low", True),
    "-s": ("low", False),
    "-ac": ("low", False),
    "-r": ("low", False),
}

#: Flags that would bypass the scope check, execute commands, redirect output
#: or tunnel traffic through a third party.
FFUF_FORBIDDEN_FLAGS: set[str] = {
    "-u",
    "-w",
    "-X",
    "-e",
    "-t",
    "-o",
    "-of",
    "-od",
    "-json",
    "-x",
    "-replay-proxy",
    "-config",
    "-request",
    "-request-proto",
    "-input-cmd",
    "-input-num",
    "-input-shell",
    "-preflight",
    "-preflight-var",
    "-preflight-mode",
    "-postflight",
    "-postflight-var",
    "-b",
    "-d",
    "-H",
    "-recursion",
    "-recursion-depth",
    "-recursion-strategy",
    "-audit-log",
    "-debug-log",
    "-mode",
    "-D",
    "-sni",
    "-raw",
    "-search",
    "-scrapers",
    "-scraperfile",
    "-c",
    "-v",

}

#: Flags the handler always sets itself; user copies are dropped as no-ops.
FFUF_MANAGED_FLAGS: set[str] = {"-s"}

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")


def ffuf_noise_level(threads: int) -> str:
    """Map a thread count to the aggregate noise level.

    ``<= 2`` → ``low``; ``<= 5`` → ``medium``; anything else → ``high`` (the
    handler default of 10 threads is therefore HIGH).
    """
    if threads <= 2:
        return "low"
    if threads <= 5:
        return "medium"
    return "high"


def validate_and_canonicalize_ffuf_flags(
    raw_flags: list[str],
) -> tuple[list[str], str, set[str]]:
    """Validate model-provided ffuf flags.

    Returns ``(canonical_flags, noise_level, warnings)``. Raises ``ValueError``
    for empty, malformed, unknown or forbidden flags.
    """
    canonical: list[str] = []
    warnings: set[str] = set()
    noise_rank = 0
    index = 0
    while index < len(raw_flags):
        token = str(raw_flags[index]).strip()
        index += 1
        if not token:
            raise ValueError("empty ffuf flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"ffuf flag must start with '-': {token!r}")

        name, separator, inline_value = token.partition("=")
        if token in FFUF_FORBIDDEN_FLAGS or name in FFUF_FORBIDDEN_FLAGS:
            raise ValueError(f"ffuf flag is forbidden: {token!r}")

        spec = FFUF_ALLOWED_FLAGS.get(token) or FFUF_ALLOWED_FLAGS.get(name)
        if spec is None:
            raise ValueError(f"ffuf flag is not allowed: {token!r}")
        level, requires_value = spec
        noise_rank = max(noise_rank, NOISE_LEVELS[level])

        if requires_value:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw_flags):
                    raise ValueError(f"ffuf flag requires a value: {token!r}")
                value = str(raw_flags[index]).strip()
                index += 1
            if not value or value.startswith("-"):
                raise ValueError(f"invalid value for ffuf flag {token!r}: {value!r}")
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"ffuf flag does not take a value: {token!r}")
            canonical.append(name)

    if noise_rank == NOISE_LEVELS["high"]:
        warnings.add("high noise profile: heavy traffic against the target")
    return canonical, NOISE_NAMES[noise_rank], warnings


def resolve_wordlist(workspace_root: str | Path, wordlist: str) -> str:
    """Resolve a wordlist path and require it to be inside an allowed root.

    The wordlist is attacker-influenced data (it comes from the model), so a
    path traversal would turn ffuf into an arbitrary-file reader. The path must
    therefore live inside the workspace *or* inside a read-only system wordlist
    directory (:func:`system_wordlist_dirs`); never anywhere else. The ephemeral
    sandbox HOME lives inside the workspace but is sandbox plumbing, so it is
    off-limits too.
    """
    root = Path(workspace_root).resolve()
    candidate = Path(str(wordlist).strip())
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    in_workspace = _inside(candidate, root)
    in_system = any(_inside(candidate, directory) for directory in system_wordlist_dirs())
    if not in_workspace and not in_system:
        allowed = ", ".join(str(directory) for directory in system_wordlist_dirs())
        raise ValueError(
            "ffuf wordlist must live inside the workspace or a configured "
            f"system wordlist dir ({allowed})"
        )
    if in_workspace:
        sandbox_home = root / SANDBOX_HOME_DIRNAME
        if candidate == sandbox_home or sandbox_home in candidate.parents:
            raise ValueError("ffuf wordlist must not live in the sandbox HOME")
    if not candidate.is_file():
        raise ValueError(f"ffuf wordlist does not exist: {candidate}")
    return str(candidate)


def ffuf_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.ffuf``."""
    return ToolDefinition(
        tool_id="nexus.web.ffuf",
        name="FFUF content discovery",
        tenant_id=tenant_id,
        description=(
            "Fuzzing de rutas/directorios con wordlist. Ruidoso: SIEMPRE lleva "
            "rate limit y threads acotados. La wordlist debe estar en el "
            "workspace o en un directorio de sistema, p. ej. "
            "/usr/share/dirb/wordlists/common.txt."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 3, "maxLength": 2048},
                "wordlist": {"type": "string", "minLength": 1, "maxLength": 1024},
                "extensions": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 16},
                    "maxItems": 10,
                },
                "method": {"type": "string", "enum": list(FFUF_ALLOWED_METHODS)},
                "threads": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": FFUF_MAX_THREADS,
                },
                "rate": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": FFUF_MAX_RATE,
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 64},
                    "maxItems": 12,
                },
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 900},
            },
            "required": ["url", "wordlist"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.web.ffuf"],
        timeout_seconds=600,
        max_output_bytes=3_000_000,
        scope_target_field="url",
        scope_required=True,
    )


async def ffuf_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted, rate-limited ffuf scan through the sandbox."""
    url = str(arguments["url"]).strip()
    if "FUZZ" not in url:
        raise ValueError("ffuf url must contain the FUZZ keyword")

    method = str(arguments.get("method") or FFUF_DEFAULT_METHOD).strip().upper()
    if method not in FFUF_ALLOWED_METHODS:
        raise ValueError(f"ffuf method is not allowed: {method!r}")

    raw_threads = arguments.get("threads")
    threads = min(
        FFUF_MAX_THREADS,
        max(1, int(raw_threads) if raw_threads else FFUF_DEFAULT_THREADS),
    )
    raw_rate = arguments.get("rate")
    rate = min(
        FFUF_MAX_RATE,
        max(1, int(raw_rate) if raw_rate else FFUF_DEFAULT_RATE),
    )
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        FFUF_MAX_TIMEOUT_SECONDS,
        max(
            10,
            int(requested_timeout) if requested_timeout else FFUF_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    flags, flag_noise, warnings = validate_and_canonicalize_ffuf_flags(
        list(arguments.get("flags") or [])
    )
    user_flags = [token for token in flags if token not in FFUF_MANAGED_FLAGS]
    noise_level = ffuf_noise_level(threads)
    if NOISE_LEVELS[flag_noise] > NOISE_LEVELS[noise_level]:
        noise_level = flag_noise
    if noise_level == "high":
        warnings.add(f"high noise profile: {threads} threads against {url}")

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    wordlist = resolve_wordlist(workspace_root, str(arguments["wordlist"]))

    argv = [
        "ffuf",
        "-u",
        url,
        "-w",
        wordlist,
        "-json",
        "-s",
        "-t",
        str(threads),
        "-rate",
        str(rate),
        "-timeout",
        str(FFUF_REQUEST_TIMEOUT_SECONDS),
        "-X",
        method,
    ]
    extensions = [str(item).strip() for item in arguments.get("extensions") or [] if str(item).strip()]
    if extensions:
        argv.extend(["-e", ",".join(extensions)])
    argv.extend(user_flags)

    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=FFUF_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_FFUF_IMAGE",
        default_image="ghcr.io/ffuf/ffuf",
    )

    evidence: dict = {
        "noise_level": noise_level,
        "url": url,
        "wordlist": wordlist,
        "method": method,
        "threads": threads,
        "rate": rate,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
        "warnings": sorted(warnings),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "ffuf run timed out", "url": url, "noise_level": noise_level},
            verified=False,
            verification_method="ffuf_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        fuzz = parse_ffuf_output(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "url": url, "noise_level": noise_level},
            verified=False,
            verification_method="ffuf_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "count": len(fuzz.matches),
            "status_counts": dict(fuzz.status_counts),
            "raw_sha256": fuzz.raw_sha256,
            "malformed_lines": fuzz.malformed_lines,
        }
    )
    # No match is a valid outcome: the fuzz completed and nothing matched.
    return ToolResult(
        output={
            "url": url,
            "noise_level": noise_level,
            "count": len(fuzz.matches),
            "matches": [match.to_dict() for match in fuzz.matches],
        },
        verified=result.exit_code in {0, 1},
        verification_method="ffuf_json_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
