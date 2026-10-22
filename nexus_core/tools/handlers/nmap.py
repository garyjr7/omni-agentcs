"""Durable nmap handler: allowlisted flags, sandbox execution, XML parsing."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import SandboxResult, sandbox_for_environment
from nexus_core.tools.parsers.nmap import parse_nmap_xml

# Cada entrada: flag -> (nivel_ruido, requiere_valor)
# Nivel: "low" | "medium" | "high"
NMAP_ALLOWED_FLAGS: dict[str, tuple[str, bool]] = {
    "-sV": ("medium", False),
    "-sC": ("medium", False),
    "-sS": ("medium", False),
    "-sT": ("high", False),
    "-sU": ("high", False),
    "-sn": ("low", False),
    "-Pn": ("low", False),
    "-n": ("low", False),
    "-O": ("high", False),
    "--open": ("low", False),
    "-F": ("low", False),
    "-p": ("low", True),
    "-p-": ("medium", False),
    "--top-ports": ("medium", True),
    "-T0": ("low", False),
    "-T1": ("low", False),
    "-T2": ("medium", False),
    "-T3": ("medium", False),
    "-T4": ("high", False),
    "-T5": ("high", False),
    "--max-retries": ("low", True),
    "--host-timeout": ("low", True),
    # Rate controls: the operator opts into a faster (noisier) scan. Without
    # them a full ``-p-`` scan against a ~90 ms RTT host spends most of its time
    # in nmap's conservative default pacing (measured: 43.8 s vs 23 s with
    # ``--min-rate 5000 -n`` on the RootMe target).
    "--min-rate": ("medium", True),
    "--max-rate": ("low", True),
}

# Flags PROHIBIDOS siempre, sin importar el scope.
NMAP_FORBIDDEN_FLAGS: set[str] = {
    "--script",
    "-sV --version-all",
    "-A",
    "--osscan-guess",
    "--traceroute",
    "-sO",
    "-sW",
    "-sM",
    "-sN",
    "-sF",
    "-sX",
    "--script-args",
    "-oS",
    "-oN",
    "-oG",
}

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")

NMAP_ALLOWED_PROGRAMS = ("python3", "git", "rg", "nmap")
NMAP_DEFAULT_TIMEOUT_SECONDS = 120
NMAP_MAX_TIMEOUT_SECONDS = 600

#: ``full_tcp`` finding fewer open ports than this triggers the fallback scan.
#: Measured on Simple CTF (2026-10-17): ``-p- -T4`` reported 65 533 ports as
#: ``filtered`` and missed 2222/tcp, the only way into the room, while a
#: ``--top-ports 1000`` pass found it in 9,65 s. A host with fewer than three
#: open ports over a full sweep is far more likely to have paced itself out
#: than to be that empty.
NMAP_FALLBACK_MIN_OPEN_PORTS = 3
#: A sweep that reports at least this many ``filtered`` ports could not tell
#: "closed" from "dropped" (the measured host answers 65 533 of them), so its
#: port list is untrustworthy even when it did find a few open ones.
NMAP_FALLBACK_FILTERED_PORTS = 1_000
#: The fallback re-scans only the top 1 000 ports: the point is to defeat the
#: rate-limit that swallowed the full sweep, not to sweep twice.
NMAP_FALLBACK_FLAGS: tuple[str, ...] = (
    "-Pn",
    "-n",
    "-sS",
    "--top-ports",
    "1000",
    "--min-rate",
    "1000",
    "-T4",
    "--open",
)
NMAP_FALLBACK_TIMEOUT_SECONDS = 180
#: Hard cap on the raw XML handed back in ``stdout`` once it has been parsed.
#: The full XML averages ~30 KB and only floods the agent context: the parsed
#: ``output.scan`` + ``raw_xml_sha256`` carry the whole finding, so the raw text
#: is kept only as a short forensic prefix (H1 of the RUN7 report).
NMAP_STDOUT_MAX_BYTES = 500

# Perfiles de reconocimiento: nombre -> (flags base, timeout recomendado).
# El perfil se expande server-side, así que el modelo nunca inventa flags: pide
# un nombre conocido. ``full_tcp`` y ``service`` cubren los 65535 puertos TCP
# (-p-), que es el paso que descubre servicios fuera de la lista "común" (p. ej.
# FTP en 21). Cuando el perfil trae ``-p-`` y el modelo manda además un ``-p``,
# hay dos casos medidos: en ``full_tcp`` la selección no puede acotar nada y se
# descarta (``drop_redundant_port_flags``); en ``service`` sí acota, porque el
# paso natural tras un barrido es pedir versión sólo de los puertos abiertos
# (ver ``selects_ports``). Descartarla ahí costaba 600 s de timeout y cero
# hechos: ``-p- -sV -sC`` sobre 65 535 puertos no termina en 10 minutos.
NMAP_PROFILES: dict[str, dict[str, Any]] = {
    "quick": {"flags": ["-Pn", "-n", "-F", "-T4"], "timeout_seconds": 120},
    "full_tcp": {"flags": ["-Pn", "-n", "-p-", "-T4", "--open"], "timeout_seconds": 600},
    "service": {
        "flags": ["-Pn", "-n", "-p-", "-sV", "-sC", "-T4", "--open"],
        "timeout_seconds": 600,
    },
    "top_udp": {
        "flags": ["-Pn", "-sU", "--top-ports", "100", "-T4"],
        "timeout_seconds": 600,
    },
}


def validate_and_canonicalize_flags(raw_flags: list[str]) -> tuple[list[str], str, set[str]]:
    """Validate raw LLM-provided flags and compute the aggregate noise level.

    Returns ``(canonical_flags, noise_level, warnings)``. Raises ``ValueError``
    for empty, malformed, unknown or forbidden flags.
    """
    if not isinstance(raw_flags, list) or not all(isinstance(flag, str) for flag in raw_flags):
        raise ValueError("flags must be strings")
    canonical: list[str] = []
    warnings: set[str] = set()
    noise_rank = 0
    index = 0
    while index < len(raw_flags):
        token = str(raw_flags[index]).strip()
        index += 1
        if not token:
            raise ValueError("empty nmap flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"nmap flag must start with '-': {token!r}")

        name, separator, inline_value = token.partition("=")
        if token in NMAP_FORBIDDEN_FLAGS or name in NMAP_FORBIDDEN_FLAGS:
            raise ValueError(f"nmap flag is forbidden: {token!r}")

        spec = NMAP_ALLOWED_FLAGS.get(token) or NMAP_ALLOWED_FLAGS.get(name)
        if spec is None:
            raise ValueError(f"nmap flag is not allowed: {token!r}")
        level, requires_value = spec
        noise_rank = max(noise_rank, NOISE_LEVELS[level])

        if requires_value:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw_flags):
                    raise ValueError(f"nmap flag requires a value: {token!r}")
                value = str(raw_flags[index]).strip()
                index += 1
            if not value or value.startswith("-") or any(char.isspace() or ord(char) < 32 for char in value):
                raise ValueError(f"invalid value for nmap flag {token!r}: {value!r}")
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"nmap flag does not take a value: {token!r}")
            canonical.append(token)

    if noise_rank == NOISE_LEVELS["high"]:
        warnings.add("high noise profile: flags generate significant traffic")
    if "-sS" in canonical:
        warnings.add("SYN scan may require elevated privileges inside the sandbox")
    return canonical, NOISE_NAMES[noise_rank], warnings


def selects_ports(raw_flags: list[str]) -> bool:
    """Whether the model's flags choose ports themselves (not the ``-p-`` sweep).

    ``-p-`` is explicitly *not* a selection: it is the full sweep the profile
    already means. ``-p 22,80``, ``-p=22,80``, ``--top-ports 1000`` and
    ``--top-ports=1000`` are. Used to decide whether a ``service`` scan should
    fingerprint the named ports instead of all 65 535.
    """
    for token in raw_flags:
        candidate = str(token).strip()
        if candidate in {"-p", "--top-ports"}:
            return True
        if candidate.startswith(("-p=", "--top-ports=")):
            return True
    return False


def drop_redundant_port_flags(
    raw_flags: list[str], base_flags: list[str]
) -> tuple[list[str], list[str]]:
    """Drop the model's port selection when the profile already scans all ports.

    ``full_tcp``/``service`` expand to ``-p-`` server-side, so a ``-p 21,80``
    sent alongside them cannot narrow anything: it only produced a ValueError
    that cost the run an iteration. The pair is removed (with its value) and
    reported back in ``evidence.warnings`` instead of failing the call.

    Returns ``(kept_flags, dropped_flags)``.
    """
    if "-p-" not in base_flags:
        return list(raw_flags), []
    kept: list[str] = []
    dropped: list[str] = []
    index = 0
    while index < len(raw_flags):
        token = str(raw_flags[index]).strip()
        index += 1
        if token == "-p":
            dropped.append(token)
            # The value is the next token when it is not itself a flag.
            if index < len(raw_flags) and not str(raw_flags[index]).startswith("-"):
                dropped.append(str(raw_flags[index]))
                index += 1
            continue
        if token.startswith("-p=") or token.startswith("--top-ports="):
            dropped.append(token)
            continue
        if token == "--top-ports":
            dropped.append(token)
            if index < len(raw_flags) and not str(raw_flags[index]).startswith("-"):
                dropped.append(str(raw_flags[index]))
                index += 1
            continue
        kept.append(raw_flags[index - 1])
    return kept, dropped


def needs_port_fallback(
    flags: list[str], open_ports_total: int, filtered_ports_total: int = 0
) -> bool:
    """Whether a full-port sweep came back either empty or blind.

    Only a sweep that claimed to cover every TCP port (``-p-``) is retried: a
    deliberate ``-p 21,80`` that returns two ports is the operator's contract,
    not a false negative. Two signatures are retried, both measured on Simple
    CTF: a sweep with fewer than :data:`NMAP_FALLBACK_MIN_OPEN_PORTS` open ports
    (2 open, 65 533 filtered, 2222/tcp invisible) and one that could not tell
    closed from dropped for at least :data:`NMAP_FALLBACK_FILTERED_PORTS` ports.
    The thresholds are named so both cases stay regression tests instead of
    magic numbers.
    """
    if "-p-" not in flags:
        return False
    return (
        open_ports_total < NMAP_FALLBACK_MIN_OPEN_PORTS
        or filtered_ports_total >= NMAP_FALLBACK_FILTERED_PORTS
    )


def _port_key(port: dict[str, Any]) -> tuple[str, str]:
    return (str(port.get("protocol", "")), str(port.get("port", "")))


def merge_scans(primary: Any, fallback: Any) -> tuple[Any, list[dict[str, Any]]]:
    """Union the fallback's ports into the primary scan.

    Returns ``(merged_scan, recovered_ports)``. Ports keep their primary
    finding (state, service, product) and only the ones the first sweep missed
    are added, so a fallback that fails or repeats the same answer costs nothing
    but its own absence.
    """
    recovered: list[dict[str, Any]] = []
    if not fallback.hosts:
        return primary, recovered
    by_ip = {host.ip: host for host in fallback.hosts if host.ip}
    merged_hosts = []
    for host in primary.hosts:
        extra = by_ip.get(host.ip)
        if extra is None:
            merged_hosts.append(host)
            continue
        known = {_port_key(port) for port in host.ports}
        added = [dict(port) for port in extra.ports if _port_key(port) not in known]
        recovered.extend(added)
        if added:
            merged_hosts.append(replace(host, ports=(*host.ports, *added)))
        else:
            merged_hosts.append(host)
    if not primary.hosts:
        # A sweep that missed the host entirely: the fallback's hosts are the
        # only evidence there is.
        merged_hosts = list(fallback.hosts)
        recovered = [dict(port) for host in fallback.hosts for port in host.ports]
    merged = replace(
        primary,
        hosts=tuple(merged_hosts),
        elapsed_seconds=primary.elapsed_seconds + fallback.elapsed_seconds,
    )
    return merged, recovered


def truncate_stdout(
    stdout: str, limit: int = NMAP_STDOUT_MAX_BYTES
) -> tuple[str, bool]:
    """Clip raw stdout to ``limit`` UTF-8 bytes.

    Returns ``(text, truncated)``. The cut is done on bytes and decoded
    leniently so a multi-byte character straddling the boundary never raises and
    the result is never longer than ``limit`` bytes.
    """
    raw = str(stdout or "")
    encoded = raw.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return raw, False
    return encoded[:limit].decode("utf-8", "ignore"), True


def nmap_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.nmap``."""
    return ToolDefinition(
        tool_id="nexus.recon.nmap",
        effect="read_only",
        idempotent=True,
        name="Nmap scan",
        tenant_id=tenant_id,
        description=(
            "Ejecuta nmap contra un target dentro del scope. 'full_tcp' barre "
            "los 65535 puertos TCP y 'service' añade -sV -sC a ese barrido: no "
            "añadas '-p' con 'full_tcp'. Con 'service' sí: pásale los puertos "
            "que ya descubriste (p. ej. flags=['-p','22,80','-sV','-sC']) y el "
            "handler quita el -p- del perfil para hacer fingerprint solo de "
            "esos; sin '-p' el -sV -sC recorre los 65535 y tarda minutos. Si un "
            "barrido -p- sale vacío o ciego (pocos abiertos, muchos filtered), "
            "se reintenta top-1000 (-sS -Pn --min-rate 1000)."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "profile": {
                    "type": "string",
                    "enum": sorted(NMAP_PROFILES),
                    "description": (
                        "Perfil de escaneo predefinido. 'full_tcp' descubre los "
                        "65535 puertos TCP (-p-) y 'service' añade detección de "
                        "versiones. Con 'full_tcp' no pases '-p' ni "
                        "'--top-ports' (se ignoran). Con 'service' pásalos si ya "
                        "sabes los puertos: '-p 22,80' hace que -sV -sC corra "
                        "solo ahí y el -p- del perfil se descarta."
                    ),
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 64},
                    "maxItems": 20,
                    "description": (
                        "Flags sueltos extra (p. ej. ['-sV']). Con 'service' "
                        "incluye '-p <puertos>' para acotar el fingerprint a lo "
                        "ya descubierto; con 'full_tcp' no incluyas '-p'."
                    ),
                },
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 1800},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.recon.nmap"],
        timeout_seconds=600,
        max_output_bytes=4_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def _run_nmap(sandbox: Any, argv: list[str], timeout_seconds: int) -> SandboxResult:
    """Run nmap through the given sandbox, normalizing the OCI signature."""
    from ._exec import run_in_sandbox

    return await run_in_sandbox(sandbox, argv, timeout_seconds=timeout_seconds,
                                image_env="NEXUS_NMAP_IMAGE", default_image="instrumentisto/nmap")


async def nmap_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Execute an allowlisted nmap scan inside a sandbox and parse its XML."""
    from nexus_core.tools.execution_contract import validate_target

    target = validate_target(arguments["target"])

    profile = arguments.get("profile")
    profile_name: str | None = None
    base_flags: list[str] = []
    profile_timeout: int | None = None
    if profile not in (None, ""):
        profile_name = str(profile).strip()
        spec = NMAP_PROFILES.get(profile_name)
        if spec is None:
            raise ValueError(f"unknown nmap profile: {profile_name!r}")
        base_flags = list(spec["flags"])
        profile_timeout = int(spec["timeout_seconds"])

    model_flags = list(arguments.get("flags") or [])
    narrowed_service = False
    if profile_name == "service" and "-p-" in base_flags and selects_ports(model_flags):
        # DeadDrop (2026-10-22): tras un ``full_tcp`` con 22/80 abiertos, el
        # modelo pidió ``profile="service"`` + ``-p 22,80 -sV -sC`` y el handler
        # volvió a barrer 65 535 puertos con version detection: 600 s de timeout
        # y ningún hecho. El fingerprint de los puertos ya descubiertos es el
        # paso siguiente correcto, así que la selección manda sobre el ``-p-``.
        base_flags = [flag for flag in base_flags if flag != "-p-"]
        narrowed_service = True
    raw_flags, dropped_port_flags = drop_redundant_port_flags(model_flags, base_flags)
    flags, noise_level, warnings = validate_and_canonicalize_flags([*base_flags, *raw_flags])
    if "-p-" in flags and "-p" in flags:
        raise ValueError("conflicting nmap flags: '-p-' (all ports) and '-p <ports>'")
    warnings = set(warnings)
    if profile_name:
        warnings.add(f"profile: {profile_name}")
    if narrowed_service:
        warnings.add(
            "service scan narrowed to the port selection in flags: -p- dropped "
            "so -sV/-sC only touch the ports named"
        )
    if dropped_port_flags:
        # The call succeeds; tell the model why its port selection had no effect.
        warnings.add(
            "ignored redundant port flags "
            f"{' '.join(dropped_port_flags)}: profile {profile_name!r} already "
            "scans all 65535 TCP ports (-p-)"
        )

    requested_timeout = arguments.get("timeout_seconds")
    if requested_timeout:
        timeout_seconds = min(NMAP_MAX_TIMEOUT_SECONDS, max(10, int(requested_timeout)))
    elif profile_timeout:
        timeout_seconds = min(NMAP_MAX_TIMEOUT_SECONDS, max(10, profile_timeout))
    else:
        timeout_seconds = NMAP_DEFAULT_TIMEOUT_SECONDS

    argv = ["nmap", *flags, "-oX", "-", target]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=NMAP_ALLOWED_PROGRAMS)
    result = await _run_nmap(sandbox, argv, timeout_seconds)

    if result.timed_out:
        return ToolResult(
            output={"error": "nmap scan timed out", "target": target},
            verified=False,
            verification_method="nmap_timeout",
            evidence={"noise_level": noise_level, "timeout_seconds": timeout_seconds},
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        scan = parse_nmap_xml(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="nmap_xml_parse_failed",
            evidence={"noise_level": noise_level},
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    open_ports_total = sum(
        1 for host in scan.hosts for port in host.ports if port["state"] == "open"
    )
    filtered_ports_total = sum(
        int(count)
        for host in scan.hosts
        for state, count in host.extraports.items()
        if state == "filtered"
    )
    fallback_evidence: dict[str, Any] | None = None
    primary_open_ports = open_ports_total
    if needs_port_fallback(flags, open_ports_total, filtered_ports_total):
        # The full sweep paced itself out on a host that drops closed ports; a
        # short ``--top-ports`` pass with an explicit rate crosses that floor.
        fallback_argv = ["nmap", *NMAP_FALLBACK_FLAGS, "-oX", "-", target]
        fallback_result = await _run_nmap(
            sandbox, fallback_argv, min(timeout_seconds, NMAP_FALLBACK_TIMEOUT_SECONDS)
        )
        fallback_evidence = {
            "reason": (
                f"full port sweep returned {open_ports_total} open ports and "
                f"{filtered_ports_total} filtered"
            ),
            "args": " ".join(fallback_argv),
            "timed_out": fallback_result.timed_out,
            "exit_code": fallback_result.exit_code,
        }
        if not fallback_result.timed_out and fallback_result.exit_code in {0, 1}:
            try:
                fallback_scan = parse_nmap_xml(fallback_result.stdout)
            except ValueError as exc:
                fallback_evidence["error"] = str(exc)
            else:
                scan, recovered = merge_scans(scan, fallback_scan)
                fallback_evidence["raw_xml_sha256"] = fallback_scan.raw_xml_sha256
                fallback_evidence["ports_open_total"] = sum(
                    1 for host in fallback_scan.hosts for port in host.ports
                    if port["state"] == "open"
                )
                fallback_evidence["recovered_ports"] = [
                    f"{port['port']}/{port['protocol']}" for port in recovered
                ]
                if recovered:
                    warnings.add(
                        "fallback scan recovered ports the full sweep missed: "
                        + ", ".join(
                            f"{port['port']}/{port['protocol']}" for port in recovered
                        )
                    )
        else:
            fallback_evidence["error"] = "fallback scan failed"
        open_ports_total = sum(
            1 for host in scan.hosts for port in host.ports if port["state"] == "open"
        )
        warnings.add(
            "fallback: top-1000 scan (-sS -Pn --min-rate 1000) after the full "
            f"sweep returned {primary_open_ports} open ports out of "
            f"{filtered_ports_total} filtered"
        )
    verified = result.exit_code in {0, 1}
    # The XML is already parsed into ``output.scan``; do not ship the raw ~30 KB
    # back in stdout (it only inflates the agent's context). Keep a short prefix
    # and flag the truncation (H1).
    stdout_text, stdout_truncated = truncate_stdout(result.stdout)
    output: dict[str, Any] = {
        "target": target,
        "noise_level": noise_level,
        "profile": profile_name,
        "scan": scan.to_dict(),
    }
    if dropped_port_flags:
        output["ignored_flags"] = dropped_port_flags
    if stdout_truncated:
        output["stdout_truncated"] = True
    return ToolResult(
        output=output,
        verified=verified,
        verification_method="nmap_xml_parsed",
        evidence={
                "noise_level": noise_level,
                "profile": profile_name,
                "host_count": len(scan.hosts),
            "hosts_up": scan.hosts_up,
            "ports_open_total": open_ports_total,
            "elapsed_seconds": scan.elapsed_seconds,
            "raw_xml_sha256": scan.raw_xml_sha256,
            "warnings": sorted(warnings),
            "stdout_truncated": stdout_truncated,
            **({"fallback": fallback_evidence} if fallback_evidence else {}),
        },
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=stdout_text,
        stderr=result.stderr,
    )
