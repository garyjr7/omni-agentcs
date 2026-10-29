"""How much of the machine a run may use, and how to ask the OS for less.

A pentest box runs Metasploit, the CLI and, sometimes, the tool that is cracking
hashes at 100 % of every core. The run has to know the machine it is on for
two very different decisions:

* **How many tools may run at once?** Three parallel `nmap` sweeps on a
  2-core laptop is not parallelism, it is a lock-up. :func:`parallel_tools`
  derives the ceiling from the detected hardware.
* **How does a child yield the CPU?** Every sandboxed command is started under
  ``nice`` (and CPU-saturating tools under ``cpulimit``), so the CLI and its TUI
  keep the scheduler's favour while a cracking job runs. :func:`priority_prefix`
  builds that prologue; ``nexus_core.kernel.sandbox`` applies it.

Detection prefers ``psutil`` (physical vs logical cores, real available RAM) and
falls back to ``/proc`` so a host without the wheel still gets a sane budget
instead of a traceback. Everything is read once per process (``lru_cache``) and
the operator can override every number with an environment variable -a machine
list that says "8 cores" but is a shared VM must not be trusted over the person
sitting in front of it.
"""

from __future__ import annotations

import functools
import os
import platform
import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
GIB = 1024 * MIB

#: Hard ceiling of concurrent calls in one ReAct turn, whatever the hardware.
MAX_PARALLEL_TOOLS = 3
#: Operator override of the concurrency ceiling (``1`` = fully sequential).
PARALLEL_LIMIT_ENV = "NEXUS_PARALLEL_TOOL_LIMIT"

#: ``nice`` increment applied to every sandboxed child (Linux only).
NICE_ENV = "NEXUS_TOOL_NICE"
DEFAULT_NICE = 10
#: CPU ceiling, in percent of one core, for tools that saturate the machine.
CPU_LIMIT_ENV = "NEXUS_TOOL_CPU_LIMIT"
DEFAULT_CPU_PERCENT = 80
#: Extra programs to treat as CPU-saturating (comma separated, additive).
CPU_HEAVY_ENV = "NEXUS_CPU_HEAVY_PROGRAMS"

#: Tools measured to pin every core while they run. ``john`` is included because
#: :mod:`nexus_core.tools.handlers.crack_hash` runs it, and ``hashcat`` /
#: ``aircrack-ng`` because they are the ones the operator reaches for next.
CPU_HEAVY_PROGRAMS: frozenset[str] = frozenset(
    {"hashcat", "john", "aircrack-ng", "aircrack", "reaver", "wifite"}
)

#: Below this much RAM a second concurrent tool is not a speed-up, it is swap.
MIN_RAM_FOR_PARALLEL = 4 * GIB


@dataclass(frozen=True)
class HardwareProfile:
    """What the machine actually offers, as detected once at startup."""

    cpu_logical: int
    cpu_physical: int
    ram_total_bytes: int
    ram_available_bytes: int
    #: ``"psutil"`` when the wheel is installed, ``"proc"`` for the stdlib
    #: fallback, ``"unknown"`` when nothing could be read.
    source: str = "unknown"

    @property
    def ram_total_gib(self) -> float:
        return self.ram_total_bytes / GIB if self.ram_total_bytes else 0.0

    @property
    def ram_available_gib(self) -> float:
        return self.ram_available_bytes / GIB if self.ram_available_bytes else 0.0

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready report (used by ``omni --doctor``)."""
        return {
            "cpu": {
                "logical": self.cpu_logical,
                "physical": self.cpu_physical or self.cpu_logical,
                "source": self.source,
            },
            "ram": {
                "total_bytes": self.ram_total_bytes,
                "total_human": human_bytes(self.ram_total_bytes),
                "available_bytes": self.ram_available_bytes,
                "available_human": human_bytes(self.ram_available_bytes),
            },
        }

    def summary(self) -> str:
        """One line for the doctor: ``CPU: 8 cores (4 physical) · RAM: 15.6 GB``."""
        physical = self.cpu_physical or self.cpu_logical
        cores = f"{self.cpu_logical} cores"
        if physical and physical != self.cpu_logical:
            cores += f" ({physical} physical)"
        ram = human_bytes(self.ram_total_bytes) or "RAM desconocida"
        return f"CPU: {cores} · RAM: {ram}"


def human_bytes(value: float) -> str:
    """``16000000000`` -> ``"14.9 GB"``; empty string for an unknown size."""
    if not value or value <= 0:
        return ""
    for unit, scale in (("TB", 1024 * GIB), ("GB", GIB), ("MB", MIB)):
        if value >= scale:
            return f"{value / scale:.1f} {unit}"
    return f"{int(value)} B"


def _from_psutil() -> HardwareProfile | None:
    """Preferred probe: real physical cores and the kernel's free-RAM figure."""
    try:
        import psutil  # optional dependency, imported on demand
    except ImportError:
        return None
    try:
        memory = psutil.virtual_memory()
        logical = int(psutil.cpu_count(logical=True) or os.cpu_count() or 0)
        physical = int(psutil.cpu_count(logical=False) or 0)
        return HardwareProfile(
            cpu_logical=logical,
            cpu_physical=physical or logical,
            ram_total_bytes=int(memory.total),
            ram_available_bytes=int(memory.available),
            source="psutil",
        )
    except Exception:  # noqa: BLE001 - a broken psutil must not break startup
        return None


def _cpuinfo_counts() -> tuple[int, int]:
    """``(logical, physical)`` from ``/proc/cpuinfo``; ``(0, 0)`` when unreadable."""
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0, 0
    logical = 0
    cores: set[tuple[str, str]] = set()
    physical_id = core_id = ""
    for line in text.splitlines():
        if not line.strip():
            # A blank line closes one processor block.
            if physical_id or core_id:
                cores.add((physical_id, core_id))
            physical_id = core_id = ""
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "processor":
            logical += 1
        elif key == "physical id":
            physical_id = value
        elif key == "core id":
            core_id = value
    if physical_id or core_id:
        cores.add((physical_id, core_id))
    return logical, len(cores)


def _ram_from_meminfo() -> tuple[int, int]:
    """``(total, available)`` bytes from ``/proc/meminfo``; ``(0, 0)`` if unknown."""
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0, 0
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if not parts:
            continue
        try:
            values[key.strip()] = int(parts[0]) * 1024  # /proc reports kB
        except ValueError:
            continue
    return values.get("MemTotal", 0), values.get("MemAvailable", 0)


def _from_proc() -> HardwareProfile:
    """Stdlib fallback: ``/proc`` on Linux, ``os.cpu_count`` elsewhere."""
    logical, physical = _cpuinfo_counts()
    total, available = _ram_from_meminfo()
    detected = int(os.cpu_count() or 0)
    logical = logical or detected
    physical = physical or logical
    source = "proc" if (logical or total) else "unknown"
    return HardwareProfile(
        cpu_logical=logical,
        cpu_physical=physical,
        ram_total_bytes=total,
        ram_available_bytes=available,
        source=source,
    )


@functools.lru_cache(maxsize=1)
def detect_hardware() -> HardwareProfile:
    """Detect the machine once per process.

    Cached on purpose: the sandbox asks for the profile around every child, and
    ``psutil``/``/proc`` reads on the event loop are exactly the kind of small
    blocking I/O that makes a TUI stutter. Tests call
    ``detect_hardware.cache_clear()`` after changing the environment.
    """
    return _from_psutil() or _from_proc()


def concurrency_for(profile: HardwareProfile) -> int:
    """The tier table: 1-2 cores -> 1, 3-8 -> 2, more than 8 -> 3.

    Two reasons for the low numbers. A CPU-bound tool (``hashcat``, a ``nmap
    -p-`` with scripts) already fills every core it is given, so three of them on
    a 4-core box only add context switching. And the box is not ours alone: the
    CLI, the TUI and often Metasploit live in the same machine, so the batch
    leaves room for the operator.
    """
    if profile.ram_total_bytes and profile.ram_total_bytes < MIN_RAM_FOR_PARALLEL:
        return 1
    if profile.cpu_logical <= 2:
        return 1
    if profile.cpu_logical <= 8:
        return 2
    return MAX_PARALLEL_TOOLS


def parallel_tools(profile: HardwareProfile | None = None) -> int:
    """Concurrent tools allowed in one turn, hardware-derived, env-overridable.

    ``NEXUS_PARALLEL_TOOL_LIMIT`` wins over the detection (clamped to
    ``1..MAX_PARALLEL_TOOLS``), because a shared VM's ``/proc`` is not the last
    word on what the operator wants to run.
    """
    limit = concurrency_for(profile or detect_hardware())
    raw = os.getenv(PARALLEL_LIMIT_ENV, "").strip()
    if raw:
        try:
            limit = int(raw)
        except ValueError:
            pass  # an unparsable override keeps the detected value
    return max(1, min(int(limit), MAX_PARALLEL_TOOLS))


def nice_level() -> int:
    """``nice`` increment for sandboxed children (0 disables, max 19)."""
    raw = os.getenv(NICE_ENV, "").strip()
    if not raw:
        return DEFAULT_NICE
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_NICE
    return max(0, min(value, 19))


def cpu_cap_percent() -> int:
    """CPU ceiling applied with ``cpulimit`` (0 disables, 100 = no ceiling)."""
    raw = os.getenv(CPU_LIMIT_ENV, "").strip()
    if not raw:
        return DEFAULT_CPU_PERCENT
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_CPU_PERCENT
    return max(0, min(value, 100))


def cpu_heavy_programs() -> frozenset[str]:
    """The built-in list plus ``NEXUS_CPU_HEAVY_PROGRAMS`` (comma separated)."""
    extra = {
        item.strip().lower()
        for item in os.getenv(CPU_HEAVY_ENV, "").split(",")
        if item.strip()
    }
    return CPU_HEAVY_PROGRAMS | extra if extra else CPU_HEAVY_PROGRAMS


def _resolve(name: str, search_path: str | None, which: Callable[..., str | None]) -> str | None:
    try:
        return which(name, path=search_path)
    except TypeError:  # a test double without the ``path`` keyword
        return which(name)


#: Interpreters that only exist to run somebody else's command.
_SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh"})


def heavy_target(argv: Sequence[str]) -> str:
    """The binary the prologue must classify: ``argv[0]``, or a shell's command.

    ``nexus.shell.exec`` runs ``bash -lc "<command>"`` inside the sandbox, so the
    tool that actually burns the CPU is the first word of the script. Without
    this, a ``hashcat`` launched through the shell would only be niced and never
    capped, which is exactly the run that freezes the TUI.
    """
    if not argv:
        return ""
    program = Path(str(argv[0])).name.lower()
    if program not in _SHELLS:
        return str(argv[0])
    for index, token in enumerate(str(item) for item in argv[1:]):
        if token.startswith("-") and "c" in token and len(token) <= 4:
            script = str(argv[index + 2]) if index + 2 < len(argv) else ""
            words = script.strip().split(maxsplit=1)
            return words[0] if words else program
    return program


def priority_prefix(
    program: str,
    *,
    search_path: str | None = None,
    which: Callable[..., str | None] = shutil.which,
    system: str | None = None,
) -> list[str]:
    """The ``nice``/``cpulimit`` prologue for ``program`` (empty when inapplicable).

    * Linux only: ``nice`` is what protects the TUI's scheduling share and the
      other platforms have no equivalent in this codebase.
    * ``nice`` is skipped when the binary is absent, so a minimal container
      still runs its tools instead of failing to start them.
    * ``cpulimit`` is added **only** for a CPU-saturating program, and only when
      installed: it is an optional package on most distros (``apt install
      cpulimit``) and the doctor reports its absence.
    """
    platform_name = (system or platform.system()).lower()
    if platform_name != "linux":
        return []
    prefix: list[str] = []
    level = nice_level()
    if level > 0:
        nice = _resolve("nice", search_path, which)
        if nice:
            prefix += [nice, "-n", str(level)]
    name = Path(str(program)).name.lower()
    cap = cpu_cap_percent()
    if name in cpu_heavy_programs() and cap > 0:
        limiter = _resolve("cpulimit", search_path, which)
        if limiter:
            prefix += [limiter, "-l", str(cap), "--"]
    return prefix


def tool_priority_available(
    *, search_path: str | None = None, which: Callable[..., str | None] = shutil.which
) -> dict[str, Any]:
    """What the doctor reports: which knobs exist on this host right now."""
    return {
        "os": platform.system().lower(),
        "nice_level": nice_level(),
        "nice_binary": _resolve("nice", search_path, which) if nice_level() > 0 else None,
        "cpu_percent": cpu_cap_percent(),
        "cpulimit_binary": (
            _resolve("cpulimit", search_path, which) if cpu_cap_percent() > 0 else None
        ),
        "cpu_heavy_programs": sorted(cpu_heavy_programs()),
    }


__all__ = [
    "CPU_HEAVY_ENV",
    "CPU_HEAVY_PROGRAMS",
    "CPU_LIMIT_ENV",
    "DEFAULT_CPU_PERCENT",
    "DEFAULT_NICE",
    "GIB",
    "MAX_PARALLEL_TOOLS",
    "MIN_RAM_FOR_PARALLEL",
    "NICE_ENV",
    "PARALLEL_LIMIT_ENV",
    "HardwareProfile",
    "concurrency_for",
    "cpu_cap_percent",
    "cpu_heavy_programs",
    "detect_hardware",
    "heavy_target",
    "human_bytes",
    "nice_level",
    "parallel_tools",
    "priority_prefix",
    "tool_priority_available",
]
