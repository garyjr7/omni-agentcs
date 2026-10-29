"""The hardware budget: detection, the concurrency tiers and the nice/cpulimit policy.

The parallel orchestrator asks these functions two questions on every turn: how
many tools may run at once on *this* machine, and how does a child yield the CPU
so the CLI keeps responding. Both answers have to be deterministic under test
(the CI runner is not the operator's Kali box) and honest on a host where the
probe cannot read anything.
"""

from __future__ import annotations

import sys

import pytest

from nexus_core.kernel import hardware


def _profile(logical: int, *, physical: int = 0, ram_gib: float = 16) -> hardware.HardwareProfile:
    return hardware.HardwareProfile(
        cpu_logical=logical,
        cpu_physical=physical or max(1, logical // 2),
        ram_total_bytes=int(ram_gib * hardware.GIB),
        ram_available_bytes=int(ram_gib * hardware.GIB / 2),
        source="test",
    )


# ------------------------------------------------------------------ the tiers
@pytest.mark.parametrize(
    ("logical", "expected"),
    [(1, 1), (2, 1), (3, 2), (4, 2), (8, 2), (9, 3), (16, 3), (64, 3)],
)
def test_the_concurrency_tier_follows_the_core_count(logical, expected):
    assert hardware.concurrency_for(_profile(logical)) == expected


def test_a_machine_with_little_ram_never_runs_two_tools():
    """Below 4 GiB a second concurrent tool is swap, not a speed-up."""
    assert hardware.concurrency_for(_profile(16, ram_gib=2)) == 1


def test_an_unknown_ram_figure_does_not_lower_the_tier():
    """``/proc/meminfo`` unreadable means "no data", not "no memory"."""
    profile = hardware.HardwareProfile(8, 4, 0, 0, "unknown")
    assert hardware.concurrency_for(profile) == 2


def test_the_env_override_wins_and_is_clamped(monkeypatch):
    monkeypatch.setattr(hardware, "detect_hardware", lambda: _profile(2))

    monkeypatch.delenv(hardware.PARALLEL_LIMIT_ENV, raising=False)
    assert hardware.parallel_tools() == 1

    monkeypatch.setenv(hardware.PARALLEL_LIMIT_ENV, "3")
    assert hardware.parallel_tools() == 3, "a 2-core box can still be asked for 3"

    monkeypatch.setenv(hardware.PARALLEL_LIMIT_ENV, "99")
    assert hardware.parallel_tools() == hardware.MAX_PARALLEL_TOOLS

    monkeypatch.setenv(hardware.PARALLEL_LIMIT_ENV, "0")
    assert hardware.parallel_tools() == 1

    monkeypatch.setenv(hardware.PARALLEL_LIMIT_ENV, "muchos")
    assert hardware.parallel_tools() == 1, "an unparsable override keeps the detected value"


# ------------------------------------------------------------------ the knobs
def test_nice_defaults_to_ten_and_zero_disables_it(monkeypatch):
    monkeypatch.delenv(hardware.NICE_ENV, raising=False)
    assert hardware.nice_level() == 10

    monkeypatch.setenv(hardware.NICE_ENV, "0")
    assert hardware.nice_level() == 0

    monkeypatch.setenv(hardware.NICE_ENV, "5")
    assert hardware.nice_level() == 5

    monkeypatch.setenv(hardware.NICE_ENV, "999")
    assert hardware.nice_level() == 19, "nice has no value above 19"

    monkeypatch.setenv(hardware.NICE_ENV, "-4")
    assert hardware.nice_level() == 0, "raising a child's priority is not on the table"

    monkeypatch.setenv(hardware.NICE_ENV, "nope")
    assert hardware.nice_level() == 10


def test_the_cpu_cap_defaults_to_eighty_and_zero_disables_it(monkeypatch):
    monkeypatch.delenv(hardware.CPU_LIMIT_ENV, raising=False)
    assert hardware.cpu_cap_percent() == 80

    monkeypatch.setenv(hardware.CPU_LIMIT_ENV, "0")
    assert hardware.cpu_cap_percent() == 0

    monkeypatch.setenv(hardware.CPU_LIMIT_ENV, "150")
    assert hardware.cpu_cap_percent() == 100

    monkeypatch.setenv(hardware.CPU_LIMIT_ENV, "nope")
    assert hardware.cpu_cap_percent() == 80


def test_the_heavy_list_is_additive_and_overridable(monkeypatch):
    monkeypatch.delenv(hardware.CPU_HEAVY_ENV, raising=False)
    assert {"hashcat", "john", "aircrack-ng"} <= hardware.cpu_heavy_programs()

    monkeypatch.setenv(hardware.CPU_HEAVY_ENV, " medusa , sqlmap ")
    assert {"medusa", "sqlmap"} <= hardware.cpu_heavy_programs()
    assert "john" in hardware.cpu_heavy_programs(), "the built-ins stay"


# ------------------------------------------------------- the argv prologue
def _which(table: dict[str, str]):
    def resolver(name, path=None):
        return table.get(name)

    return resolver


def test_a_normal_tool_only_gets_nice():
    prefix = hardware.priority_prefix(
        "nmap", which=_which({"nice": "/usr/bin/nice"}), system="Linux"
    )

    assert prefix == ["/usr/bin/nice", "-n", "10"]


def test_a_cpu_heavy_tool_gets_nice_and_a_cpu_ceiling():
    prefix = hardware.priority_prefix(
        "/usr/bin/hashcat",
        which=_which({"nice": "/usr/bin/nice", "cpulimit": "/usr/bin/cpulimit"}),
        system="Linux",
    )

    assert prefix == [
        "/usr/bin/nice", "-n", "10",
        "/usr/bin/cpulimit", "-l", "80", "--",
    ]


def test_the_cpu_ceiling_is_skipped_when_cpulimit_is_not_installed():
    """A missing optional package must not stop the tool from running."""
    prefix = hardware.priority_prefix(
        "john", which=_which({"nice": "/usr/bin/nice"}), system="Linux"
    )

    assert prefix == ["/usr/bin/nice", "-n", "10"]


def test_no_nice_binary_means_no_prefix_at_all():
    prefix = hardware.priority_prefix("nmap", which=_which({}), system="Linux")

    assert prefix == []


def test_nice_zero_and_cap_zero_turn_the_injection_off(monkeypatch):
    monkeypatch.setenv(hardware.NICE_ENV, "0")
    monkeypatch.setenv(hardware.CPU_LIMIT_ENV, "0")
    prefix = hardware.priority_prefix(
        "hashcat",
        which=_which({"nice": "/usr/bin/nice", "cpulimit": "/usr/bin/cpulimit"}),
        system="Linux",
    )

    assert prefix == []


def test_a_shell_command_is_classified_by_what_the_shell_will_run():
    """``bash -lc "hashcat ..."`` must be capped, not just niced."""
    assert hardware.heavy_target(["bash", "-lc", "hashcat -m 1000 h.txt w.txt"]) == "hashcat"
    assert hardware.heavy_target(["sh", "-c", "  nmap -p- 10.0.0.5"]) == "nmap"
    assert hardware.heavy_target(["/usr/bin/hashcat", "-b"]) == "/usr/bin/hashcat"
    assert hardware.heavy_target(["python3", "-c", "print(1)"]) == "python3"
    assert hardware.heavy_target(["bash", "-l"]) == "bash", "no command word means no guess"
    assert hardware.heavy_target([]) == ""


def test_other_platforms_keep_their_own_scheduler_untouched():
    prefix = hardware.priority_prefix(
        "nmap",
        which=_which({"nice": "/usr/bin/nice", "cpulimit": "/usr/bin/cpulimit"}),
        system="Windows",
    )

    assert prefix == []


# --------------------------------------------------------------- detection
def test_detection_prefers_psutil_and_reports_physical_cores(monkeypatch):
    class FakeMemory:
        total = 16 * hardware.GIB
        available = 8 * hardware.GIB

    fake = type(
        "FakePsutil",
        (),
        {
            "virtual_memory": staticmethod(lambda: FakeMemory()),
            "cpu_count": staticmethod(lambda logical=True: 8 if logical else 4),
        },
    )
    monkeypatch.setitem(sys.modules, "psutil", fake)
    hardware.detect_hardware.cache_clear()
    try:
        profile = hardware.detect_hardware()
    finally:
        hardware.detect_hardware.cache_clear()

    assert profile.source == "psutil"
    assert (profile.cpu_logical, profile.cpu_physical) == (8, 4)
    assert profile.ram_total_gib == pytest.approx(16)


def test_without_psutil_detection_falls_back_to_proc(monkeypatch):
    """CI installs the locked requirements; a host without the wheel still runs."""
    monkeypatch.setattr(hardware, "_from_psutil", lambda: None)
    profile = hardware._from_proc()

    assert profile.source in {"proc", "unknown"}
    assert profile.cpu_logical >= 1
    assert profile.cpu_physical >= 1
    assert profile.source != "psutil"


def test_a_broken_psutil_never_breaks_startup(monkeypatch):
    """A psutil that raises is treated as absent, never as a fatal error."""
    class Broken:
        @staticmethod
        def virtual_memory():
            raise RuntimeError("psutil is broken on this kernel")

        @staticmethod
        def cpu_count(logical=True):
            return 4

    monkeypatch.setitem(sys.modules, "psutil", Broken)
    assert hardware._from_psutil() is None

    hardware.detect_hardware.cache_clear()
    try:
        assert hardware.detect_hardware().cpu_logical >= 1
    finally:
        hardware.detect_hardware.cache_clear()


def test_human_sizes_read_like_the_doctor_line():
    assert hardware.human_bytes(16 * hardware.GIB) == "16.0 GB"
    assert hardware.human_bytes(0) == ""
    assert hardware.human_bytes(1536 * hardware.MIB) == "1.5 GB"

    summary = _profile(8, physical=4, ram_gib=16).summary()
    assert summary == "CPU: 8 cores (4 physical) · RAM: 16.0 GB"


def test_the_doctor_report_says_which_knobs_are_really_available(monkeypatch):
    from nexus_core.cli import doctor

    # ``doctor`` imports these helpers by name, so the stubs go there.
    monkeypatch.setattr(doctor, "detect_hardware", lambda: _profile(8, ram_gib=16))
    monkeypatch.setattr(
        doctor,
        "tool_priority_available",
        lambda **kwargs: {
            "os": "linux",
            "nice_level": 10,
            "nice_binary": "/usr/bin/nice",
            "cpu_percent": 80,
            "cpulimit_binary": None,
            "cpu_heavy_programs": ["hashcat", "john"],
        },
    )

    report = doctor._hardware_report()

    assert report["summary"].startswith("CPU: 8 cores")
    assert report["limits"]["parallel_tools"] == 2
    assert report["limits"]["parallel_tools_source"] == "hardware"
    assert report["limits"]["nice_binary"] == "/usr/bin/nice"
    assert report["limits"]["cpulimit_binary"] is None, (
        "the doctor must not claim a CPU ceiling the host cannot enforce"
    )
