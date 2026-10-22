"""Decide, cheaply, whether this process can reach a host at all.

The pre-scan gate (:func:`nexus_core.agent.planner.pivot_gate`) has to answer one
question before a sweep is allowed to spend its budget: does the operator have a
route to that host? The history cannot answer it -the run may simply never have
scanned that host-, and guessing from the subnet is wrong (DeadDrop's DMZ
``192.168.11.200`` and its DC ``192.168.11.100`` share the /24 and only the first
is routable). The measurement is a TCP connect: if *any* of the target's ports
answers, there is a route and the call proceeds untouched.

The probe is deliberately boring and bounded:

* a few ports, in parallel, with a hard ceiling of :data:`PROBE_TIMEOUT_SECONDS`,
  so the gate costs about a second instead of the 600 s an ``nmap`` pays when it
  has no route (measured in DeadDrop P10, 2026-10-22);
* a short cache keyed by ``(host, ports)`` so several turns against the same
  host do not probe again;
* fail-open on any error of the probe itself: this decides whether to *refuse* a
  call, so a broken probe must never be the reason a valid scan is denied.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

#: Hard ceiling of one probe, for all ports together (they run in parallel).
PROBE_TIMEOUT_SECONDS = 1.5

#: Deadline of each port, strictly below the ceiling of the whole probe. Measured
#: on the live DeadDrop room (2026-10-22): the DC ``192.168.11.100`` is a black
#: hole -every port there hangs until the deadline- while the DMZ
#: ``192.168.11.200`` answers 22 in 0.18 s and 80 in 0.40 s and hangs on the rest.
#: With one shared deadline the gather always expired first and the fail-open
#: branch answered "reachable" for the black hole too, which is exactly the case
#: the gate exists for; the per-port deadline lets the answer arrive inside the
#: ceiling, so only a *real* silence reads as unreachable.
PROBE_PORT_TIMEOUT_SECONDS = 0.8

#: How long a verdict stays valid. A pivot that comes up between two attempts is
#: rare; a stale "reachable" only costs the timeout the run already paid before.
PROBE_CACHE_TTL_SECONDS = 60.0

#: ``(host, ports) -> (verdict, monotonic time)``. Module-level because the
#: coordinator and its tests share one process.
_PROBE_CACHE: dict[tuple[str, tuple[int, ...]], tuple[bool, float]] = {}


async def _probe_port(host: str, port: int, timeout: float) -> bool:
    """True when ``host:port`` completes a TCP handshake inside ``timeout``."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, ValueError):
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:  # noqa: BLE001 - closing a probe is never the decision
        pass
    return True


async def host_reachable(
    host: str,
    ports: Sequence[int] | None = None,
    *,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> bool:
    """True when any probe port of ``host`` answers from this process.

    A host that answers none of them inside ``timeout`` is unreachable -that is
    the measurement, and it is what lets the gate refuse a sweep that would spend
    600 s learning the same thing-. A probe that *breaks* (an exception of the
    machinery, not silence) is reported as reachable: the caller refuses a call on
    ``False``, and a broken probe must never deny work the operator asked for.
    ``timeout`` bounds the whole probe, not each port.
    """
    candidates = tuple(dict.fromkeys(int(port) for port in (ports or (22,))))
    if not host or not candidates:
        return True
    key = (host, candidates)
    cached = _PROBE_CACHE.get(key)
    now = time.monotonic()
    if cached is not None and now - cached[1] < PROBE_CACHE_TTL_SECONDS:
        return cached[0]
    per_port = min(PROBE_PORT_TIMEOUT_SECONDS, timeout)
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(_probe_port(host, port, per_port) for port in candidates)),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        # Every port outlived the ceiling: the host did not answer, and that *is*
        # the measurement the caller asked for (the fail-open rule below is for a
        # probe that broke, never for a host that stayed silent).
        return False
    except (OSError, RuntimeError):
        return True
    reachable = any(results)
    if len(_PROBE_CACHE) > 256:
        _PROBE_CACHE.clear()
    _PROBE_CACHE[key] = (reachable, now)
    return reachable


def clear_cache() -> None:
    """Drop every cached verdict (tests and a manual re-check of a host)."""
    _PROBE_CACHE.clear()
