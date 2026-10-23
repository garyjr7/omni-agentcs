"""B2: one port can hold several paths, and each one gets its own verdict.

Measured on a web target with four routes into the same ``:80``: the ledger had
one item per service, so a ``barrier`` written after the first dead end closed
the service and the other three routes disappeared from the map. These tests pin
the fix: a barrier that names a path closes that path, the service stays open
while another path has no verdict, and a barrier that names only the service
keeps its historical meaning.
"""

from __future__ import annotations

from nexus_core.agent.coverage import (
    STATUS_CLOSED,
    STATUS_PENDING,
    STATUS_PROBED,
    build_coverage,
    render_coverage,
)

HOST = "10.10.10.5"
WEB = f"{HOST}:80"

PATH_A = "/admin/app_themes.aspx"
PATH_B = "/upload"
PATH_C = "/api/v1"
PATH_D = "/preview/enum.js"


def _service(port: int = 80, name: str = "http") -> dict:
    return {
        "fact_type": "service",
        "key": f"{HOST}:{port}:tcp",
        "value": {"port": port, "protocol": "tcp", "service": name,
                  "product": "", "version": ""},
    }


def _path(path: str, label: str, *, recorded_at: str = "2026-10-23T10:00:00+00:00",
          key: str | None = None) -> dict:
    return {
        "fact_type": "vulnerability",
        "key": key or f"vuln:{path}",
        "value": {"id": label, "url": f"http://{HOST}{path}"},
        "recorded_at": recorded_at,
    }


def _barrier(reason: str, *, recorded_at: str = "2026-10-23T11:00:00+00:00",
             key: str = WEB, conclusive: bool = True) -> dict:
    value = {"reason": reason, "sweep_attempted": conclusive}
    return {
        "fact_type": "barrier",
        "key": key,
        "value": value,
        "recorded_at": recorded_at,
    }


FOUR_PATHS = [
    _path(PATH_A, "CVE-2019-6714"),
    _path(PATH_B, "unrestricted file upload"),
    _path(PATH_C, "broken object level authorization"),
    _path(PATH_D, "server-side JS execution"),
]


def test_four_routes_on_one_port_are_four_paths():
    coverage = build_coverage([_service(), *FOUR_PATHS])
    entry = coverage.find(WEB)
    assert entry.status == STATUS_PROBED
    assert entry.vector_count == 4
    assert entry.vulnerabilities == 4
    assert {item.status for item in entry.vectors} == {STATUS_PENDING}
    labels = " | ".join(item.label for item in entry.vectors)
    assert "CVE-2019-6714" in labels and "unrestricted file upload" in labels


def test_a_barrier_closes_the_path_it_names_not_the_whole_service():
    coverage = build_coverage([
        _service(), *FOUR_PATHS,
        _barrier(f"el tema no aterriza en {PATH_A}: el panel responde 200 sin efecto",
                 key=WEB),
    ])
    entry = coverage.find(WEB)
    assert entry.status == STATUS_PROBED          # still open work
    closed = [item for item in entry.vectors if item.status == STATUS_CLOSED]
    pending = [item for item in entry.vectors if item.status == STATUS_PENDING]
    assert [item.label for item in closed] == [f"CVE-2019-6714 ({PATH_A})"]
    assert len(pending) == 3
    assert "no aterriza" in closed[0].verdict


def test_the_service_closes_once_every_path_has_a_verdict():
    coverage = build_coverage([
        _service(), *FOUR_PATHS,
        _barrier(f"sin efecto en {PATH_A}"),
        _barrier(f"el upload rechaza php en {PATH_B}"),
        _barrier(f"401 en {PATH_C}"),
        _barrier(f"el módulo exporta nada en {PATH_D}"),
    ])
    entry = coverage.find(WEB)
    assert entry.status == STATUS_CLOSED
    assert {item.status for item in entry.vectors} == {STATUS_CLOSED}
    assert entry.verdict


def test_a_barrier_that_names_only_the_service_keeps_its_old_meaning():
    coverage = build_coverage([
        _service(), *FOUR_PATHS,
        _barrier("puerto parcheado: no expone nada"),
    ])
    assert coverage.find(WEB).status == STATUS_CLOSED


def test_a_barrier_older_than_the_path_does_not_close_it():
    coverage = build_coverage([
        _service(),
        _barrier("probado sin suerte", recorded_at="2026-10-23T09:00:00+00:00"),
        _path(PATH_A, "CVE-2019-6714", recorded_at="2026-10-23T10:00:00+00:00"),
    ])
    entry = coverage.find(WEB)
    assert entry.status == STATUS_PROBED
    assert entry.vectors[0].status == STATUS_PENDING


def test_an_inconclusive_barrier_closes_nothing():
    """V12: a barrier without an attempt is a hypothesis, not a verdict."""
    coverage = build_coverage([
        _service(), *FOUR_PATHS,
        _barrier(f"creo que {PATH_A} no funciona", conclusive=False),
    ])
    entry = coverage.find(WEB)
    assert entry.status == STATUS_PROBED
    assert {item.status for item in entry.vectors} == {STATUS_PENDING}


def test_the_ledger_shows_the_paths_and_still_orders_the_service():
    coverage = build_coverage([
        _service(),
        _path(PATH_A, "CVE-2019-6714"),
        _path(PATH_B, "unrestricted file upload"),
        _barrier(f"sin efecto en {PATH_A}"),
    ])
    text = render_coverage(coverage)
    assert f"- {WEB}/tcp http → sondeado" in text
    assert f"↳ CVE-2019-6714 ({PATH_A}) → descartado" in text
    assert f"↳ unrestricted file upload ({PATH_B}) → pendiente" in text
    assert "FRONTERA: 1/1 servicios sin veredicto" in text


def test_a_hidden_path_still_reports_its_verdict():
    """A closed path under the cap must not read as "another pending route"."""
    coverage = build_coverage([
        _service(), *FOUR_PATHS,
        _barrier(f"sin efecto en {PATH_A}"),
    ])
    text = render_coverage(coverage)
    # Three pending paths are rendered; the closed fourth is summarized *with*
    # its verdict, so the model is not invited to retry it.
    assert "… y 1 camino(s) más (1 descartado)" in text


def test_the_ledger_exposes_paths_as_data():
    coverage = build_coverage([_service(), *FOUR_PATHS])
    payload = coverage.find(WEB).to_dict()
    assert payload["vector_count"] == 4
    assert payload["vulnerabilities"] == 4
    assert {item["status"] for item in payload["vectors"]} == {STATUS_PENDING}
    assert payload["vectors"][0]["ref"] and payload["vectors"][0]["label"]


def test_the_pivot_orders_the_next_path_instead_of_abandoning_the_service():
    from nexus_core.agent.coverage import pivot_hint

    coverage = build_coverage([
        _service(), *FOUR_PATHS,
        _barrier(f"sin efecto en {PATH_A}"),
    ])
    entry = coverage.find(WEB)
    hint = pivot_hint(coverage, no_progress=5, focus=entry)
    assert "CAMINOS PENDIENTES" in hint
    assert "/upload" in hint
    # The path that already has a verdict is closed, not offered again.
    assert "/admin/app_themes.aspx" not in hint


def test_a_service_with_every_path_closed_still_reads_as_closed():
    from nexus_core.agent.coverage import pivot_hint

    coverage = build_coverage([
        _service(), *FOUR_PATHS,
        _barrier(f"sin efecto en {PATH_A}"),
        _barrier(f"el upload rechaza php en {PATH_B}"),
        _barrier(f"401 en {PATH_C}"),
        _barrier(f"el módulo exporta nada en {PATH_D}"),
    ])
    entry = coverage.find(WEB)
    hint = pivot_hint(coverage, no_progress=5, focus=entry)
    assert "RAMAL CERRADO" in hint
    assert "CAMINOS PENDIENTES" not in hint


def test_a_fact_keyed_on_the_service_names_no_path():
    """``10.10.10.5:80`` says "this port is vulnerable", not *which route*."""
    coverage = build_coverage([
        _service(),
        _path(PATH_A, "CVE-2019-6714"),
        {
            "fact_type": "vulnerability",
            "key": WEB,
            "value": {"class": "exposed management port"},
            "recorded_at": "2026-10-23T10:00:00+00:00",
        },
    ])
    entry = coverage.find(WEB)
    assert entry.vulnerabilities == 2      # both facts keep the branch open
    assert entry.vector_count == 1         # only one names a route
    assert entry.vectors[0].label.startswith("CVE-2019-6714")
