"""Fase 3: the asset & exploration graph.

Pinned here:

* a fact and its edges are committed together, and an anchor that names a fact
  the board does not have is dropped (no dangling edges);
* the graph links a discovered port, the credential it yielded and the
  privilege gained through that credential into one chain;
* coverage attributes facts by edge instead of by text when the fact is
  anchored, and the prompt view names services per host and credential origins;
* the six verifiers pass their origin anchor.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from nexus_core.agent.coverage import (
    STATUS_OWNED,
    build_coverage,
    render_asset_graph,
)
from nexus_core.kernel.blackboard import Blackboard, fact_uri
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.fact_verification import derive_assertions

pytestmark = pytest.mark.unit

TENANT = "system"
ENGAGEMENT = "eng-graph"
HOST = "10.0.0.5"
SERVICE_KEY = f"{HOST}:22:tcp"
CRED_KEY = f"cred:ssh:lin@{HOST}"


def _store(tmp_path) -> ControlStore:
    store = ControlStore(tmp_path / "nexus.db")
    store.initialize()
    return store


def _board(tmp_path) -> Blackboard:
    return Blackboard(_store(tmp_path))


def _record(board, fact_type, key, value=None, *, anchors=None, relation="derived_from"):
    return board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type=fact_type,
        key=key,
        value=value or {},
        source="test",
        created_by="verifier-test",
        verified=True,
        asserted_by="verifier",
        verification_method="unit",
        invocation_id=f"inv-{fact_type}-{key}",
        anchors=anchors,
        relation=relation,
    )


def test_an_anchor_to_a_fact_that_does_not_exist_creates_no_edge(tmp_path):
    board = _board(tmp_path)
    _record(board, "host", HOST)
    missing = fact_uri(ENGAGEMENT, "host", "10.0.0.99")
    _record(
        board,
        "service",
        SERVICE_KEY,
        {"port": 22, "protocol": "tcp", "service": "ssh"},
        anchors=[
            (fact_uri(ENGAGEMENT, "host", HOST), "host_has_service"),
            (missing, "host_has_service"),
        ],
    )
    _record(
        board,
        "credential",
        CRED_KEY,
        {"username": "lin", "service": "ssh"},
        anchors=[(fact_uri(ENGAGEMENT, "host", "10.0.0.98"), "host_yields_credential")],
    )

    edges = board.list_edges(TENANT, ENGAGEMENT)
    (edge,) = edges
    assert edge["src_uri"] == fact_uri(ENGAGEMENT, "host", HOST)
    assert edge["dst_uri"] == fact_uri(ENGAGEMENT, "service", SERVICE_KEY)

    # No edge points at a document the tenant does not have.
    with board.store.connect() as conn:
        known = {
            str(row["source_uri"])
            for row in conn.execute(
                "SELECT DISTINCT source_uri FROM kernel_knowledge_documents "
                "WHERE tenant_id=?",
                (TENANT,),
            ).fetchall()
        }
    assert missing not in known
    for row in edges:
        assert row["src_uri"] in known
        assert row["dst_uri"] in known


def test_the_attack_chain_is_connected_in_the_graph(tmp_path):
    board = _board(tmp_path)
    host_uri = fact_uri(ENGAGEMENT, "host", HOST)
    service_uri = fact_uri(ENGAGEMENT, "service", SERVICE_KEY)
    cred_uri = fact_uri(ENGAGEMENT, "credential", CRED_KEY)
    privilege_uri = fact_uri(ENGAGEMENT, "privilege", HOST)

    _record(board, "host", HOST, {"state": "up"})
    _record(
        board,
        "service",
        SERVICE_KEY,
        {"port": 22, "protocol": "tcp", "service": "ssh"},
        anchors=[(host_uri, "host_has_service")],
    )
    _record(
        board,
        "credential",
        CRED_KEY,
        {"username": "lin", "service": "ssh"},
        anchors=[(service_uri, "service_yields_credential")],
    )
    _record(
        board,
        "privilege",
        HOST,
        {"uid": 0, "user": "root"},
        anchors=[(cred_uri, "credential_grants_privilege")],
    )

    edges = board.list_edges(TENANT, ENGAGEMENT)
    pairs = {(row["src_uri"], row["dst_uri"], row["relation"]) for row in edges}
    assert (host_uri, service_uri, "host_has_service") in pairs
    assert (service_uri, cred_uri, "service_yields_credential") in pairs
    assert (cred_uri, privilege_uri, "credential_grants_privilege") in pairs

    # Walk the chain: port -> credential -> privilege.
    outgoing: dict[str, set[str]] = {}
    for src, dst, _relation in pairs:
        outgoing.setdefault(src, set()).add(dst)
    assert privilege_uri in outgoing.get(cred_uri, set())
    assert cred_uri in outgoing.get(service_uri, set())
    assert service_uri in outgoing.get(host_uri, set())

    facts = board.list_facts(TENANT, ENGAGEMENT)
    coverage = build_coverage(facts, edges=edges, engagement_id=ENGAGEMENT)
    entry = coverage.find(f"{HOST}:22")
    assert entry is not None
    assert entry.status == STATUS_OWNED, "la credencial cuelga del servicio por arista"

    view = render_asset_graph(facts, edges)
    assert f"host {HOST}" in view and "22/tcp (ssh)" in view
    assert f"credencial {CRED_KEY} ← {SERVICE_KEY}" in view


def test_coverage_prefers_the_edge_over_the_text(tmp_path):
    """A fact anchored to :22 is not attributed to :80 by a port in its text."""
    board = _board(tmp_path)
    host_uri = fact_uri(ENGAGEMENT, "host", HOST)
    _record(board, "host", HOST)
    _record(
        board,
        "service",
        f"{HOST}:22:tcp",
        {"port": 22, "protocol": "tcp", "service": "ssh"},
        anchors=[(host_uri, "host_has_service")],
    )
    _record(
        board,
        "service",
        f"{HOST}:80:tcp",
        {"port": 80, "protocol": "tcp", "service": "http"},
        anchors=[(host_uri, "host_has_service")],
    )
    # The value mentions 80, but the edge says it came from the SSH service.
    _record(
        board,
        "credential",
        CRED_KEY,
        {"username": "lin", "service": "ssh", "note": "pista en 80"},
        anchors=[(fact_uri(ENGAGEMENT, "service", f"{HOST}:22:tcp"),
                  "service_yields_credential")],
    )

    facts = board.list_facts(TENANT, ENGAGEMENT)
    edges = board.list_edges(TENANT, ENGAGEMENT)
    coverage = build_coverage(facts, edges=edges, engagement_id=ENGAGEMENT)

    ssh = coverage.find(f"{HOST}:22")
    http = coverage.find(f"{HOST}:80")
    assert ssh is not None and http is not None
    assert ssh.status == STATUS_OWNED
    assert http.status != STATUS_OWNED


def test_re_recording_a_fact_replaces_its_previous_provenance(tmp_path):
    """A credential found from another service keeps only the current origin."""
    board = _board(tmp_path)
    first_host, second_host = "10.0.0.5", "10.0.0.6"
    _record(board, "host", first_host)
    _record(board, "host", second_host)
    service_a = f"{first_host}:22:tcp"
    service_b = f"{second_host}:80:tcp"
    _record(board, "service", service_a, {"port": 22, "service": "ssh"},
            anchors=[(fact_uri(ENGAGEMENT, "host", first_host), "host_has_service")])
    _record(board, "service", service_b, {"port": 80, "service": "http"},
            anchors=[(fact_uri(ENGAGEMENT, "host", second_host), "host_has_service")])
    _record(board, "credential", CRED_KEY, {"username": "lin"},
            anchors=[(fact_uri(ENGAGEMENT, "service", service_a),
                      "service_yields_credential")])
    # The same key proved again from the web service: the old origin is no
    # longer true, so it must not linger in the graph (V0-33).
    _record(board, "credential", CRED_KEY, {"username": "lin"},
            anchors=[(fact_uri(ENGAGEMENT, "service", service_b),
                      "service_yields_credential")])

    dest = fact_uri(ENGAGEMENT, "credential", CRED_KEY)
    edges = [row for row in board.list_edges(TENANT, ENGAGEMENT)
             if row["dst_uri"] == dest]
    assert [row["src_uri"] for row in edges] == [fact_uri(ENGAGEMENT, "service", service_b)]

    # An agent re-registration without anchors never erases the verifier's.
    board.record(
        tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="credential",
        key=CRED_KEY, value={"username": "lin"}, source="agent",
        created_by="agent-test",
    )
    edges = [row for row in board.list_edges(TENANT, ENGAGEMENT)
             if row["dst_uri"] == dest]
    assert [row["src_uri"] for row in edges] == [fact_uri(ENGAGEMENT, "service", service_b)]


def test_edges_are_read_by_fact_not_by_the_first_two_thousand(tmp_path):
    """A large scan cannot push the provenance of a live fact out of the read."""
    board = _board(tmp_path)
    _record(board, "host", HOST)
    service_uri = fact_uri(ENGAGEMENT, "service", SERVICE_KEY)
    _record(board, "service", SERVICE_KEY, {"port": 22, "service": "ssh"},
            anchors=[(fact_uri(ENGAGEMENT, "host", HOST), "host_has_service")])
    last_uri = ""
    for index in range(2050):
        key = f"{HOST}:{10_000 + index}:tcp"
        last_uri = fact_uri(ENGAGEMENT, "endpoint", key)
        _record(board, "endpoint", key, {"path": f"/p{index}"},
                anchors=[(service_uri, "service_exposes_endpoint")])

    # The global oldest-2000 window no longer contains the newest edge.
    assert last_uri not in {
        row["dst_uri"] for row in board.list_edges(TENANT, ENGAGEMENT, limit=2000)
    }
    rows = board.list_edges_for_facts(TENANT, ENGAGEMENT, [last_uri])
    assert len(rows) == 1
    assert rows[0]["dst_uri"] == last_uri
    assert rows[0]["src_uri"] == service_uri


# ------------------------------------------------------------------ verifiers
def _context(engagement_id: str = ENGAGEMENT, store=None) -> SimpleNamespace:
    return SimpleNamespace(
        engagement_id=engagement_id,
        invocation_id="inv-verifier",
        run_id="run-verifier",
        tenant_id=TENANT,
        store=store,
        scope=SimpleNamespace(engagement_id=engagement_id),
    )


class _Result:
    success = True
    outcome = "success"
    verification_method = ""
    exit_code = 0
    output: dict = {}
    evidence: dict = {}

    def __init__(self, method: str, output: dict, evidence: dict | None = None) -> None:
        self.verification_method = method
        self.output = output
        self.evidence = evidence or {}


def test_nmap_anchors_each_service_to_its_host():
    result = _Result(
        "nmap_xml_parsed",
        {
            "scan": {
                "hosts": [
                    {
                        "ip": HOST,
                        "state": "up",
                        "ports": [
                            {"port": 22, "protocol": "tcp", "state": "open"},
                            {"port": 80, "protocol": "tcp", "state": "open"},
                        ],
                    }
                ]
            }
        },
    )
    rows = derive_assertions("nexus.recon.nmap", {}, result, _context())

    host_uri = fact_uri(ENGAGEMENT, "host", HOST)
    services = [row for row in rows if row["fact_type"] == "service"]
    assert len(services) == 2
    assert all([host_uri, "host_has_service"] in row["anchors"] for row in services)


def test_cred_bruteforce_anchors_the_credential_to_the_service():
    result = _Result(
        "cred_bruteforce_completed",
        {
            "target": HOST,
            "service": "ssh",
            "port": 22,
            "valid_credentials": [{"username": "lin", "password": "secret"}],
        },
    )
    rows = derive_assertions("nexus.cred.bruteforce", {}, result, _context())

    (credential,) = [row for row in rows if row["fact_type"] == "credential"]
    service_uri = fact_uri(ENGAGEMENT, "service", SERVICE_KEY)
    assert [service_uri, "service_yields_credential"] in credential["anchors"]


def test_httpx_normalizes_a_hostname_to_the_proved_host(tmp_path):
    """nmap recorded the IP; httpx probes localhost: the edge still lands."""
    store = _store(tmp_path)
    board = Blackboard(store)
    _record(board, "host", "127.0.0.1", {"state": "up"})
    _record(
        board, "service", "127.0.0.1:80:tcp", {"port": 80, "service": "http"},
        anchors=[(fact_uri(ENGAGEMENT, "host", "127.0.0.1"), "host_has_service")],
    )
    result = _Result(
        "httpx_jsonl_parsed",
        {"probes": [{"url": "http://localhost/", "status_code": 200,
                     "host": "localhost"}]},
    )
    rows = derive_assertions(
        "nexus.recon.httpx", {"targets": ["localhost"]}, result,
        _context(store=store),
    )
    endpoint = next(row for row in rows if row["fact_type"] == "endpoint")
    service_uri = fact_uri(ENGAGEMENT, "service", "127.0.0.1:80:tcp")
    assert [service_uri, "service_exposes_web"] in endpoint["anchors"]
    assert [fact_uri(ENGAGEMENT, "host", "127.0.0.1"),
            "host_exposes_web"] in endpoint["anchors"]


def test_gobuster_normalizes_a_hostname_to_the_proved_host(tmp_path):
    store = _store(tmp_path)
    board = Blackboard(store)
    _record(board, "host", "127.0.0.1", {"state": "up"})
    _record(
        board, "service", "127.0.0.1:8080:tcp", {"port": 8080, "service": "http"},
        anchors=[(fact_uri(ENGAGEMENT, "host", "127.0.0.1"), "host_has_service")],
    )
    result = _Result(
        "gobuster_text_parsed",
        {"target": "http://localhost:8080",
         "hits": [{"url": "http://localhost:8080/admin", "path": "/admin",
                   "status": 200}]},
    )
    rows = derive_assertions(
        "nexus.recon.gobuster", {"url": "http://localhost:8080"}, result,
        _context(store=store),
    )
    endpoint = next(row for row in rows if row["fact_type"] == "endpoint")
    service_uri = fact_uri(ENGAGEMENT, "service", "127.0.0.1:8080:tcp")
    assert [service_uri, "service_exposes_endpoint"] in endpoint["anchors"]


def test_msf_exploit_anchors_the_session_to_host_and_service():
    result = _Result(
        "session_established",
        {
            "target": HOST,
            "port": 445,
            "session_uuid": "abc123",
            "session": {"session_host": HOST, "session_port": 445,
                        "via_exploit": "ms17_010_psexec", "type": "meterpreter",
                        "username": "SYSTEM"},
        },
    )
    rows = derive_assertions("nexus.exploit.msf_exploit", {}, result, _context())
    session = next(row for row in rows if row["fact_type"] == "session")
    anchors = {tuple(anchor) for anchor in session["anchors"]}
    assert (fact_uri(ENGAGEMENT, "service", f"{HOST}:445:tcp"),
            "service_yields_session") in anchors
    assert (fact_uri(ENGAGEMENT, "host", HOST), "host_yields_session") in anchors


def test_ssh_exec_anchors_privilege_to_the_credential_it_used():
    result = _Result(
        "ssh_exec_completed",
        {
            "target": HOST,
            "command": "id",
            "stdout": "uid=0(root) gid=0(root) groups=0(root)",
            "exit_status": 0,
        },
    )
    rows = derive_assertions(
        "nexus.post.ssh_exec",
        {"username": "lin", "password": "secret", "port": 22},
        result,
        _context(),
    )

    (privilege,) = [row for row in rows if row["fact_type"] == "privilege"]
    cred_uri = fact_uri(ENGAGEMENT, "credential", CRED_KEY)
    assert [cred_uri, "credential_grants_privilege"] in privilege["anchors"]
