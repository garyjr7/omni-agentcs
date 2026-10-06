"""``nexus_core.report.cve_enrichment``: cache-backed CVE enrichment.

The update path is exercised with an injected ``http_get`` so no test touches the
network; the enrichment path is cache-only by construction.
"""

from __future__ import annotations

from dataclasses import replace

from nexus_core.report import cve_enrichment as cve
from nexus_core.report.models import Finding
from nexus_core.tests import report_support as support

NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "es", "value": "no inglesa"},
                    {"lang": "en", "value": "Apache 2.4.49 path traversal"},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                        }}
                    ],
                    "cvssMetricV40": [
                        {"cvssData": {
                            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                            "baseScore": 9.3,
                        }}
                    ],
                },
                "weaknesses": [{"description": [{"value": "CWE-22"}]}],
                "references": [{"url": "https://example.com/a"}],
            }
        }
    ]
}
EPSS_PAYLOAD = {"data": [{"cve": "CVE-2021-41773", "epss": "0.974"}]}
KEV_PAYLOAD = {"vulnerabilities": [{"cveID": "CVE-2021-41773"}]}


def _fake_http(url: str):
    if "cveId=" in url:
        return NVD_PAYLOAD
    if "epss" in url:
        return EPSS_PAYLOAD
    if "known_exploited" in url:
        return KEV_PAYLOAD
    raise AssertionError(f"unexpected url {url}")


def _finding(**overrides) -> Finding:
    base = Finding(
        finding_id="f", title="Apache path traversal", description="d", severity="high",
        cvss_score=None, cvss_vector=None, cwe=None, cve="CVE-2021-41773",
        mitre_techniques=(), owasp_category=None,
        affected_targets=(support.LAB_TARGET,), evidence=(),
        discovered_by_tool="nexus.web.nuclei", discovered_at=support.iso(),
        reproduction_steps=(),
    )
    return replace(base, **overrides)


def test_normalize_cve():
    assert cve.normalize_cve("cve-2021-41773") == "CVE-2021-41773"
    assert cve.normalize_cve(" CVE-2021-41773 ") == "CVE-2021-41773"
    assert cve.normalize_cve("CVE-21-1") is None
    assert cve.normalize_cve(None) is None
    assert cve.normalize_cve("no-soy-un-cve") is None


def test_parse_nvd_extracts_fields():
    info = cve.parse_nvd(NVD_PAYLOAD, "CVE-2021-41773")
    assert info.description == "Apache 2.4.49 path traversal"
    assert info.cwe == ("CWE-22",)
    assert info.cvss31_score == 9.8
    assert info.cvss4_vector.startswith("CVSS:4.0/")
    assert info.references == ("https://example.com/a",)


def test_parse_nvd_malformed():
    assert cve.parse_nvd(None, "CVE-2021-41773") is None
    assert cve.parse_nvd({}, "CVE-2021-41773") is None
    assert cve.parse_nvd({"vulnerabilities": []}, "CVE-2021-41773") is None


def test_parse_epss_and_kev():
    assert cve.parse_epss(EPSS_PAYLOAD, "CVE-2021-41773") == 0.974
    assert cve.parse_epss(EPSS_PAYLOAD, "CVE-2000-0001") is None
    assert cve.parse_epss({"data": [{"cve": "CVE-2021-41773", "epss": "nope"}]}, "CVE-2021-41773") is None
    assert cve.kev_cves(KEV_PAYLOAD) == {"CVE-2021-41773"}
    assert cve.kev_cves(None) == set()


def test_update_then_lookup_round_trip(tmp_path):
    summary = cve.update_cves(["cve-2021-41773"], root=tmp_path, http_get=_fake_http)
    assert summary["nvd_updated"] == 1
    assert summary["epss_updated"] == 1
    assert summary["kev_updated"] is True
    assert summary["errors"] == []

    info = cve.load_cve("CVE-2021-41773", tmp_path)
    assert info.description == "Apache 2.4.49 path traversal"
    assert info.epss == 0.974
    assert info.kev is True


def test_update_records_errors_without_raising(tmp_path):
    def broken(_url):
        raise RuntimeError("no network")

    summary = cve.update_cves(["CVE-2021-41773"], root=tmp_path, http_get=broken)
    assert summary["nvd_updated"] == 0
    assert summary["kev_updated"] is False
    assert any(item.startswith("nvd:") for item in summary["errors"])
    assert any(item.startswith("epss:") for item in summary["errors"])
    assert any(item.startswith("kev:") for item in summary["errors"])


def test_update_ignores_invalid_ids(tmp_path):
    summary = cve.update_cves(["nope", ""], root=tmp_path, http_get=_fake_http)
    assert summary["requested"] == 0


def test_load_cve_uncached_is_empty(tmp_path):
    info = cve.load_cve("CVE-2000-0001", tmp_path)
    assert info.description == ""
    assert info.kev is False
    assert info.epss is None


def test_enrich_without_cache_keeps_finding_intact(tmp_path):
    finding = _finding()
    result = cve.enrich_findings([finding], root=tmp_path)
    assert result == (finding,)
    assert result[0].epss_score is None
    assert result[0].kev is False


def test_enrich_fills_from_cache(tmp_path):
    cve.update_cves(["CVE-2021-41773"], root=tmp_path, http_get=_fake_http)
    (finding,) = cve.enrich_findings([_finding()], root=tmp_path)
    assert finding.cve_description == "Apache 2.4.49 path traversal"
    assert finding.cwe == "CWE-22"
    assert finding.epss_score == 0.974
    assert finding.kev is True
    # The CVSS 4.0 vector came from NVD, but only as a vector (score recomputed).
    assert finding.cvss4_vector.startswith("CVSS:4.0/")
    assert finding.cvss4_source == "nvd"


def test_enrich_never_overwrites_a_local_vector(tmp_path):
    cve.update_cves(["CVE-2021-41773"], root=tmp_path, http_get=_fake_http)
    local = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    finding = _finding(cvss4_vector=local, cvss4_source="tool")
    (enriched,) = cve.enrich_findings([finding], root=tmp_path)
    assert enriched.cvss4_vector == local
    assert enriched.cvss4_source == "tool"


def test_enrich_ignores_findings_without_cve(tmp_path):
    finding = _finding(cve=None)
    assert cve.enrich_findings([finding], root=tmp_path) == (finding,)


def test_collect_cves_dedupes():
    findings = [_finding(), _finding(finding_id="g"), _finding(cve=None)]
    assert cve.collect_cves(findings) == ["CVE-2021-41773"]


def test_cache_root_honours_paths():
    class _Paths:
        cache_dir = "/tmp/omni-cache"

    from pathlib import Path

    assert cve.cache_root(_Paths()) == Path("/tmp/omni-cache/cve")


def test_cve_info_serializes():
    info = cve.parse_nvd(NVD_PAYLOAD, "CVE-2021-41773")
    payload = info.to_dict()
    assert payload["cve"] == "CVE-2021-41773"
    assert payload["cwe"] == ["CWE-22"]


def test_parse_nvd_defensive_shapes():
    # First vulnerabilities entry is not an object.
    assert cve.parse_nvd({"vulnerabilities": [1]}, "CVE-2021-41773") is None
    # A weakness entry and a reference that are not objects are skipped.
    info = cve.parse_nvd(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "descriptions": ["not-a-dict"],
                        "weaknesses": ["not-a-dict", {"description": ["not-a-dict"]}],
                        "metrics": "not-a-dict",
                        "references": ["not-a-dict"],
                    }
                }
            ]
        },
        "CVE-2021-41773",
    )
    assert info.description == ""
    assert info.cwe == ()
    assert info.cvss31_vector is None and info.cvss4_vector is None
    assert info.references == ()
    # A metric group that is not a list yields nothing.
    info2 = cve.parse_nvd(
        {"vulnerabilities": [{"cve": {"metrics": {"cvssMetricV31": "nope"}}}]},
        "CVE-2021-41773",
    )
    assert info2 is not None and info2.cvss31_vector is None


def test_parse_epss_normalized_shape():
    assert cve.parse_epss({"cve": "CVE-2021-41773", "epss": "0.5"}, "CVE-2021-41773") == 0.5
    assert cve.parse_epss({"cve": "CVE-2000-0001", "epss": 0.5}, "CVE-2021-41773") is None
    assert cve.parse_epss({"cve": "CVE-2021-41773", "epss": "bad"}, "CVE-2021-41773") is None
    assert cve.parse_epss({"data": [1, {"cve": "CVE-2021-41773", "epss": 0.2}]}, "CVE-2021-41773") == 0.2


def test_kev_skips_non_objects():
    assert cve.kev_cves({"vulnerabilities": [1, {"cveID": "CVE-2021-41773"}]}) == {"CVE-2021-41773"}


def test_update_reports_empty_nvd(tmp_path):
    def empty_nvd(url):
        if "cveId=" in url:
            return {}
        return {}

    summary = cve.update_cves(["CVE-2021-41773"], root=tmp_path, http_get=empty_nvd)
    assert any(item.endswith(":empty") for item in summary["errors"])


def test_update_tolerates_unwritable_cache(tmp_path):
    root_file = tmp_path / "not-a-dir"
    root_file.write_text("x", encoding="utf-8")
    # Writing under a path whose parent is a file must degrade, not raise.
    summary = cve.update_cves(["CVE-2021-41773"], root=root_file, http_get=_fake_http)
    assert summary["nvd_updated"] == 0
    assert summary["kev_updated"] is False


def test_load_cve_ignores_corrupt_cache(tmp_path):
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir(parents=True)
    (nvd_dir / "CVE-2021-41773.json").write_text("{not json", encoding="utf-8")
    info = cve.load_cve("CVE-2021-41773", tmp_path)
    assert info.description == ""


def test_enrich_handles_lookup_none_and_exception(tmp_path, monkeypatch):
    finding = _finding()
    monkeypatch.setattr(cve, "load_cve", lambda cve_value, root=None: None)
    assert cve.enrich_findings([finding], root=tmp_path) == (finding,)

    def exploding(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(cve, "load_cve", exploding)
    assert cve.enrich_findings([finding], root=tmp_path) == (finding,)


def test_default_http_get_uses_httpx(monkeypatch):
    import httpx

    captured: dict = {}

    class _Response:
        def raise_for_status(self) -> None:
            return None

        def json(self):
            return {"ok": True}

    def fake_get(url, headers=None, timeout=None, follow_redirects=None):
        captured.update(url=url, headers=headers, timeout=timeout)
        return _Response()

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setenv(cve.NVD_API_KEY_ENV, "secret-key")
    assert cve.default_http_get(cve.NVD_API) == {"ok": True}
    assert captured["headers"]["apiKey"] == "secret-key"
    monkeypatch.delenv(cve.NVD_API_KEY_ENV, raising=False)
    assert cve.default_http_get("https://example.com") == {"ok": True}
    assert "apiKey" not in captured["headers"]
