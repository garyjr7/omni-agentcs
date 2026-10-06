"""Offline-first CVE enrichment (NVD description/CWE/CVSS, EPSS, CISA KEV).

The report must never wait on the network. So enrichment is split in two:

* **lookup (this module's default path)** reads only the local cache under
  ``$XDG_CACHE_HOME/omni/cve`` — :func:`enrich_findings` never opens a socket,
  never blocks and never fails the engagement; a missing cache simply means the
  CVE fields stay empty (``unknown``), which is honest and cheap;
* **update (``omni cve update``)** performs the network calls and fills that
  cache. It is explicit, on demand and idempotent.

Values are copied verbatim from the authoritative source that provided them; the
module never invents a description, a CWE, an EPSS number or a KEV flag. When a
finding already carries a CVSS v4.0 vector, the cached one is ignored. Cached
scores from the sources are stored for reference but the *scores that reach the
report* are always recomputed locally by :mod:`nexus_core.report.cvss4`.
"""

from __future__ import annotations

import json
import re
import os
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

CVE_DIRNAME = "cve"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_API = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
#: Header used for the NVD API (an API key raises the rate limit when set).
NVD_API_KEY_ENV = "NVD_API_KEY"
USER_AGENT = "OmniAgentCS/3.0 (+https://github.com/BAJIOWARE/omni-agentcs)"
DEFAULT_TIMEOUT_SECONDS = 30.0

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_PATTERN = re.compile(r"^CWE-\d+$")


def normalize_cve(value: Any) -> str | None:
    """Return the canonical upper-case ``CVE-...`` id, or ``None``."""
    text = str(value or "").strip().upper()
    return text if _CVE_PATTERN.match(text) else None


@dataclass(frozen=True)
class CVEInfo:
    """Everything the cache knows about one CVE (all fields optional)."""

    cve: str
    description: str = ""
    cwe: tuple[str, ...] = ()
    cvss31_vector: str | None = None
    cvss31_score: float | None = None
    cvss4_vector: str | None = None
    cvss4_score: float | None = None
    epss: float | None = None
    kev: bool = False
    references: tuple[str, ...] = ()
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        value = {
            "cve": self.cve,
            "description": self.description,
            "cwe": list(self.cwe),
            "cvss31_vector": self.cvss31_vector,
            "cvss31_score": self.cvss31_score,
            "cvss4_vector": self.cvss4_vector,
            "cvss4_score": self.cvss4_score,
            "epss": self.epss,
            "kev": self.kev,
            "references": list(self.references),
            "updated_at": self.updated_at,
        }
        return value


# ------------------------------------------------------------------ cache layout
def cache_root(paths: Any = None) -> Path:
    """Return ``$XDG_CACHE_HOME/omni/cve`` (created lazily by writers)."""
    if paths is not None and getattr(paths, "cache_dir", None) is not None:
        return Path(paths.cache_dir) / CVE_DIRNAME
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().cache_dir / CVE_DIRNAME


def _nvd_path(cve: str, root: Path) -> Path:
    return root / "nvd" / f"{cve}.json"


def _epss_path(cve: str, root: Path) -> Path:
    return root / "epss" / f"{cve}.json"


def _kev_path(root: Path) -> Path:
    return root / "kev.json"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write_json(path: Path, payload: Any) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        return True
    except OSError:
        return False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ------------------------------------------------------------------- parsing
def _first_cve(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list) or not entries:
        return None
    first = entries[0]
    if not isinstance(first, dict):
        return None
    cve = first.get("cve")
    return cve if isinstance(cve, dict) else None


def parse_nvd(payload: Any, cve: str) -> CVEInfo | None:
    """Parse an NVD 2.0 response for one CVE (``None`` when malformed)."""
    entry = _first_cve(payload)
    if entry is None:
        return None

    description = ""
    for item in entry.get("descriptions") or ():
        if isinstance(item, dict) and str(item.get("lang")) == "en" and item.get("value"):
            description = str(item["value"])
            break

    cwes: list[str] = []
    for weakness in entry.get("weaknesses") or ():
        if not isinstance(weakness, dict):
            continue
        for item in weakness.get("description") or ():
            value = (
                str(item.get("value") or "").upper() if isinstance(item, dict) else ""
            )
            if _CWE_PATTERN.match(value) and value not in cwes:
                cwes.append(value)

    def metric(group: str) -> tuple[str | None, float | None]:
        metrics = entry.get("metrics") or {}
        items = metrics.get(group) if isinstance(metrics, dict) else None
        if not isinstance(items, list):
            return None, None
        for item in items:
            data = (item or {}).get("cvssData") if isinstance(item, dict) else None
            if isinstance(data, dict) and data.get("vectorString"):
                score = data.get("baseScore")
                return str(data["vectorString"]), (
                    float(score) if isinstance(score, (int, float)) else None
                )
        return None, None

    v31_vector, v31_score = metric("cvssMetricV31")
    v4_vector, v4_score = metric("cvssMetricV40")

    references: list[str] = []
    for item in entry.get("references") or ():
        url = str((item or {}).get("url") or "") if isinstance(item, dict) else ""
        if url and url not in references:
            references.append(url)

    return CVEInfo(
        cve=cve,
        description=description,
        cwe=tuple(cwes),
        cvss31_vector=v31_vector,
        cvss31_score=v31_score,
        cvss4_vector=v4_vector,
        cvss4_score=v4_score,
        references=tuple(references),
        updated_at=_now(),
    )


def parse_epss(payload: Any, cve: str) -> float | None:
    """Extract the EPSS probability (0.0-1.0) for one CVE.

    Accepts both the API batch shape (``{"data": [...]}``) and the normalized
    single-CVE shape :func:`update_cves` writes to the cache.
    """
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if data is None:
        if str(payload.get("cve") or "").upper() != cve:
            return None
        raw = payload.get("epss")
        if raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None
    for item in data or ():
        if not isinstance(item, dict):
            continue
        if str(item.get("cve") or "").upper() != cve:
            continue
        raw = item.get("epss")
        if raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None
    return None


def kev_cves(payload: Any) -> set[str]:
    """Return the set of CVE ids listed in a CISA KEV catalog document."""
    result: set[str] = set()
    if not isinstance(payload, dict):
        return result
    for item in payload.get("vulnerabilities") or ():
        if not isinstance(item, dict):
            continue
        value = normalize_cve(item.get("cveID"))
        if value:
            result.add(value)
    return result


# --------------------------------------------------------------------- lookup
def load_cve(cve_value: Any, root: Path | None = None) -> CVEInfo | None:
    """Return the cached :class:`CVEInfo`; never touches the network."""
    cve = normalize_cve(cve_value)
    if cve is None:
        return None
    base = Path(root) if root is not None else cache_root()

    nvd = _read_json(_nvd_path(cve, base))
    info = parse_nvd(nvd, cve) if nvd is not None else None
    if info is None:
        info = CVEInfo(cve=cve)

    epss = parse_epss(_read_json(_epss_path(cve, base)), cve)
    kev = cve in kev_cves(_read_json(_kev_path(base)))
    return replace(info, epss=epss, kev=kev)


# --------------------------------------------------------------------- update
def default_http_get(url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Any:
    """Fetch ``url`` and decode JSON with httpx (the project's HTTP client).

    Raises on any transport/decoding error: the caller (:func:`update_cves`)
    records it and moves on, so one dead source never aborts an update.
    """
    import httpx

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    api_key = os.environ.get(NVD_API_KEY_ENV)
    if api_key and "services.nvd.nist.gov" in url:
        headers["apiKey"] = api_key
    response = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    return response.json()


def _nvd_url(cve: str) -> str:
    return f"{NVD_API}?cveId={cve}"


def _epss_url(cves: Iterable[str]) -> str:
    return f"{EPSS_API}?cve={','.join(cves)}"


def update_cves(
    cves: Iterable[str],
    *,
    root: Path | None = None,
    http_get: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Refresh the local cache for ``cves`` (NVD + EPSS + CISA KEV).

    Returns a summary dict; every source is best-effort and independent, so a
    network failure is reported in ``errors`` instead of raising.
    """
    base = Path(root) if root is not None else cache_root()
    fetch = http_get or default_http_get
    requested = [normalize_cve(item) for item in cves]
    targets = [item for item in requested if item]
    summary: dict[str, Any] = {
        "requested": len(targets),
        "nvd_updated": 0,
        "epss_updated": 0,
        "kev_updated": False,
        "errors": [],
    }

    for cve in targets:
        try:
            payload = fetch(_nvd_url(cve))
        except Exception as exc:  # noqa: BLE001 - best-effort by contract
            summary["errors"].append(f"nvd:{cve}:{type(exc).__name__}")
            continue
        info = parse_nvd(payload, cve)
        if info is None:
            summary["errors"].append(f"nvd:{cve}:empty")
            continue
        if _write_json(_nvd_path(cve, base), payload):
            summary["nvd_updated"] += 1

    if targets:
        try:
            payload = fetch(_epss_url(targets))
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(f"epss:{type(exc).__name__}")
            payload = None
        if payload is not None:
            for cve in targets:
                score = parse_epss(payload, cve)
                if score is None:
                    continue
                if _write_json(_epss_path(cve, base), {"cve": cve, "epss": score}):
                    summary["epss_updated"] += 1

    try:
        kev_payload = fetch(KEV_API)
    except Exception as exc:  # noqa: BLE001
        summary["errors"].append(f"kev:{type(exc).__name__}")
    else:
        if _write_json(_kev_path(base), kev_payload):
            summary["kev_updated"] = True

    return summary


# ------------------------------------------------------------------ enrichment
def enrich_findings(
    findings: Iterable[Any],
    *,
    root: Path | None = None,
) -> tuple[Any, ...]:
    """Return copies of ``findings`` carrying cached CVE enrichment.

    Purely cache-backed: no network, no blocking, no exceptions. A finding whose
    CVE is not cached keeps empty fields. An existing CVSS v4.0 vector on the
    finding is never overwritten (local/tool calculation prevails).
    """
    base = Path(root) if root is not None else cache_root()
    result: list[Any] = []
    for finding in findings:
        cve = normalize_cve(getattr(finding, "cve", None))
        if cve is None:
            result.append(finding)
            continue
        try:
            info = load_cve(cve, base)
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            info = None
        if info is None:
            result.append(finding)
            continue
        result.append(_apply(finding, info))
    return tuple(result)


def _apply(finding: Any, info: CVEInfo) -> Any:
    """Merge one :class:`CVEInfo` into a finding without overwriting data."""
    updates: dict[str, Any] = {}
    if info.description and not getattr(finding, "cve_description", ""):
        updates["cve_description"] = info.description
    if info.cwe and not getattr(finding, "cwe", None):
        updates["cwe"] = info.cwe[0]
    if info.epss is not None and getattr(finding, "epss_score", None) is None:
        updates["epss_score"] = info.epss
    if info.kev and not getattr(finding, "kev", False):
        updates["kev"] = True
    if not getattr(finding, "cvss4_vector", None) and info.cvss4_vector:
        # Validate before trusting it; a malformed cached vector is ignored.
        from .cvss4 import parse_cvss4_vector

        if parse_cvss4_vector(info.cvss4_vector) is not None:
            updates["cvss4_vector"] = info.cvss4_vector
            updates["cvss4_source"] = "nvd"
    if not updates:
        return finding
    try:
        return replace(finding, **updates)
    except Exception:  # noqa: BLE001 - never break the report for enrichment
        return finding


def collect_cves(findings: Iterable[Any]) -> list[str]:
    """Return the distinct, normalized CVEs referenced by ``findings``."""
    result: list[str] = []
    for finding in findings:
        cve = normalize_cve(getattr(finding, "cve", None))
        if cve and cve not in result:
            result.append(cve)
    return result


__all__ = [
    "CVE_DIRNAME",
    "CVEInfo",
    "DEFAULT_TIMEOUT_SECONDS",
    "EPSS_API",
    "KEV_API",
    "NVD_API",
    "NVD_API_KEY_ENV",
    "cache_root",
    "collect_cves",
    "default_http_get",
    "enrich_findings",
    "kev_cves",
    "load_cve",
    "normalize_cve",
    "parse_epss",
    "parse_nvd",
    "update_cves",
]
