"""Native WordPress reconnaissance parsers (no wpscan, no external database).

WordPress advertises almost everything a first-pass assessment needs over plain
HTTP: the version in ``<meta name="generator">`` (and in ``readme.html``), the
author accounts through the REST API *and* through the blog's author archives,
and the active theme/plugins through ``/wp-content/...`` asset URLs. Parsing
that locally is deterministic, needs no metadata database (``wpscan`` refuses to
scan at all when its DB is missing) and takes milliseconds instead of seconds.

Everything here is pure: the handlers stay thin and the behaviour is testable
without a network.
"""

from __future__ import annotations

import html as _html
import json
import re
from dataclasses import dataclass, field
from typing import Any

#: ``<meta name="generator" content="WordPress 5.4.2" />`` on the front page/feed.
WP_GENERATOR_RE = re.compile(
    r"""<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s+([0-9][0-9.]*)""",
    re.IGNORECASE,
)
#: ``readme.html`` states the version in a heading: ``<h1>Version 5.4.2</h1>``.
WP_README_VERSION_RE = re.compile(r"Version\s+([0-9][0-9.]+)")
#: ``/wp-content/themes/<slug>/...`` and ``/wp-content/plugins/<slug>/...``.
WP_THEME_ASSET_RE = re.compile(r"/wp-content/themes/([A-Za-z0-9._-]+)")
WP_PLUGIN_ASSET_RE = re.compile(r"/wp-content/plugins/([A-Za-z0-9._-]+)")
#: ``<input ... name="_wpnonce" value="abc123" />`` in either attribute order.
WP_NONCE_RE = re.compile(
    r"""name=["']_wpnonce["'][^>]*value=["']([A-Za-z0-9]+)["']"""
    r"""|value=["']([A-Za-z0-9]+)["'][^>]*name=["']_wpnonce["']""",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WP_SITE_NAME_RE = re.compile(r"<title>.*?[&#8211;\-|]\s*([^<]+)</title>", re.IGNORECASE)
_TRAILING_PUNCTUATION = " \t\r\n/.,;:"


def normalize_site_url(value: str) -> str:
    """Return a bare ``scheme://host[:port]/path`` base with no trailing slash.

    Raises ``ValueError`` for anything without an http(s) scheme: the handlers
    must never build URLs around a value the operator did not scope.
    """
    text = str(value or "").strip()
    if not text:
        raise ValueError("url is required")
    if "://" not in text:
        text = "http://" + text
    scheme, _, rest = text.partition("://")
    if scheme.lower() not in ("http", "https"):
        raise ValueError(f"url scheme must be http or https: {value!r}")
    if not rest:
        raise ValueError(f"url has no host: {value!r}")
    return f"{scheme.lower()}://{rest}".rstrip(_TRAILING_PUNCTUATION)


def extract_version(front_page: str = "", readme: str = "") -> tuple[str | None, str | None]:
    """Return ``(version, source)`` from the generator meta tag or ``readme.html``."""
    match = WP_GENERATOR_RE.search(front_page or "")
    if match:
        return match.group(1), "meta_generator"
    match = WP_README_VERSION_RE.search(readme or "")
    if match:
        return match.group(1), "readme_html"
    return None, None


def extract_assets(*documents: str) -> dict[str, list[str]]:
    """Return the themes/plugins observed in any of the supplied HTML documents."""
    themes: list[str] = []
    plugins: list[str] = []
    for document in documents:
        for match in WP_THEME_ASSET_RE.finditer(document or ""):
            name = match.group(1)
            if name not in themes:
                themes.append(name)
        for match in WP_PLUGIN_ASSET_RE.finditer(document or ""):
            name = match.group(1)
            if name not in plugins:
                plugins.append(name)
    return {"themes": themes, "plugins": plugins}


def extract_site_title(document: str) -> str | None:
    """Return the human-facing site name from ``<title>`` (``Page – Name``)."""
    match = _TITLE_RE.search(document or "")
    if not match:
        return None
    title = _html.unescape(re.sub(r"\s+", " ", match.group(1))).strip()
    if not title:
        return None
    if "–" in title:
        return title.rsplit("–", 1)[-1].strip()
    match = _WP_SITE_NAME_RE.search(document or "")
    return match.group(1).strip() if match else title


def extract_rest_users(payload: str) -> list[dict[str, Any]]:
    """Parse a ``/wp-json/wp/v2/users`` (or ``?rest_route=``) response.

    Raises ``ValueError`` when the payload is not the user array, so a 404 page
    is never mistaken for "the site has no users".
    """
    try:
        data = json.loads(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"REST users payload is not JSON: {exc}") from exc
    if not isinstance(data, list):
        # ``ValueError`` (not ``TypeError``) on purpose: it is the documented
        # contract of this parser and the call site in ``handlers/wp.py`` treats
        # a 200 that is not a user array as "no users", never as a crash.
        raise ValueError("REST users payload is not an array")  # noqa: TRY004
    users: list[dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        slug = str(entry.get("slug") or entry.get("name") or "").strip()
        if not slug:
            continue
        users.append(
            {
                "id": entry.get("id"),
                "slug": slug,
                "name": str(entry.get("name") or slug).strip(),
                "link": entry.get("link"),
            }
        )
    return users


def extract_nonce(document: str) -> str | None:
    """Return the ``_wpnonce`` of a wp-admin form, or ``None``."""
    match = WP_NONCE_RE.search(document or "")
    if not match:
        return None
    return match.group(1) or match.group(2)


def extract_textarea(document: str, name: str) -> str | None:
    """Return the decoded value of ``<textarea name="...">``, or ``None``.

    ``wp-admin/theme-editor.php`` escapes the file with ``esc_textarea``, so the
    entities have to be decoded before the content can be uploaded back.
    """
    match = re.search(
        r'<textarea[^>]*name=["\']' + re.escape(name) + r'["\'][^>]*>(.*?)</textarea>',
        document or "",
        re.DOTALL,
    )
    if not match:
        return None
    return _html.unescape(match.group(1))


@dataclass(frozen=True)
class WordPressFindings:
    """Structured result of one WordPress enumeration."""

    version: str | None = None
    version_source: str | None = None
    site_title: str | None = None
    users: tuple[dict[str, Any], ...] = ()
    themes: tuple[str, ...] = ()
    plugins: tuple[str, ...] = ()
    interesting: tuple[dict[str, Any], ...] = field(default=())
    raw_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "version": self.version,
            "version_source": self.version_source,
            "site_title": self.site_title,
            "users": list(self.users),
            "themes": list(self.themes),
            "plugins": list(self.plugins),
            "interesting": list(self.interesting),
            "raw_sha256": self.raw_sha256,
        }


__all__ = [
    "WordPressFindings",
    "extract_assets",
    "extract_nonce",
    "extract_rest_users",
    "extract_site_title",
    "extract_textarea",
    "extract_version",
    "normalize_site_url",
]
