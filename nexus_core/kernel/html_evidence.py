"""Deterministic page evidence: what a page *says* about identity and surface.

Measured on HackPark (2026-10-21, V15 family): the run downloaded a footer that
carried ``j.doe@services.local`` and a team page that listed ``Jack Rock - IT
Staff``, and the engine recorded neither. ``user`` and ``email`` are legal fact
types (:mod:`nexus_core.kernel.blackboard`) and the only producer of a ``user``
fact was ``wp_enum``; nothing in the HTTP path extracted an address, a person or
an ``<a href>``. The page was 35 KB of untouched HTML in the observation and the
run asked "are there users?" with the users already on screen.

The fix is not a better prompt: it is taking the model out of that path. This
module is pure, stdlib-only (``html.parser``, no new dependency), bounded, and
cheap enough to run on every response. It never asserts a fact -it returns
observations- and it never claims an account exists: an address in a page proves
the address is published, not that the directory has it.

What it returns::

    {
        "emails": ["j.doe@services.local"],
        "people": [{"name": "Jack Rock", "title": "IT Staff"}],
        "links": [{"url": "http://host/about.html", "text": "About",
                   "internal": True, "navigable": True}],
        "technologies": ["bootstrap", "jquery"],
        "truncated": False,
    }

Limits are deliberate: a huge page is cut at a tag-ish boundary, lists are
capped, and every list is de-duplicated preserving the order the page used.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

#: Characters of HTML this module will read. Above this the page is metadata,
#: not evidence: the tail of a 10 MB dump is not where a team page hides.
MAX_HTML_CHARS = 200_000
MAX_EMAILS = 50
MAX_LINKS = 60
MAX_PEOPLE = 40
MAX_TECHNOLOGIES = 15

#: A published address. Deliberately conservative about the TLD (2+ letters) and
#: about the local part (no spaces, no quotes) so a CSS ``content:`` or a log
#: line is not read as an identity.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")

#: File extensions that are never a page to fetch. They stay in ``links`` (a
#: backup or a PDF can be loot) but never in ``next_steps``.
_ASSET_EXTENSIONS = (
    ".css", ".js", ".mjs", ".json", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".svg", ".ico", ".webp", ".bmp", ".woff", ".woff2", ".ttf", ".eot",
)

#: Two or three capitalised tokens: a human name, not a sentence.
_NAME_RE = re.compile(r"^[A-Z][A-Za-z'’\-]{1,}(?:\s+[A-Z][A-Za-z'’\-]{1,}){1,2}$")

#: ``Joanne Doe - Sales`` / ``Jack Rock: IT Staff`` in a single text node.
_NAME_TITLE_RE = re.compile(
    r"^(?P<name>[A-Z][A-Za-z'’\-]{1,}(?:\s+[A-Z][A-Za-z'’\-]{1,}){1,2})\s*[-–—|·:]\s*(?P<title>\S.*)$"
)

#: Words that make two capitalised tokens a label instead of a person. "IT
#: Staff" is a role, "Our Team" is a heading and "Privacy Policy" is a link;
#: none of them is a candidate account.
_ROLE_WORDS: frozenset[str] = frozenset(
    {
        "admin", "administrator", "analyst", "assistant", "ceo", "cfo", "cio",
        "coo", "consultant", "coordinator", "cto", "customer", "developer",
        "designer", "director", "engineer", "finance", "founder", "group",
        "head", "helpdesk", "hr", "human", "it", "lead", "manager", "marketing",
        "officer", "operations", "owner", "partner", "president", "receptionist",
        "representative", "resources", "sales", "security", "service", "services",
        "solutions", "specialist", "staff", "support", "team", "technician",
    }
)

#: UI phrases that match ``_NAME_RE`` and are not a person.
_STOP_PHRASES: frozenset[str] = frozenset(
    {
        "about us", "all rights", "back to", "click here", "contact us",
        "cookie policy", "get started", "learn more", "log in", "meet the",
        "our team", "privacy policy", "read more", "see more", "sign in",
        "sign up", "terms conditions", "the team", "view all", "view more",
        "your account",
    }
)

_HEADING_TAGS: frozenset[str] = frozenset({"h1", "h2", "h3", "h4", "h5", "h6", "strong", "b", "figcaption"})

#: Titles longer than this are prose, not a role label.
_MAX_TITLE_CHARS = 60

#: Known fingerprints worth naming without a Wappalyzer-style database. Each
#: entry is (marker in the page, canonical technology).
_TECH_HINTS: tuple[tuple[str, str], ...] = (
    ("jquery", "jquery"),
    ("bootstrap", "bootstrap"),
    ("flexslider", "flexslider"),
    ("modernizr", "modernizr"),
    ("font-awesome", "fontawesome"),
    ("fontawesome", "fontawesome"),
    ("html5shim", "html5shim"),
    ("wp-content", "wordpress"),
    ("wp-includes", "wordpress"),
    ("joomla", "joomla"),
    ("drupal", "drupal"),
    ("sites/default/files", "drupal"),
    ("angular", "angularjs"),
    ("vue.min.js", "vue"),
    ("react-dom", "react"),
    ("/cdn-cgi/", "cloudflare"),
)


class _PageParser(HTMLParser):
    """Collect the three things this module needs from the markup stream."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.texts: list[tuple[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.generator = ""
        self.assets: list[str] = []
        self._stack: list[str] = []
        self._anchor: dict[str, str] | None = None

    # -- tags ---------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(name).lower(): (value or "") for name, value in attrs}
        self._stack.append(tag)
        if tag == "meta" and values.get("name", "").lower() == "generator":
            self.generator = values.get("content", "").strip()
        elif tag == "a":
            self._anchor = {"href": values.get("href", "").strip(), "text": ""}
        elif tag in {"script", "link"}:
            asset = values.get("src") or values.get("href") or ""
            if asset:
                self.assets.append(asset)
        elif tag == "base" and values.get("href"):
            # A ``<base>`` changes every relative link; recorded as an asset so
            # the caller can still resolve against the request URL (the common
            # case) without silently rewriting the whole page.
            self.assets.append(values["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchor is not None:
            href = self._anchor["href"]
            text = " ".join(self._anchor["text"].split())
            if href:
                self.links.append({"href": href, "text": text})
            self._anchor = None
        # Pop to the matching opener; malformed markup must not corrupt the
        # stack (the parser is tolerant, our stack has to be too).
        while self._stack:
            if self._stack.pop() == tag:
                break

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if not text:
            return
        if self._anchor is not None:
            self._anchor["text"] = f"{self._anchor['text']} {text}".strip()
        if len(text) <= 120:
            self.texts.append((self._stack[-1] if self._stack else "", text))


def _dedupe(values, *, limit: int) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = str(value).strip()
        if not key or key.casefold() in seen:
            continue
        seen.add(key.casefold())
        result.append(key)
        if len(result) >= limit:
            break
    return result


def _truncate(body: str) -> tuple[str, bool]:
    if len(body) <= MAX_HTML_CHARS:
        return body, False
    cut = body[:MAX_HTML_CHARS]
    # Do not leave a half-written tag: retire the partial tail if one is open.
    last_open = cut.rfind("<")
    last_close = cut.rfind(">")
    if last_open > last_close:
        cut = cut[:last_open]
    return cut, True


def _is_person_name(text: str) -> bool:
    candidate = text.strip()
    if not candidate or len(candidate) > 48 or not _NAME_RE.match(candidate):
        return False
    folded = candidate.casefold()
    if folded in _STOP_PHRASES:
        return False
    tokens = folded.replace("-", " ").split()
    return not any(token in _ROLE_WORDS for token in tokens)


def _is_title(text: str) -> bool:
    candidate = text.strip()
    if not candidate or len(candidate) > _MAX_TITLE_CHARS:
        return False
    if candidate.endswith("."):
        return False
    words = {word.strip(".,;:()[]").casefold() for word in candidate.split()}
    return bool(words & _ROLE_WORDS)


def _extract_people(texts: list[tuple[str, str]]) -> list[dict[str, str]]:
    people: dict[str, dict[str, str]] = {}
    for index, (tag, text) in enumerate(texts):
        name = ""
        title = ""
        combined = _NAME_TITLE_RE.match(text)
        if combined and _is_person_name(combined.group("name")):
            name = combined.group("name").strip()
            if _is_title(combined.group("title")):
                title = combined.group("title").strip()
        elif _is_person_name(text):
            name = text.strip()
            # The title usually lives in the *next* text chunk of the same card
            # (``<h4>Name</h4><p>Role</p>``). Looking three chunks ahead covers
            # the ``<span>``/``<br>`` variants without pairing across cards: a
            # card never contributes more than name + role.
            for _ahead_tag, ahead in texts[index + 1:index + 4]:
                if _is_title(ahead):
                    title = ahead.strip()
                    break
        if not name:
            continue
        if not title and tag not in _HEADING_TAGS:
            # A bare two-token capitalised string outside a heading is a label
            # or a nav item far more often than a person.
            continue
        key = name.casefold()
        current = people.get(key)
        if current is None or (not current["title"] and title):
            people[key] = {"name": name, "title": title}
        if len(people) >= MAX_PEOPLE:
            break
    return list(people.values())


def _normalize_link(href: str, base_url: str) -> tuple[str, bool] | None:
    raw = href.strip()
    if not raw or raw.startswith("#"):
        return None
    lowered = raw.lower()
    if lowered.startswith(("mailto:", "tel:", "javascript:", "data:", "sms:")):
        return None
    absolute = urljoin(base_url, raw)
    parts = urlsplit(absolute)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    # Drop the fragment (the page is the same document) and keep the query: a
    # ``?page=2`` is a different page on half the CMSs in the wild.
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    base = urlsplit(base_url)
    internal = parts.netloc.casefold() == (base.netloc or "").casefold()
    return clean, internal


def _is_navigable(url: str) -> bool:
    path = urlsplit(url).path.casefold()
    return not path.endswith(_ASSET_EXTENSIONS)


def extract_page_evidence(body: str | bytes | None, base_url: str) -> dict:
    """Return what ``body`` publishes about identity, links and technology.

    Accepts ``bytes`` (the handler carries the preview as text, but a caller may
    hold the raw body) and returns empty lists for a non-HTML or empty page
    instead of raising: a tool must never fail because a page was not markup.
    """
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if not isinstance(body, str) or not body.strip():
        return {"emails": [], "people": [], "links": [], "technologies": [], "truncated": False}
    text, truncated = _truncate(body)
    parser = _PageParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # noqa: BLE001 - a malformed page is not a tool failure
        pass

    emails = _dedupe(_EMAIL_RE.findall(text), limit=MAX_EMAILS)
    people = _extract_people(parser.texts)

    links: list[dict[str, object]] = []
    seen: set[str] = set()
    for anchor in parser.links:
        resolved = _normalize_link(anchor["href"], base_url)
        if resolved is None:
            continue
        url, internal = resolved
        if url in seen:
            continue
        seen.add(url)
        links.append(
            {
                "url": url,
                "text": anchor["text"][:80],
                "internal": internal,
                "navigable": _is_navigable(url),
            }
        )
        if len(links) >= MAX_LINKS:
            break

    lowered = text.casefold()
    technologies = [name for marker, name in _TECH_HINTS if marker in lowered]
    if parser.generator:
        # ``WordPress 5.4`` names the product, not the vendor string: the first
        # token is what a later ``searchsploit`` query needs.
        technologies.append(parser.generator.split()[0].casefold())
    technologies = _dedupe(technologies, limit=MAX_TECHNOLOGIES)

    return {
        "emails": emails,
        "people": people,
        "links": links,
        "technologies": technologies,
        "truncated": truncated,
    }


def next_pages(evidence: dict, current_url: str, *, limit: int = 5) -> list[str]:
    """Same-origin pages the response links to and the run has not fetched.

    This is the "about.html was never requested" fix: the observation itself
    names the pages that are one hop away, so the model does not have to notice
    them in 35 KB of markup. The current URL is excluded (a self-link is not a
    new page) as are assets and external hosts.
    """
    if not isinstance(evidence, dict):
        return []
    current = urlsplit(current_url)
    current_key = urlunsplit((current.scheme, current.netloc, current.path or "/", current.query, ""))
    pages: list[str] = []
    for link in evidence.get("links") or ():
        if not isinstance(link, dict):
            continue
        if not link.get("internal") or not link.get("navigable"):
            continue
        url = str(link.get("url") or "")
        if not url or url == current_key or url in pages:
            continue
        pages.append(url)
        if len(pages) >= limit:
            break
    return pages
