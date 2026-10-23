"""The page says who works there; the extractor is what reads it.

Measured (HackPark, V15 family): the run downloaded a footer with
``j.doe@services.local`` and never requested ``/about.html``, although the nav
linked it and the page listed the staff with their roles. This module is the
deterministic half of that fix, so the tests pin the four lists it produces and
the one it refuses to produce (a name is not an account).
"""

from __future__ import annotations

from nexus_core.kernel.html_evidence import extract_page_evidence, next_pages

TEAM_PAGE = """<!doctype html>
<html><head>
  <meta name="generator" content="WordPress 5.4">
  <link rel="stylesheet" href="/assets/bootstrap.min.css">
  <script src="/js/jquery.js"></script>
</head><body>
  <nav>
    <a href="/index.html">Home</a>
    <a href="/about.html">About</a>
    <a href="/courses.html">Courses</a>
    <a href="https://partner.example/offer">Partner</a>
    <a href="#top">Top</a>
    <a href="mailto:j.doe@services.local">Mail us</a>
  </nav>
  <div class="team">
    <div class="member"><h4>Joanne Doe</h4><p>Sales</p></div>
    <div class="member"><h4>Jack Rock</h4><p>IT Staff</p></div>
    <div class="member"><h4>Will Masters</h4><p>CEO</p></div>
    <div class="member"><h4>Johnny LaRusso</h4><p>Marketing</p></div>
  </div>
  <footer>Contact: <a href="mailto:j.doe@services.local">j.doe@services.local</a></footer>
</body></html>
"""

BASE = "http://203.0.113.10/index.html"


def test_emails_are_read_from_text_and_mailto_and_not_duplicated():
    evidence = extract_page_evidence(TEAM_PAGE, BASE)
    assert evidence["emails"] == ["j.doe@services.local"]


def test_people_are_paired_with_the_role_that_follows_them():
    people = extract_page_evidence(TEAM_PAGE, BASE)["people"]
    roles = {person["name"]: person["title"] for person in people}
    assert roles["Jack Rock"] == "IT Staff"
    assert roles["Joanne Doe"] == "Sales"
    assert roles["Will Masters"] == "CEO"
    assert roles["Johnny LaRusso"] == "Marketing"


def test_a_role_label_is_never_read_as_a_person():
    """"IT Staff" and "Our Team" match the shape of a name; they are not one."""
    page = "<html><body><h4>IT Staff</h4><p>Our Team</p></body></html>"
    assert extract_page_evidence(page, BASE)["people"] == []


def test_links_are_resolved_and_external_or_non_http_ones_are_flagged():
    links = extract_page_evidence(TEAM_PAGE, BASE)["links"]
    by_url = {link["url"]: link for link in links}
    assert by_url["http://203.0.113.10/about.html"]["internal"] is True
    assert by_url["http://203.0.113.10/about.html"]["navigable"] is True
    assert by_url["https://partner.example/offer"]["internal"] is False
    assert not any("mailto:" in url or url.endswith("#top") for url in by_url)
    # A fragment is the same document, never a new page to fetch.
    assert all("#" not in url for url in by_url)


def test_technology_is_named_without_a_fingerprint_database():
    technologies = extract_page_evidence(TEAM_PAGE, BASE)["technologies"]
    assert "wordpress" in technologies
    assert "bootstrap" in technologies
    assert "jquery" in technologies


def test_next_pages_names_only_the_unvisited_internal_routes():
    evidence = extract_page_evidence(TEAM_PAGE, BASE)
    pages = next_pages(evidence, BASE)
    assert "http://203.0.113.10/about.html" in pages
    assert "http://203.0.113.10/courses.html" in pages
    # The page itself and the CSS/JS assets are not pages to fetch.
    assert BASE not in pages
    assert not any(page.endswith((".css", ".js")) for page in pages)
    assert all(page.startswith("http://203.0.113.10/") for page in pages)


def test_a_non_markup_page_yields_nothing_and_never_raises():
    for body in ("", None, b"", '{"users": ["admin"]}', "<html>"):
        evidence = extract_page_evidence(body, BASE)
        assert evidence["emails"] == []
        assert evidence["people"] == []
        assert next_pages(evidence, BASE) == []


def test_a_huge_page_is_cut_and_says_so():
    body = "<html><body>" + ("<p>x</p>" * 40_000) + "</body></html>"
    evidence = extract_page_evidence(body, BASE)
    assert evidence["truncated"] is True
