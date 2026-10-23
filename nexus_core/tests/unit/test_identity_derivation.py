"""From a published address and a staff list to a ranked candidate list.

The rule is arithmetic, and its ranking is a safety property: an address the
page printed outranks a convention guess, a person with a privileged role
outranks the rest, and a page with no address produces no accounts at all
instead of inventing a convention.
"""

from __future__ import annotations

from nexus_core.kernel.identity_derivation import (
    CONVENTION_FIRST_DOT_LAST,
    CONVENTION_INITIAL_DOT_LAST,
    derive_identities,
    detect_convention,
    split_name,
)

PEOPLE = [
    {"name": "Joanne Doe", "title": "Sales"},
    {"name": "Jack Rock", "title": "IT Staff"},
    {"name": "Will Masters", "title": "CEO"},
    {"name": "Johnny LaRusso", "title": "Marketing"},
]
EMAILS = ["j.doe@services.local"]


def test_the_confirmed_address_fixes_the_convention():
    convention, matches, sample = detect_convention(EMAILS, PEOPLE)
    assert convention == CONVENTION_INITIAL_DOT_LAST
    assert matches == 1
    assert sample == "j.doe@services.local"


def test_a_second_convention_is_detected_when_the_page_uses_it():
    people = [{"name": "Joanne Doe", "title": "Sales"}]
    convention, matches, _ = detect_convention(["joanne.doe@corp.example"], people)
    assert convention == CONVENTION_FIRST_DOT_LAST
    assert matches == 1


def test_names_derive_the_expected_accounts_in_ranked_order():
    result = derive_identities(EMAILS, PEOPLE)
    usernames = [candidate["username"] for candidate in result["candidates"]]
    assert usernames[0] == "j.doe"          # printed on the page
    assert "j.rock" in usernames            # IT Staff, derived
    assert "w.masters" in usernames
    assert "j.larusso" in usernames
    assert result["domain"] == "services.local"
    assert result["convention"] == CONVENTION_INITIAL_DOT_LAST


def test_the_observed_address_keeps_its_dots_and_outranks_every_guess():
    candidates = {c["username"]: c for c in derive_identities(EMAILS, PEOPLE)["candidates"]}
    assert candidates["j.doe"]["confidence"] == 1.0
    assert candidates["j.doe"]["basis"] == "observed_email"
    assert candidates["j.rock"]["confidence"] < candidates["j.doe"]["confidence"]
    # Folding the local part would have produced "jdoe", a different account.
    assert "jdoe" not in candidates


def test_privileged_roles_are_ranked_first_among_the_derived():
    result = derive_identities(EMAILS, PEOPLE)
    targets = {item["name"]: item for item in result["priority_targets"]}
    assert targets["Jack Rock"]["title"] == "IT Staff"
    assert targets["Will Masters"]["title"] == "CEO"
    assert targets["Jack Rock"]["username"] == "j.rock"
    assert "Joanne Doe" not in targets       # Sales is not a priority account


def test_without_a_published_address_there_are_no_accounts_to_invent():
    result = derive_identities([], PEOPLE)
    assert result["candidates"] == []
    assert result["convention"] is None
    assert result["domain"] == ""


def test_without_a_confirmed_convention_the_guess_is_explicitly_weak():
    result = derive_identities(["helpdesk@services.local"], PEOPLE)
    candidates = {c["username"]: c for c in result["candidates"]}
    assert candidates["j.rock"]["confidence"] == 0.3
    assert candidates["j.rock"]["basis"] == "derived_without_confirmed_convention"


def test_a_middle_initial_or_an_accent_does_not_change_the_account():
    assert split_name("Joanne M. Doe") == ("joanne", "doe")
    assert split_name("Núñez, José") is None or split_name("José Núñez") == ("jose", "nunez")
    result = derive_identities([], [{"name": "José Núñez", "title": "IT"}])
    assert result["candidates"] == []
    derived = derive_identities(["j.nunez@services.local"], [{"name": "José Núñez", "title": "IT"}])
    assert derived["candidates"][0]["username"] == "j.nunez"
