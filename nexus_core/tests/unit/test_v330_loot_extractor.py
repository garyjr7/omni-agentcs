"""V0-24/V0-27/V0-30: one deterministic loot extractor for every channel."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.loot_extractor import (
    extract_credentials,
    extract_file_loot,
    extract_http_loot,
    extract_untrusted_text,
)
from nexus_core.kernel.models import ToolResult

pytestmark = pytest.mark.unit

TARGET = "10.10.10.5"


def _context() -> SimpleNamespace:
    return SimpleNamespace(invocation_id="inv-v330", run_id="run-v330", tenant_id="system")


def _rows(tool_id: str, arguments: dict, output: dict, method: str):
    result = ToolResult(output=output, verified=True, verification_method=method)
    return derive_assertions(tool_id, arguments, result, _context())


# --------------------------------------------------------------- pure extractor
def test_a_flag_needs_a_known_prefix_and_a_body():
    candidates = extract_file_loot(
        "notes: {not-a-flag}\nflag{fake_flag}\nHTB{another}\n",
        path="/tmp/notes.txt",
    )
    assert [item.value for item in candidates] == ["flag{fake_flag}", "HTB{another}"]


def test_a_conventional_flag_file_accepts_a_plain_hash_but_not_a_long_file():
    short = extract_file_loot("8bd7992f...\n", path="/home/lin/user.txt")
    assert [item.value for item in short] == ["8bd7992f..."]

    long = extract_file_loot("line one\nline two\n", path="/home/lin/user.txt")
    assert long == []


def test_a_flag_in_a_response_header_is_loot():
    candidates = extract_http_loot(
        "<html>nothing here</html>",
        {"x-proof": "THM{header_flag}", "content-type": "text/html"},
    )
    assert [(item.value, item.path) for item in candidates] == [
        ("THM{header_flag}", "header:x-proof")
    ]


def test_credentials_require_labels_or_a_complete_user_pass_line():
    labelled = extract_file_loot(
        "username: lin\npassword: s3cret\n", path="/tmp/note.txt"
    )
    assert [(item.username, item.password) for item in labelled] == [("lin", "s3cret")]

    pair = extract_credentials("admin:Passw0rd\n")
    assert [(item.username, item.password) for item in pair] == [("admin", "Passw0rd")]

    # ``username: admin`` is a note; a bare token is not a credential.
    assert extract_credentials("username: admin\n") == []
    assert extract_credentials("admin\n") == []


def test_llm_text_without_reproducibility_or_raw_evidence_promotes_nothing():
    assert extract_untrusted_text("flag{fake_flag}") == []
    assert [item.value for item in extract_untrusted_text(
        "flag{fake_flag}", reproduced=2
    )] == ["flag{fake_flag}"]
    assert [item.value for item in extract_untrusted_text(
        "flag{fake_flag}", raw_sha256="a" * 64
    )] == ["flag{fake_flag}"]


# ------------------------------------------------------------- HTTP integration
def test_http_body_and_header_loot_reach_the_board():
    rows = _rows(
        "nexus.web.request",
        {"url": "http://10.10.10.5/notes.txt"},
        {
            "url": "http://10.10.10.5/notes.txt",
            "status": 200,
            "body_preview": "welcome\nflag{body_flag}\n",
            "headers": {"x-proof": "HTB{header_flag}"},
        },
        "http_response_received",
    )
    loot = [row for row in rows if row["fact_type"] == "loot"]
    assert {row["value"]["flag"] for row in loot} == {
        "flag{body_flag}",
        "HTB{header_flag}",
    }
    assert all(row["target"] == TARGET for row in loot)


def test_an_html_form_does_not_create_a_fake_credential():
    rows = _rows(
        "nexus.web.request",
        {"url": "http://10.10.10.5/login"},
        {
            "url": "http://10.10.10.5/login",
            "status": 200,
            "body_preview": (
                "<html><form><input name='username'>Username\n"
                "Username: admin\nPassword: secret\n</form></html>"
            ),
            "headers": {},
        },
        "http_response_received",
    )
    assert "credential" not in {row["fact_type"] for row in rows}


# --------------------------------------------------------- SMB/workspace/FTP
def test_smb_download_promotes_the_remote_file_and_keeps_the_digest():
    rows = _rows(
        "nexus.recon.smb",
        {"target": TARGET, "remote_path": "share/root.txt"},
        {
            "target": TARGET,
            "file": "root.txt",
            "size": 18,
            "sha256": "b" * 64,
            "preview": "flag{smb_flag}\n",
        },
        "smb_download_verified",
    )
    loot = [row for row in rows if row["fact_type"] == "loot"]
    assert len(loot) == 1
    assert loot[0]["key"] == f"smb:{TARGET}:share/root.txt"
    assert loot[0]["value"]["sha256"] == "b" * 64
    assert loot[0]["value"]["flag"] == "flag{smb_flag}"


def test_ftp_listing_promotes_the_flag_the_handler_only_stored_as_a_lead():
    rows = _rows(
        "nexus.recon.ftp",
        {"target": TARGET, "action": "list"},
        {
            "target": TARGET,
            "port": 21,
            "files": [
                {
                    "remote": "pub/flag.txt",
                    "preview": "flag{ftp_flag}\n",
                    "sha256": "c" * 64,
                }
            ],
        },
        "ftp_listing_parsed",
    )
    loot = [row for row in rows if row["fact_type"] == "loot"]
    assert len(loot) == 1
    assert loot[0]["key"] == f"ftp:{TARGET}:21:pub/flag.txt"
    assert loot[0]["value"]["flag"] == "flag{ftp_flag}"


def test_workspace_read_promotes_a_downloaded_flag_with_its_sha256():
    rows = _rows(
        "nexus.workspace.read",
        {"path": "loot/user.txt"},
        {
            "path": "loot/user.txt",
            "content": "8bd7992f...\n",
            "sha256": "d" * 64,
            "truncated": False,
        },
        "workspace_read_sha256",
    )
    loot = [row for row in rows if row["fact_type"] == "loot"]
    assert len(loot) == 1
    assert loot[0]["key"] == "workspace:loot/user.txt"
    assert loot[0]["value"]["content"] == "8bd7992f..."
    assert loot[0]["value"]["sha256"] == "d" * 64
