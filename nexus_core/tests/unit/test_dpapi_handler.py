"""Unit tests for ``nexus.post.dpapi`` (offline DPAPI / KeePass loot, V0-39).

The acceptance case is a fully synthetic DPAPI -> KeePass chain: random key
material, a synthetic protected blob and a synthetic KDBX 3.1 database. The
fixtures under ``tests/fixtures/dpapi`` contain no engagement artifacts.

The shipped client is exercised for real (a subprocess with the module's own
source), so the crypto is asserted against FIPS/eSTREAM vectors and not against
itself, and the two negatives the fixture exercises (missing KeePass entropy, KDF
without the master seed) are asserted as *declared* negatives.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools import dpapi_client
from nexus_core.tools.dpapi_client import (
    Salsa20,
    _aes_expand,
    _des3_block,
    _des_block,
    _des_subkeys,
    aes_encrypt_block,
    aes_encrypt_block_fast,
    aes_round_words,
    dpapi_unwrap,
    open_kdbx,
)
from nexus_core.tools.handlers import dpapi as dpapi_module
from nexus_core.tools.handlers.dpapi import (
    KEEPASS_ENTROPY_HEX,
    client_source,
    dpapi_definition,
    dpapi_handler,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "dpapi"

#: sha256 of the synthetic 64-byte key material used by the fixture.
MATERIAL_SHA256 = "5cf9e4438e9493c24fc5bb1fc005f47ff756de44e4e1f9148996a3ff26caa068"
#: The synthetic flag, stored as the password of the "Synthetic Wallet" entry.
SYNTHETIC_FLAG = "flag{fake_flag}"


def fixture_bytes(name: str) -> bytes:
    """Return a base64 fixture decoded to bytes."""
    return base64.b64decode(FIXTURES.joinpath(name).read_text())


def masterkey_bytes() -> bytes:
    """Return synthetic-user's DPAPI masterkey from its hex fixture."""
    return bytes.fromhex(FIXTURES.joinpath("synthetic_masterkey.hex").read_text().strip())


# ------------------------------------------------------------------ crypto vectors
def test_aes_matches_the_fips_197_vectors():
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    for key_hex, expected in (
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"),
    ):
        keys, rounds = _aes_expand(bytes.fromhex(key_hex))
        assert aes_encrypt_block(plaintext, keys, rounds).hex() == expected
        # The T-table path is only an optimisation: it must agree byte for byte.
        assert aes_encrypt_block_fast(plaintext, aes_round_words(keys)).hex() == expected


def test_des_matches_the_fips_vector_and_three_des_agrees_with_a_reference():
    subkeys = _des_subkeys(bytes.fromhex("133457799bbcdff1"))
    block = int.from_bytes(bytes.fromhex("0123456789abcdef"), "big")
    cipher = _des_block(block, subkeys, decrypt=False)
    assert cipher == 0x85E813540F0AB405
    assert _des_block(cipher, subkeys, decrypt=True) == block

    des3 = pytest.importorskip("Cryptodome.Cipher.DES3")
    key, payload = bytes(range(24)), bytes(range(16, 24))
    schedules = [_des_subkeys(key[i:i + 8]) for i in range(0, 24, 8)]
    assert _des3_block(int.from_bytes(payload, "big"), schedules,
                       decrypt=False).to_bytes(8, "big") == des3.new(key, des3.MODE_ECB).encrypt(payload)


def test_salsa20_matches_the_estream_vector():
    keystream = Salsa20(bytes([0x80] + [0] * 31), bytes(8)).keystream(64)
    assert keystream.hex() == (
        "e3be8fdd8beca2e3ea8ef9475b29a6e7003951e1097a5c38d23b7a5fad9f6844"
        "b22c97559e2723c7cbbd3fe4fc8d9a0744652a83e72a9c461876af4d7ef1a117"
    )


def test_primitives_agree_with_an_independent_implementation():
    """Cross-check against pycryptodome when the host has it (it is not a runtime
    dependency of the tool, so the vector tests above are the ones that always run)."""
    crypto = pytest.importorskip("Cryptodome.Cipher.AES").new
    for key in (bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
                bytes(range(32))):
        block = bytes(range(16, 32))
        keys, rounds = _aes_expand(key)
        assert aes_encrypt_block_fast(block, aes_round_words(keys)) == crypto(key, 1).encrypt(block)


# ------------------------------------------------- the synthetic artifacts, offline
def test_the_synthetic_material_is_recovered_and_verified():
    raw = fixture_bytes("synthetic_protected_user_key.b64")
    unwrapped = dpapi_unwrap(raw, masterkey_bytes(), dpapi_client.KEEPASS_ENTROPY)
    material = unwrapped.pop("cleartext")
    assert hashlib.sha256(material).hexdigest() == MATERIAL_SHA256
    assert len(material) == 64
    assert unwrapped["signature_verified"] is True
    assert unwrapped["crypt_algo"] == "3des" and unwrapped["hash_algo"] == "sha1"



def test_the_synthetic_database_opens_and_yields_the_flag():
    material = dpapi_unwrap(
        fixture_bytes("synthetic_protected_user_key.b64"), masterkey_bytes(),
        dpapi_client.KEEPASS_ENTROPY,
    )["cleartext"]
    result = open_kdbx(fixture_bytes("synthetic_database.kdbx.b64"), material)
    assert result["format"] == "kdbx3.1"
    assert result["rounds"] == 60000
    assert result["groups"] == 2 and result["entry_count"] == 2
    assert result["flags"] == [SYNTHETIC_FLAG]
    wallet = [entry for entry in result["entries"] if entry["title"] == "Synthetic Wallet"]
    assert wallet and wallet[0]["group"] == "Synthetic"
    passwords = {entry["title"]: entry["password"] for entry in result["entries"]}
    assert passwords["Synthetic Wallet"] == SYNTHETIC_FLAG


def test_entries_match_pykeepass_when_available():
    """The independent reader must agree entry for entry (it is not a dependency)."""
    pykeepass = pytest.importorskip("pykeepass")
    kdbx_bytes = fixture_bytes("synthetic_database.kdbx.b64")
    material = dpapi_unwrap(
        fixture_bytes("synthetic_protected_user_key.b64"), masterkey_bytes(),
        dpapi_client.KEEPASS_ENTROPY,
    )["cleartext"]
    ours = sorted(
        (entry["group"].split("/")[-1], entry["title"], entry["username"], entry["password"])
        for entry in open_kdbx(kdbx_bytes, material)["entries"]
    )
    import struct

    from pykeepass.kdbx_parsing.common import aes_kdf

    header, _, _, _ = dpapi_client._kdbx_header(kdbx_bytes)
    transformed = aes_kdf(header[5], struct.unpack("<Q", header[6])[0],
                          hashlib.sha256(material).digest())
    import io

    database = pykeepass.PyKeePass(io.BytesIO(kdbx_bytes), transformed_key=transformed)
    theirs = sorted(
        (entry.group.name if entry.group else "", entry.title, entry.username or "",
         entry.password or "")
        for entry in database.entries
    )
    assert ours == theirs


def test_wrong_entropy_and_wrong_masterkey_are_declared_negatives():
    raw = fixture_bytes("synthetic_protected_user_key.b64")
    with pytest.raises(dpapi_client.LootError) as no_entropy:
        dpapi_unwrap(raw, masterkey_bytes())
    assert no_entropy.value.code == "dpapi_signature_invalid"
    with pytest.raises(dpapi_client.LootError) as wrong_key:
        dpapi_unwrap(raw, bytes(64), dpapi_client.KEEPASS_ENTROPY)
    assert wrong_key.value.code == "dpapi_signature_invalid"


def test_truncated_blob_and_wrong_material_are_classified():
    with pytest.raises(dpapi_client.LootError) as truncated:
        dpapi_unwrap(fixture_bytes("synthetic_protected_user_key.b64")[:40], masterkey_bytes())
    assert truncated.value.code == "dpapi_blob_truncated"
    with pytest.raises(dpapi_client.LootError) as wrong_material:
        open_kdbx(fixture_bytes("synthetic_database.kdbx.b64"), b"ab" * 64)
    assert wrong_material.value.code == "kdbx_credentials_invalid"


def test_kdbx4_and_foreign_files_are_refused():
    with pytest.raises(dpapi_client.LootError) as not_kdbx:
        open_kdbx(b"not a keepass database at all", bytes(64))
    assert not_kdbx.value.code == "kdbx_bad_signature"
    kdbx4 = bytearray(fixture_bytes("synthetic_database.kdbx.b64"))
    kdbx4[8:12] = (0x00040000).to_bytes(4, "little")
    with pytest.raises(dpapi_client.LootError) as version:
        open_kdbx(bytes(kdbx4), bytes(64))
    assert version.value.code == "kdbx_unsupported_version"


# ----------------------------------------------------------- the shipped client
def _run_client(*argv: str, cwd: Path) -> dict:
    """Run the *shipped* module as a script (what the sandbox actually executes)."""
    proc = subprocess.run(
        [sys.executable, "-c", client_source(), *argv],
        capture_output=True, text=True, cwd=cwd, timeout=300,
    )
    payloads = [line for line in proc.stdout.splitlines() if line.startswith("{")]
    assert payloads, proc.stdout + proc.stderr
    return json.loads(payloads[-1])


@pytest.fixture
def artifacts(tmp_path):
    """The synthetic artifacts written into a scratch workspace."""
    (tmp_path / "ProtectedUserKey.bin").write_bytes(
        fixture_bytes("synthetic_protected_user_key.b64"))
    (tmp_path / "Database.kdbx").write_bytes(fixture_bytes("synthetic_database.kdbx.b64"))
    (tmp_path / "synthetic_masterkey.hex").write_bytes(
        FIXTURES.joinpath("synthetic_masterkey.hex").read_bytes())
    return tmp_path


def test_shipped_client_unwraps_and_writes_the_material(artifacts):
    masterkey = masterkey_bytes().hex()
    payload = _run_client("unwrap", "ProtectedUserKey.bin", masterkey,
                          KEEPASS_ENTROPY_HEX, "material.bin", cwd=artifacts)
    assert payload["ok"] is True and payload["signature_verified"] is True
    assert payload["material_sha256"] == MATERIAL_SHA256
    assert (artifacts / "material.bin").read_bytes() == bytes.fromhex(payload["material_hex"])


def test_shipped_client_opens_the_database_through_the_material_file(artifacts):
    _run_client("unwrap", "ProtectedUserKey.bin", masterkey_bytes().hex(),
                KEEPASS_ENTROPY_HEX, "material.bin", cwd=artifacts)
    material_hex = (artifacts / "material.bin").read_bytes().hex()
    payload = _run_client("open_kdbx", "Database.kdbx", material_hex, "25", cwd=artifacts)
    assert payload["ok"] is True
    assert payload["flags"] == [SYNTHETIC_FLAG]
    assert payload["entry_count"] == 2


def test_shipped_client_reports_declared_negatives(artifacts):
    # Declared negative: without KeePass entropy the blob signature cannot verify.
    payload = _run_client("unwrap", "ProtectedUserKey.bin", masterkey_bytes().hex(), "-",
                          cwd=artifacts)
    assert payload["ok"] is False and payload["error"] == "dpapi_signature_invalid"
    payload = _run_client("open_kdbx", "Database.kdbx", "ab" * 64, cwd=artifacts)
    assert payload["ok"] is False and payload["error"] == "kdbx_credentials_invalid"
    payload = _run_client("rotate", "ProtectedUserKey.bin", cwd=artifacts)
    assert payload["ok"] is False and payload["error"] == "unsupported_action"


# ------------------------------------------------------------------ definition
def test_definition_is_offline_sandboxed_and_declares_its_effect():
    definition = dpapi_definition()
    assert definition.tool_id == "nexus.post.dpapi"
    assert definition.scope_required is False      # nothing is sent to a target
    assert definition.sandbox_required is True
    assert definition.effect == "credential_access"
    assert definition.risk.value == "medium"
    assert definition.idempotent is True
    assert definition.input_schema["properties"]["action"]["enum"] == ["unwrap", "open_kdbx"]


# --------------------------------------------------------------------- handler
class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(dpapi_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        yield sandbox


@pytest.fixture
def workspace(artifacts, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(artifacts))
    yield artifacts


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)),
                      run_id="run-dpapi-1")


def _run(arguments: dict) -> object:
    return asyncio.run(dpapi_handler(arguments, _context()))


def _sandbox_for(payload: dict) -> SandboxResult:
    return SandboxResult(0, json.dumps(payload) + "\n", "")


def test_handler_unwrap_ships_the_client_and_persists_the_material(workspace):
    payload = {"ok": True, "action": "unwrap", "material_hex": "ab" * 64,
               "material_b64": base64.b64encode(b"\xab" * 64).decode(),
               "material_sha256": hashlib.sha256(b"\xab" * 64).hexdigest(),
               "guid": "deee73a7b671664db4b8437e01749caa", "crypt_algo": "3des",
               "hash_algo": "sha1", "signature_verified": True,
               "session_key_variant": "manual-ipad-opad", "material_bytes": 64}
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run({"action": "unwrap", "blob_file": "ProtectedUserKey.bin",
                       "masterkey": masterkey_bytes().hex(), "entropy": KEEPASS_ENTROPY_HEX})
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert "dpapi_unwrap" in argv[2]           # the client's own source is shipped
    assert argv[3] == "unwrap" and argv[4].endswith("ProtectedUserKey.bin")
    assert argv[5] == masterkey_bytes().hex() and argv[6] == KEEPASS_ENTROPY_HEX
    assert result.verified is True and result.verification_method == "dpapi_unwrapped"
    assert result.evidence["material_sha256"] == payload["material_sha256"]
    assert result.evidence["signature_verified"] is True
    artifact = Path(result.evidence["artifact"])
    assert artifact.read_bytes() == b"\xab" * 64
    assert artifact.name == "dpapi_material_run-dpapi-1.bin"


def test_handler_open_kdbx_chains_off_the_material_artifact(workspace):
    material = b"\xcd" * 64
    (workspace / "material.bin").write_bytes(material)
    payload = {"ok": True, "action": "open_kdbx", "format": "kdbx3.1", "rounds": 60000,
               "groups": 2, "entry_count": 1, "truncated": False,
               "entries": [{"group": "Synthetic", "title": "Synthetic Wallet",
                            "username": "", "password": SYNTHETIC_FLAG, "url": "", "notes": ""}],
               "flags": [SYNTHETIC_FLAG]}
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run({"action": "open_kdbx", "kdbx_file": "Database.kdbx",
                       "material_file": "material.bin", "max_entries": 25})
    argv = sandbox.calls[0][0]
    assert argv[3] == "open_kdbx" and argv[5] == material.hex() and argv[6] == "25"
    assert result.verified is True and result.verification_method == "kdbx_opened"
    assert result.output["flags"] == [SYNTHETIC_FLAG]
    assert result.evidence["entry_count"] == 1 and result.evidence["rounds"] == 60000


def test_handler_never_spawns_subprocess_directly(workspace):
    payload = {"ok": True, "action": "unwrap", "material_hex": "ab" * 64,
               "material_b64": base64.b64encode(b"\xab" * 64).decode(),
               "material_sha256": "x", "signature_verified": True}
    with _fake_sandbox(_sandbox_for(payload)):
        with mock.patch(
            "asyncio.create_subprocess_exec",
            side_effect=AssertionError("handler must not spawn subprocesses directly"),
        ):
            _run({"action": "unwrap", "blob_file": "ProtectedUserKey.bin",
                  "masterkey": masterkey_bytes().hex()})


def test_handler_reports_the_declared_negatives(workspace):
    payload = {"ok": False, "error": "dpapi_signature_invalid", "detail": "padding"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"action": "unwrap", "blob_file": "ProtectedUserKey.bin",
                       "masterkey": masterkey_bytes().hex()})
    assert result.verified is False
    assert result.verification_method == "dpapi_signature_invalid"
    assert result.evidence["client_error"] == "dpapi_signature_invalid"

    payload = {"ok": False, "error": "kdbx_credentials_invalid", "detail": "stream start"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run({"action": "open_kdbx", "kdbx_file": "Database.kdbx",
                       "material": "ab" * 64})
    assert result.verified is False
    assert result.verification_method == "kdbx_credentials_invalid"


def test_handler_timeout_is_not_verified(workspace):
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run({"action": "unwrap", "blob_file": "ProtectedUserKey.bin",
                       "masterkey": masterkey_bytes().hex()})
    assert result.verified is False and result.verification_method == "dpapi_timeout"
    assert result.timed_out is True


# ------------------------------------------------------------------- validation
def test_unsupported_action_and_missing_files_are_refused(workspace):
    with pytest.raises(ValueError):
        _run({"action": "protect", "blob_file": "ProtectedUserKey.bin"})
    with pytest.raises(ValueError):
        _run({"action": "unwrap", "masterkey": masterkey_bytes().hex()})
    with pytest.raises(ValueError):
        _run({"action": "unwrap", "blob_file": "nope.bin",
              "masterkey": masterkey_bytes().hex()})
    with pytest.raises(ValueError):
        _run({"action": "open_kdbx", "kdbx_file": "Database.kdbx"})


@pytest.mark.parametrize("bad", ["zz", "abc", "0x", ""])
def test_masterkey_must_be_even_length_hex(workspace, bad):
    with pytest.raises(ValueError):
        _run({"action": "unwrap", "blob_file": "ProtectedUserKey.bin", "masterkey": bad})


def test_material_outside_the_workspace_is_refused(workspace, tmp_path):
    outside = tmp_path.parent / "outside-material.bin"
    outside.write_bytes(b"\x01" * 64)
    with pytest.raises(ValueError):
        _run({"action": "open_kdbx", "kdbx_file": "Database.kdbx",
              "material_file": "../outside-material.bin"})


# ------------------------------------------------- deterministic verifier promotion
def test_verifier_promotes_the_flag_and_the_credential_from_an_opened_kdbx(tmp_path, monkeypatch):
    from nexus_core.kernel.fact_verification import derive_assertions
    from nexus_core.kernel.models import ToolResult
    from nexus_core.kernel.secret_store import default_secret_store

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    context = SimpleNamespace(invocation_id="i", run_id="r")
    result = ToolResult(
        output={
            "action": "open_kdbx",
            "entries": [
                {"group": "Synthetic", "title": "Synthetic Wallet",
                 "username": "", "password": SYNTHETIC_FLAG, "url": "", "notes": ""},
                {"group": "Database", "title": "VPN", "username": "synthetic-user",
                 "password": "s3cret", "url": "", "notes": ""},
            ],
        },
        verified=True,
        verification_method="kdbx_opened",
    )
    facts = derive_assertions("nexus.post.dpapi", {}, result, context)
    assert {fact["fact_type"] for fact in facts} == {"credential", "loot"}
    loot = [fact for fact in facts if fact["fact_type"] == "loot"]
    assert [fact["value"]["flag"] for fact in loot] == [SYNTHETIC_FLAG]
    credentials = [fact for fact in facts if fact["fact_type"] == "credential"]
    assert {fact["key"] for fact in credentials} == {
        "keepass:Synthetic/Synthetic Wallet", "keepass:Database/VPN",
    }
    # The vault entry never carries the plaintext (V1-29), not even for a handler
    # that still returns it: the verifier stores it and asserts the handle.
    assert all("password" not in fact["value"] for fact in credentials)
    handles = {fact["value"]["secret_ref"] for fact in credentials}
    assert all(handle and handle.startswith("vault:") for handle in handles)
    vault = default_secret_store()
    assert {vault.get(handle) for handle in handles} == {SYNTHETIC_FLAG.encode(), b"s3cret"}


def test_verifier_promotes_the_recovered_key_material_as_a_credential():
    from nexus_core.kernel.fact_verification import derive_assertions
    from nexus_core.kernel.models import ToolResult

    context = SimpleNamespace(invocation_id="i", run_id="r")
    result = ToolResult(
        output={"action": "unwrap", "master_key_guid": "deee73a7b671664db4b8437e01749caa",
                "material_sha256": MATERIAL_SHA256, "crypt_algo": "3des"},
        verified=True,
        verification_method="dpapi_unwrapped",
    )
    facts = derive_assertions("nexus.post.dpapi", {}, result, context)
    assert [fact["fact_type"] for fact in facts] == ["credential"]
    assert facts[0]["value"]["material_sha256"] == MATERIAL_SHA256
