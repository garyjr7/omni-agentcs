"""Standalone DPAPI / KDBX 3.1 loot client (stdlib only) shipped into the sandbox.

Why it exists (a synthetic lab run · deuda V0-39): the room's last flag lives in
the KeePass database of a user and the *database key* is wrapped in **user-scope
DPAPI** (``ProtectedUserKey.bin``, itself decrypted with the user's DPAPI
masterkey, which needs the domain backup key). Reaching that flag took three steps
that no governed tool covered — ``impacket-dpapi`` + ``dploot`` + ``pykeepass`` by
hand — so the loot was obtained but never *accredited* by the engine, and every
Windows room with a DPAPI-protected secret store pays the same tax again.

Nothing here needs a network: both blobs are already-exfiltrated artifacts, so the
tool is an offline computation over the engagement workspace. To stay runnable in
any sandbox image (this repo ships stdlib-only clients: TFTP, DNS, the ADIDNS
updater) the three primitives are implemented here rather than imported:

* **DES/3DES** — DPAPI user blobs are still written with ``CALG_3DES`` (measured:
  the synthetic lab blob declares ``CryptAlgo=0x6603`` with 72 bytes of ciphertext).
* **AES-128/192/256** — KDBX 3.x uses AES-ECB for its key-derivation rounds and
  AES-CBC for the payload.
* **Salsa20** — KDBX 3.x protects individual values with a Salsa20 keystream.

Formats implemented (both documented by their reference implementations, which is
what the tests cross-check against):

* DPAPI blob (``CryptProtectData`` output) — SHA1/SHA512 HMAC session key, the
  impacket/dploot field order, PKCS#7 padding, signature verification.
* KDBX 3.1 — header fields, ``SHA256(AES-ECB^rounds(composite))`` transformed key,
  ``SHA256(master_seed || transformed_key)`` payload key, hashed block stream,
  gzip compression and the Salsa20-protected values.

The client prints exactly one JSON object on stdout::

    python3 dpapi_client.py unwrap    <blob> <masterkey_hex> <entropy_hex|-> [out]
    python3 dpapi_client.py open_kdbx <kdbx> <material_hex> <max_entries> [out]
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import struct
import sys
from xml.etree import ElementTree as ET

#: Hard bounds so a hostile artifact cannot make the tool allocate forever.
MAX_BLOB_BYTES = 4 << 20
MAX_KDBX_BYTES = 64 << 20
MAX_ENTRIES = 500
MAX_FIELD_CHARS = 512
#: KDBX transform rounds are a KDF cost parameter; 60000 is KeePass' default.
MAX_KDBX_ROUNDS = 5_000_000

CIPHER_AES = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
KEEPASS_ENTROPY = bytes.fromhex("de135b5f18a34670b2572429698898e6")


class LootError(Exception):
    """A declared negative: the artifact is well-formed enough to classify."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# DES / 3DES (FIPS 46-3 tables)
# --------------------------------------------------------------------------

_IP = (
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
)
_FP = (
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
)
_E = (
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23,
    24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
)
_P = (
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
)
_PC1 = (
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
    61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
)
_PC2 = (
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

_SBOXES = (
    (
        (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7),
        (0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8),
        (4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0),
        (15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    ),
    (
        (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10),
        (3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5),
        (0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15),
        (13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    ),
    (
        (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8),
        (13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1),
        (13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7),
        (1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    ),
    (
        (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15),
        (13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9),
        (10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4),
        (3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    ),
    (
        (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9),
        (14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6),
        (4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14),
        (11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    ),
    (
        (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11),
        (10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8),
        (9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6),
        (4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    ),
    (
        (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1),
        (13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6),
        (1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2),
        (6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    ),
    (
        (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7),
        (1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2),
        (7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8),
        (2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
    ),
)


def _permute(value: int, table: tuple[int, ...], in_bits: int) -> int:
    """Return ``value`` with its bits permuted by ``table`` (1-based, MSB first)."""
    out = 0
    for position in table:
        out = (out << 1) | ((value >> (in_bits - position)) & 1)
    return out


def _des_subkeys(key: bytes) -> list[int]:
    """Return the 16 round subkeys of one 8-byte DES key."""
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    state = _permute(int.from_bytes(key, "big"), _PC1, 64)
    left, right = state >> 28, state & 0xFFFFFFF
    subkeys = []
    for shift in _SHIFTS:
        left = ((left << shift) | (left >> (28 - shift))) & 0xFFFFFFF
        right = ((right << shift) | (right >> (28 - shift))) & 0xFFFFFFF
        subkeys.append(_permute((left << 28) | right, _PC2, 56))
    return subkeys


def _des_feistel(right: int, subkey: int) -> int:
    """The DES ``f`` function: expand, xor the subkey, substitute, permute."""
    mixed = _permute(right, _E, 32) ^ subkey
    out = 0
    for index in range(8):
        chunk = (mixed >> (42 - 6 * index)) & 0x3F
        row = ((chunk >> 4) & 0x2) | (chunk & 0x1)
        column = (chunk >> 1) & 0xF
        out = (out << 4) | _SBOXES[index][row][column]
    return _permute(out, _P, 32)


def _des_block(block: int, subkeys: list[int], *, decrypt: bool) -> int:
    """Encrypt or decrypt one 64-bit block with a precomputed key schedule."""
    permuted = _permute(block, _IP, 64)
    left, right = permuted >> 32, permuted & 0xFFFFFFFF
    for subkey in (reversed(subkeys) if decrypt else subkeys):
        left, right = right, left ^ _des_feistel(right, subkey)
    return _permute((right << 32) | left, _FP, 64)


def _des3_block(block: int, schedules: list[list[int]], *, decrypt: bool) -> int:
    """One ``E``-``D``-``E`` 3DES block with three independent key schedules."""
    first, second, third = schedules
    if decrypt:
        value = _des_block(block, third, decrypt=True)
        value = _des_block(value, second, decrypt=False)
        return _des_block(value, first, decrypt=True)
    value = _des_block(block, first, decrypt=False)
    value = _des_block(value, second, decrypt=True)
    return _des_block(value, third, decrypt=False)


# --------------------------------------------------------------------------
# AES (FIPS 197)
# --------------------------------------------------------------------------

def _build_sbox() -> list[int]:
    """Build the AES S-box from its algebraic definition (no magic table)."""
    sbox = [0] * 256
    p, q = 1, 1
    while True:
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        x = (q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6))
             ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))) & 0xFF
        sbox[p] = x ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _build_sbox()
_INV_SBOX = [0] * 256
for _index, _value in enumerate(_SBOX):
    _INV_SBOX[_value] = _index


def _gmul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) with the AES polynomial 0x11B."""
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return product


#: Precomputed GF(2^8) products: the KDBX key derivation applies AES-ECB 60.000
#: times over a 32-byte buffer, so the per-byte multiplications have to be lookups.
_MUL2 = [_gmul(value, 2) for value in range(256)]
_MUL3 = [_gmul(value, 3) for value in range(256)]

def _rotate_word(word: int, count: int) -> int:
    """Rotate a 32-bit word left by ``count`` bytes (T-table construction)."""
    return ((word << (8 * count)) | (word >> (32 - 8 * count))) & 0xFFFFFFFF


def _build_t_tables() -> tuple[tuple[int, ...], ...]:
    """Build the four T tables used by the fast AES encryption path."""
    base = [
        ((_MUL2[_SBOX[i]] << 24) | (_SBOX[i] << 16) | (_SBOX[i] << 8) | _MUL3[_SBOX[i]])
        for i in range(256)
    ]
    te1 = [_rotate_word(word, 1) for word in base]
    te2 = [_rotate_word(word, 2) for word in base]
    te3 = [_rotate_word(word, 3) for word in base]
    return tuple(base), tuple(te1), tuple(te2), tuple(te3)


_TE0, _TE1, _TE2, _TE3 = _build_t_tables()


def aes_round_words(round_keys: list[bytes]) -> list[list[int]]:
    """Return the AES round keys as big-endian 32-bit words (T-table layout)."""
    return [list(struct.unpack(">4I", key)) for key in round_keys]


def aes_encrypt_block_fast(block: bytes, round_words: list[list[int]]) -> bytes:
    """Encrypt one block with the T-table path (used by the KDBX KDF loop)."""
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    key = round_words[0]
    s0 ^= key[0]
    s1 ^= key[1]
    s2 ^= key[2]
    s3 ^= key[3]
    # Per output word the four input bytes enter with weights (2,3,1,1), (1,2,3,1),
    # (1,1,2,3) and (3,1,1,2) — i.e. the rotations are consumed in descending order.
    for index in range(1, len(round_words) - 1):
        key = round_words[index]
        t0 = (_TE0[s0 >> 24] ^ _TE3[(s1 >> 16) & 0xFF] ^ _TE2[(s2 >> 8) & 0xFF]
              ^ _TE1[s3 & 0xFF] ^ key[0])
        t1 = (_TE0[s1 >> 24] ^ _TE3[(s2 >> 16) & 0xFF] ^ _TE2[(s3 >> 8) & 0xFF]
              ^ _TE1[s0 & 0xFF] ^ key[1])
        t2 = (_TE0[s2 >> 24] ^ _TE3[(s3 >> 16) & 0xFF] ^ _TE2[(s0 >> 8) & 0xFF]
              ^ _TE1[s1 & 0xFF] ^ key[2])
        t3 = (_TE0[s3 >> 24] ^ _TE3[(s0 >> 16) & 0xFF] ^ _TE2[(s1 >> 8) & 0xFF]
              ^ _TE1[s2 & 0xFF] ^ key[3])
        s0, s1, s2, s3 = t0, t1, t2, t3
    key = round_words[-1]
    box = _SBOX
    a0, a1, a2, a3 = s0, s1, s2, s3
    s0 = ((box[a0 >> 24] << 24) | (box[(a1 >> 16) & 0xFF] << 16)
          | (box[(a2 >> 8) & 0xFF] << 8) | box[a3 & 0xFF])
    s1 = ((box[a1 >> 24] << 24) | (box[(a2 >> 16) & 0xFF] << 16)
          | (box[(a3 >> 8) & 0xFF] << 8) | box[a0 & 0xFF])
    s2 = ((box[a2 >> 24] << 24) | (box[(a3 >> 16) & 0xFF] << 16)
          | (box[(a0 >> 8) & 0xFF] << 8) | box[a1 & 0xFF])
    s3 = ((box[a3 >> 24] << 24) | (box[(a0 >> 16) & 0xFF] << 16)
          | (box[(a1 >> 8) & 0xFF] << 8) | box[a2 & 0xFF])
    return struct.pack(">4I", s0 ^ key[0], s1 ^ key[1], s2 ^ key[2], s3 ^ key[3])


def _aes_expand(key: bytes) -> tuple[list[bytes], int]:
    """Return ``(round_keys, rounds)`` for a 16/24/32-byte AES key."""
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[byte] for byte in temp]
            temp[0] ^= rcon
            rcon = ((rcon << 1) ^ (0x1B if rcon & 0x80 else 0)) & 0xFF
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[byte] for byte in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    keys = [
        bytes(byte for word in words[4 * r:4 * r + 4] for byte in word)
        for r in range(rounds + 1)
    ]
    return keys, rounds


def _aes_add_round_key(state: list[int], round_key: bytes) -> list[int]:
    return [state[i] ^ round_key[i] for i in range(16)]


def _aes_shift_rows(state: list[int]) -> list[int]:
    return [state[4 * ((i // 4 + i % 4) % 4) + i % 4] for i in range(16)]


def _aes_inv_shift_rows(state: list[int]) -> list[int]:
    return [state[4 * ((i // 4 - i % 4) % 4) + i % 4] for i in range(16)]


def _aes_mix_columns(state: list[int]) -> list[int]:
    out = [0] * 16
    for column in range(4):
        a = state[4 * column:4 * column + 4]
        out[4 * column + 0] = _gmul(a[0], 2) ^ _gmul(a[1], 3) ^ a[2] ^ a[3]
        out[4 * column + 1] = a[0] ^ _gmul(a[1], 2) ^ _gmul(a[2], 3) ^ a[3]
        out[4 * column + 2] = a[0] ^ a[1] ^ _gmul(a[2], 2) ^ _gmul(a[3], 3)
        out[4 * column + 3] = _gmul(a[0], 3) ^ a[1] ^ a[2] ^ _gmul(a[3], 2)
    return out


def _aes_inv_mix_columns(state: list[int]) -> list[int]:
    out = [0] * 16
    for column in range(4):
        a = state[4 * column:4 * column + 4]
        out[4 * column + 0] = (_gmul(a[0], 14) ^ _gmul(a[1], 11)
                               ^ _gmul(a[2], 13) ^ _gmul(a[3], 9))
        out[4 * column + 1] = (_gmul(a[0], 9) ^ _gmul(a[1], 14)
                               ^ _gmul(a[2], 11) ^ _gmul(a[3], 13))
        out[4 * column + 2] = (_gmul(a[0], 13) ^ _gmul(a[1], 9)
                               ^ _gmul(a[2], 14) ^ _gmul(a[3], 11))
        out[4 * column + 3] = (_gmul(a[0], 11) ^ _gmul(a[1], 13)
                               ^ _gmul(a[2], 9) ^ _gmul(a[3], 14))
    return out


def aes_encrypt_block(block: bytes, keys: list[bytes], rounds: int) -> bytes:
    """Encrypt one 16-byte block (ECB building block)."""
    state = _aes_add_round_key(list(block), keys[0])
    for round_number in range(1, rounds):
        state = [_SBOX[byte] for byte in state]
        state = _aes_shift_rows(state)
        state = _aes_mix_columns(state)
        state = _aes_add_round_key(state, keys[round_number])
    state = [_SBOX[byte] for byte in state]
    state = _aes_shift_rows(state)
    return bytes(_aes_add_round_key(state, keys[rounds]))


def aes_decrypt_block(block: bytes, keys: list[bytes], rounds: int) -> bytes:
    """Decrypt one 16-byte block (CBC building block)."""
    state = _aes_add_round_key(list(block), keys[rounds])
    for round_number in range(rounds - 1, 0, -1):
        state = _aes_inv_shift_rows(state)
        state = [_INV_SBOX[byte] for byte in state]
        state = _aes_add_round_key(state, keys[round_number])
        state = _aes_inv_mix_columns(state)
    state = _aes_inv_shift_rows(state)
    state = [_INV_SBOX[byte] for byte in state]
    return bytes(_aes_add_round_key(state, keys[0]))


# --------------------------------------------------------------------------
# Salsa20 (KDBX protected stream)
# --------------------------------------------------------------------------

def _rotl32(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def _salsa20_rounds(state: list[int], double_rounds: int = 10) -> list[int]:
    """Run the Salsa20 core (``double_rounds`` × 2 rounds) in place and add."""
    x = list(state)
    for _ in range(double_rounds):
        x[4] ^= _rotl32((x[0] + x[12]) & 0xFFFFFFFF, 7)
        x[8] ^= _rotl32((x[4] + x[0]) & 0xFFFFFFFF, 9)
        x[12] ^= _rotl32((x[8] + x[4]) & 0xFFFFFFFF, 13)
        x[0] ^= _rotl32((x[12] + x[8]) & 0xFFFFFFFF, 18)
        x[9] ^= _rotl32((x[5] + x[1]) & 0xFFFFFFFF, 7)
        x[13] ^= _rotl32((x[9] + x[5]) & 0xFFFFFFFF, 9)
        x[1] ^= _rotl32((x[13] + x[9]) & 0xFFFFFFFF, 13)
        x[5] ^= _rotl32((x[1] + x[13]) & 0xFFFFFFFF, 18)
        x[14] ^= _rotl32((x[10] + x[6]) & 0xFFFFFFFF, 7)
        x[2] ^= _rotl32((x[14] + x[10]) & 0xFFFFFFFF, 9)
        x[6] ^= _rotl32((x[2] + x[14]) & 0xFFFFFFFF, 13)
        x[10] ^= _rotl32((x[6] + x[2]) & 0xFFFFFFFF, 18)
        x[3] ^= _rotl32((x[15] + x[11]) & 0xFFFFFFFF, 7)
        x[7] ^= _rotl32((x[3] + x[15]) & 0xFFFFFFFF, 9)
        x[11] ^= _rotl32((x[7] + x[3]) & 0xFFFFFFFF, 13)
        x[15] ^= _rotl32((x[11] + x[7]) & 0xFFFFFFFF, 18)
        # column round
        x[1] ^= _rotl32((x[0] + x[3]) & 0xFFFFFFFF, 7)
        x[2] ^= _rotl32((x[1] + x[0]) & 0xFFFFFFFF, 9)
        x[3] ^= _rotl32((x[2] + x[1]) & 0xFFFFFFFF, 13)
        x[0] ^= _rotl32((x[3] + x[2]) & 0xFFFFFFFF, 18)
        x[6] ^= _rotl32((x[5] + x[4]) & 0xFFFFFFFF, 7)
        x[7] ^= _rotl32((x[6] + x[5]) & 0xFFFFFFFF, 9)
        x[4] ^= _rotl32((x[7] + x[6]) & 0xFFFFFFFF, 13)
        x[5] ^= _rotl32((x[4] + x[7]) & 0xFFFFFFFF, 18)
        x[11] ^= _rotl32((x[10] + x[9]) & 0xFFFFFFFF, 7)
        x[8] ^= _rotl32((x[11] + x[10]) & 0xFFFFFFFF, 9)
        x[9] ^= _rotl32((x[8] + x[11]) & 0xFFFFFFFF, 13)
        x[10] ^= _rotl32((x[9] + x[8]) & 0xFFFFFFFF, 18)
        x[12] ^= _rotl32((x[15] + x[14]) & 0xFFFFFFFF, 7)
        x[13] ^= _rotl32((x[12] + x[15]) & 0xFFFFFFFF, 9)
        x[14] ^= _rotl32((x[13] + x[12]) & 0xFFFFFFFF, 13)
        x[15] ^= _rotl32((x[14] + x[13]) & 0xFFFFFFFF, 18)
    return [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]


class Salsa20:
    """Salsa20/20 keystream generator (8-byte nonce, 64-bit block counter)."""

    def __init__(self, key: bytes, nonce: bytes) -> None:
        if len(key) != 32 or len(nonce) != 8:
            raise ValueError("Salsa20 needs a 32-byte key and an 8-byte nonce")
        self._key = list(struct.unpack("<8I", key))
        self._nonce = list(struct.unpack("<2I", nonce))
        self._counter = 0
        self._buffer = b""

    def _block(self) -> bytes:
        # Salsa20 state layout: c0 k0 k1 k2 k3 c1 n0 n1 c2 b0 b1 k4 k5 k6 k7 c3
        state = (
            [0x61707865]
            + self._key[:4]
            + [0x3320646E]
            + self._nonce
            + [self._counter & 0xFFFFFFFF, (self._counter >> 32) & 0xFFFFFFFF]
            + [0x79622D32]
            + self._key[4:]
            + [0x6B206574]
        )
        self._counter += 1
        return struct.pack("<16I", *_salsa20_rounds(state))

    def keystream(self, length: int) -> bytes:
        """Return ``length`` keystream bytes (the caller consumes them)."""
        while len(self._buffer) < length:
            self._buffer += self._block()
        out, self._buffer = self._buffer[:length], self._buffer[length:]
        return out

    def decrypt(self, data: bytes) -> bytes:
        """XOR ``data`` with the keystream (encryption and decryption differ only
        by which side of the XOR the caller keeps)."""
        return bytes(a ^ b for a, b in zip(data, self.keystream(len(data))))


# --------------------------------------------------------------------------
# DPAPI blob
# --------------------------------------------------------------------------

#: Mirrors impacket's ``ALGORITHMS_DATA`` numbers: (hash name, key length, block).
_HASH_ALGOS = {
    0x8004: ("sha1", 20, 64),     # CALG_SHA
    0x8009: ("sha512", 20, 64),   # CALG_HMAC
    0x800C: ("sha512", 16, 128),  # CALG_SHA_512
}
#: Mirrors impacket's ``ALGORITHMS_DATA`` ciphers: (name, key bytes, block bytes).
_CIPHER_ALGOS = {
    0x6603: ("3des", 24, 8),    # CALG_3DES
    0x660E: ("aes256", 32, 16),  # CALG_AES_256
    0x660F: ("aes128", 16, 16),  # CALG_AES_128
    0x6610: ("aes192", 24, 16),  # CALG_AES_192
}


def parse_dpapi_blob(raw: bytes) -> dict:
    """Parse a ``CryptProtectData`` blob into its fields (impacket field order)."""
    if len(raw) > MAX_BLOB_BYTES:
        raise LootError("dpapi_blob_too_large", f"{len(raw)} bytes")
    offset = 0

    def take(count: int, what: str) -> bytes:
        nonlocal offset
        if offset + count > len(raw):
            raise LootError("dpapi_blob_truncated", f"while reading {what}")
        value = raw[offset:offset + count]
        offset += count
        return value

    def u32(what: str) -> int:
        return struct.unpack("<I", take(4, what))[0]

    version = u32("version")
    provider = take(16, "provider guid")
    blob = {
        "version": version,
        "provider_guid": provider.hex(),
        "master_key_version": u32("master key version"),
        "master_key_guid": take(16, "master key guid").hex(),
        "flags": u32("flags"),
    }
    description_length = u32("description length")
    blob["description"] = take(description_length, "description").decode("utf-16le", "replace")
    blob["crypt_algo"] = u32("crypt algo")
    blob["crypt_algo_len"] = u32("crypt algo length")
    salt_length = u32("salt length")
    blob["salt"] = take(salt_length, "salt")
    blob["hmac_key"] = take(u32("hmac key length"), "hmac key")
    blob["hash_algo"] = u32("hash algo")
    blob["hash_algo_len"] = u32("hash algo length")
    blob["hmac"] = take(u32("hmac length"), "hmac")
    blob["data"] = take(u32("data length"), "data")
    blob["sign"] = take(u32("sign length"), "sign")
    if offset != len(raw):
        raise LootError("dpapi_blob_trailing_bytes", f"{len(raw) - offset} bytes left")
    if blob["version"] != 1:
        raise LootError("dpapi_unsupported_version", f"version={blob['version']}")
    if blob["crypt_algo"] not in _CIPHER_ALGOS:
        raise LootError("dpapi_unsupported_cipher", f"alg={blob['crypt_algo']:#x}")
    if blob["hash_algo"] not in _HASH_ALGOS:
        raise LootError("dpapi_unsupported_hash", f"alg={blob['hash_algo']:#x}")
    if not blob["salt"] or not blob["sign"]:
        raise LootError("dpapi_blob_incomplete", "missing salt or signature")
    blob["raw"] = raw
    blob["crypt_name"], blob["key_len"], blob["block_size"] = _CIPHER_ALGOS[blob["crypt_algo"]]
    blob["hash_name"], blob["hash_key_len"], blob["hash_block"] = _HASH_ALGOS[blob["hash_algo"]]
    return blob


def _session_key_variant(key_hash: bytes, salt: bytes, blob: dict,
                         tail: bytes, *, manual: bool) -> bytes:
    """One of the two keyed-hash conventions impacket/dploot try, in that order.

    Both are used twice with the same shape: for the session key the *salt* is the
    blob's salt field and the *tail* is the entropy; for the signature the salt is
    the blob's HMac field and the tail is ``entropy + <everything before Sign>``.
    The tail always comes last, which is why it is a separate argument.
    """
    hash_name = blob["hash_name"]
    if manual:
        block = blob["hash_block"]
        padded = key_hash + b"\x00" * max(0, block - len(key_hash))
        ipad = bytes(byte ^ 0x36 for byte in padded[:block])
        opad = bytes(byte ^ 0x5C for byte in padded[:block])
        inner = hashlib.new(hash_name, ipad + salt).digest()
        return hashlib.new(hash_name, opad + inner + tail).digest()
    return hmac.new(key_hash, salt + tail, hash_name).digest()


def _fix_des_parity(data: bytes) -> bytes:
    """Set the low bit of every byte so it holds an odd number of 1 bits.

    The extension below yields a 40-byte blob that impacket then feeds to a DES
    key schedule, which ignores the parity bit; the adjustment still changes the
    *bytes* of the key material and therefore the derived key, so it has to be
    reproduced exactly.
    """
    out = bytearray()
    for byte in data:
        high = byte >> 1
        low = 0 if bin(high).count("1") % 2 else 1
        out.append((high << 1) | low)
    return bytes(out)


def _derive_cipher_key(session_key: bytes, blob: dict) -> bytes:
    """impacket's ``deriveKey``: HMAC when too long, ipad/opad when too short."""
    if len(session_key) > blob["hash_key_len"]:
        derived = hmac.new(session_key, digestmod=blob["hash_name"]).digest()
    else:
        derived = session_key
    if len(derived) < blob["key_len"]:
        block = blob["hash_block"]
        padded = derived + b"\x00" * block
        ipad = bytes(byte ^ 0x36 for byte in padded[:block])
        opad = bytes(byte ^ 0x5C for byte in padded[:block])
        derived = _fix_des_parity(
            hashlib.new(blob["hash_name"], ipad).digest()
            + hashlib.new(blob["hash_name"], opad).digest()
        )
    return derived


def _decrypt_blocks(ciphertext: bytes, key: bytes, iv: bytes, blob: dict) -> bytes:
    """Block-cipher decrypt (CBC) with the blob's own algorithm."""
    block_size = blob["block_size"]
    if len(ciphertext) % block_size:
        raise LootError("dpapi_ciphertext_misaligned", f"{len(ciphertext)} bytes")
    from_des = blob["crypt_name"] == "3des"
    if from_des:
        schedules = [_des_subkeys(key[i:i + 8]) for i in range(0, 24, 8)]

        def decrypt_block(chunk: bytes) -> bytes:
            return _des3_block(int.from_bytes(chunk, "big"), schedules,
                               decrypt=True).to_bytes(8, "big")
    else:
        round_keys, rounds = _aes_expand(key)

        def decrypt_block(chunk: bytes) -> bytes:
            return aes_decrypt_block(chunk, round_keys, rounds)
    out = bytearray()
    previous = iv
    for start in range(0, len(ciphertext), block_size):
        chunk = ciphertext[start:start + block_size]
        plain = decrypt_block(chunk)
        out.extend(a ^ b for a, b in zip(plain, previous))
        previous = chunk
    return bytes(out)


def _strip_pkcs7(data: bytes, block_size: int) -> bytes:
    """Remove PKCS#7 padding; a bad pad is a declared negative, never silent."""
    if not data or len(data) % block_size:
        raise LootError("dpapi_padding_invalid", "length is not block-aligned")
    padding = data[-1]
    if padding == 0 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise LootError("dpapi_padding_invalid", "PKCS#7 padding is corrupt")
    return data[:-padding]


def dpapi_unwrap(raw: bytes, masterkey: bytes, entropy: bytes = b"") -> dict:
    """Decrypt a DPAPI user blob and *verify its signature*.

    Returns the cleartext plus which session-key convention and cipher matched, so
    the caller can report what was actually proved instead of what was attempted.
    The signature is checked with the masterkey-derived HMAC: a blob that decrypts
    to something plausible but does not sign correctly is refused.
    """
    blob = parse_dpapi_blob(raw)
    key_hash = hashlib.sha1(masterkey).digest()
    failures: list[str] = []
    for manual in (True, False):
        session_key = _session_key_variant(key_hash, blob["salt"], blob, entropy, manual=manual)
        derived = _derive_cipher_key(session_key, blob)
        try:
            cleartext = _decrypt_blocks(
                blob["data"], derived[:blob["key_len"]], b"\x00" * blob["block_size"], blob
            )
            cleartext = _strip_pkcs7(cleartext, blob["block_size"])
        except LootError as exc:
            failures.append(f"{'manual' if manual else 'hmac'}: {exc.code}")
            continue
        to_sign = raw[20:len(raw) - len(blob["sign"]) - 4]
        expected = _session_key_variant(
            key_hash, blob["hmac"], blob, entropy + to_sign, manual=manual
        )
        if not hmac.compare_digest(expected, blob["sign"]):
            failures.append(f"{'manual' if manual else 'hmac'}: signature mismatch")
            continue
        return {
            "cleartext": cleartext,
            "guid": blob["master_key_guid"],
            "crypt_algo": blob["crypt_name"],
            "hash_algo": blob["hash_name"],
            "flags": blob["flags"],
            "signature_verified": True,
            "session_key_variant": "manual-ipad-opad" if manual else "hmac",
            "ciphertext_bytes": len(blob["data"]),
        }
    raise LootError("dpapi_signature_invalid", "; ".join(failures) or "no convention matched")


# --------------------------------------------------------------------------
# KDBX 3.x
# --------------------------------------------------------------------------

KDBX3_SIGNATURE = bytes.fromhex("03d9a29a67fb4bb5")
INNER_STREAM_SALSA20 = 2
#: KeePassLib/Cryptography/CryptoRandomStream.cs :: Salsa20 nonce (first 8 IV bytes
#: are zero). The keystream is consumed from its first byte, in document order.
KEEPASS_SALSA20_NONCE = bytes.fromhex("e830094b97205d2a")


def _kdbx_header(data: bytes) -> tuple[dict, int, int, int]:
    """Return ``(fields, payload_offset, major, minor)`` for a KDBX file."""
    if len(data) < 12 or data[:8] != KDBX3_SIGNATURE:
        raise LootError("kdbx_bad_signature", "not a KDBX file")
    # The version word is stored minor-first: 0x00030001 (KDBX 3.1).
    minor, major = struct.unpack_from("<HH", data, 8)
    if major != 3:
        raise LootError("kdbx_unsupported_version", f"{major}.{minor}")
    if minor != 1:
        # KDBX 3.0 used 32-bit header field lengths; refuse instead of mis-parsing.
        raise LootError("kdbx_unsupported_version", f"3.{minor} uses 32-bit fields")
    fields: dict[int, bytes] = {}
    offset = 12
    while True:
        if offset + 3 > len(data):
            raise LootError("kdbx_header_truncated", "no end-of-header marker")
        tag, size = struct.unpack_from("<BH", data, offset)
        offset += 3
        if offset + size > len(data):
            raise LootError("kdbx_header_truncated", f"field {tag}")
        fields[tag] = data[offset:offset + size]
        offset += size
        if tag == 0:
            break
    if fields.get(2) != CIPHER_AES:
        raise LootError("kdbx_unsupported_cipher", (fields.get(2) or b"").hex())
    return fields, offset, major, minor


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    keys, rounds = _aes_expand(key)
    if len(ciphertext) % 16:
        raise LootError("kdbx_payload_misaligned", f"{len(ciphertext)} bytes")
    out = bytearray()
    previous = iv
    for start in range(0, len(ciphertext), 16):
        chunk = ciphertext[start:start + 16]
        out.extend(a ^ b for a, b in zip(aes_decrypt_block(chunk, keys, rounds), previous))
        previous = chunk
    return bytes(out)


def _kdbx_transformed_key(fields: dict, composite: bytes) -> tuple[bytes, int, bytes]:
    """Return ``(payload_key, rounds, stream_start_bytes)`` for the KDBX payload."""
    transform_seed = fields.get(5)
    master_seed = fields.get(4)
    stream_start = fields.get(9)
    if not transform_seed or not master_seed or not stream_start:
        raise LootError("kdbx_header_incomplete", "missing seed or stream start bytes")
    rounds = struct.unpack("<Q", fields.get(6) or b"\x00" * 8)[0]
    if rounds <= 0 or rounds > MAX_KDBX_ROUNDS:
        raise LootError("kdbx_rounds_out_of_range", str(rounds))
    round_keys, _ = _aes_expand(transform_seed)
    words = aes_round_words(round_keys)
    transformed = composite
    for _ in range(rounds):
        # ECB over the whole 32-byte buffer: KeePass encrypts both halves per round.
        transformed = (aes_encrypt_block_fast(transformed[:16], words)
                       + aes_encrypt_block_fast(transformed[16:], words))
    transformed = hashlib.sha256(transformed).digest()
    # KeePass 2.x: the payload key mixes the header master seed *after* the KDF.
    return hashlib.sha256(master_seed + transformed).digest(), rounds, stream_start


def _kdbx_blocks(payload: bytes) -> bytes:
    """Return the concatenated hashed blocks of a decrypted KDBX payload."""
    offset = 0
    expected_index = 0
    chunks: list[bytes] = []
    while True:
        if offset + 40 > len(payload):
            raise LootError("kdbx_block_truncated", f"at {offset}")
        index, digest, size = struct.unpack_from("<I32sI", payload, offset)
        offset += 40
        if offset + size > len(payload):
            raise LootError("kdbx_block_truncated", f"block {index}")
        block = payload[offset:offset + size]
        offset += size
        if size == 0:
            if digest != bytes(32) or index != expected_index:
                raise LootError("kdbx_block_terminator_invalid", f"index={index}")
            break
        if index != expected_index:
            raise LootError("kdbx_block_index_invalid", f"expected {expected_index}, got {index}")
        if hashlib.sha256(block).digest() != digest:
            raise LootError("kdbx_block_hash_invalid", f"block {index}")
        chunks.append(block)
        expected_index += 1
    return b"".join(chunks)


def _kdbx_values(entry: ET.Element, cipher: Salsa20 | None) -> dict:
    """Return one entry's strings, decrypting the protected ones in order."""
    values: dict[str, str] = {}
    for string in entry.findall("String"):
        key = string.findtext("Key") or ""
        value = string.find("Value")
        if value is None:
            continue
        text = value.text or ""
        if (value.get("Protected") or "").lower() == "true":
            if cipher is None:
                raise LootError("kdbx_unsupported_stream", "protected values need Salsa20")
            try:
                raw = base64.b64decode(text)
            except ValueError as exc:  # malformed base64 inside a real database
                raise LootError("kdbx_protected_value_invalid", str(exc)) from exc
            text = cipher.decrypt(raw).decode("utf-8", "replace")
        values[key] = text
    return values


def _kdbx_entries(root: ET.Element, stream_id: int, stream_key: bytes) -> tuple[list[dict], int]:
    """Walk ``Root`` in document order, decrypting values with one stream."""
    cipher = None
    if stream_id == INNER_STREAM_SALSA20:
        cipher = Salsa20(hashlib.sha256(stream_key).digest(), KEEPASS_SALSA20_NONCE)
    elif any((value.get("Protected") or "").lower() == "true" for value in root.iter("Value")):
        raise LootError("kdbx_unsupported_stream", f"inner stream {stream_id}")

    entries: list[dict] = []
    groups = 0

    def walk(group: ET.Element, path: list[str]) -> None:
        nonlocal groups
        groups += 1
        name = group.findtext("Name") or ""
        here = path + [name] if name else path
        for entry in group.findall("Entry"):
            values = _kdbx_values(entry, cipher)
            record: dict[str, object] = {"group": "/".join(here)}
            for source, target in (("Title", "title"), ("UserName", "username"),
                                   ("Password", "password"), ("URL", "url"), ("Notes", "notes")):
                text = values.get(source, "")
                record[target] = text[:MAX_FIELD_CHARS]
                if len(text) > MAX_FIELD_CHARS:
                    record[target + "_truncated"] = True
            entries.append(record)
        for child in group.findall("Group"):
            walk(child, here)

    container = root.find("Root")
    root_group = (container if container is not None else root).find("Group")
    if root_group is not None:
        walk(root_group, [])
    return entries, groups


def open_kdbx(data: bytes, material: bytes, max_entries: int = MAX_ENTRIES) -> dict:
    """Open a KDBX 3.1 database with DPAPI-recovered KeePass key material.

    ``material`` is the 64-byte value unwrapped from ``ProtectedUserKey.bin``; the
    composite key KeePass would build for a user account is ``SHA256(material)``.
    """
    if len(data) > MAX_KDBX_BYTES:
        raise LootError("kdbx_too_large", f"{len(data)} bytes")
    if not material:
        raise LootError("kdbx_material_missing", "empty key material")
    fields, offset, major, minor = _kdbx_header(data)
    payload_key, rounds, stream_start = _kdbx_transformed_key(fields, hashlib.sha256(material).digest())
    plaintext = _aes_cbc_decrypt(data[offset:], payload_key, fields.get(7) or bytes(16))
    if plaintext[:len(stream_start)] != stream_start:
        raise LootError("kdbx_credentials_invalid", "stream start bytes do not match")
    body = plaintext[len(stream_start):]
    blocks = _kdbx_blocks(body)
    compressed = bool(struct.unpack("<I", fields.get(3) or b"\x00" * 4)[0] & 1)
    if compressed:
        try:
            blocks = gzip.decompress(blocks)
        except (OSError, EOFError) as exc:
            raise LootError("kdbx_decompression_failed", str(exc)) from exc
    try:
        root = ET.fromstring(blocks.decode("utf-8", "replace"))
    except ET.ParseError as exc:
        raise LootError("kdbx_xml_invalid", str(exc)) from exc
    stream_id = struct.unpack("<I", fields.get(10) or b"\x02\x00\x00\x00")[0]
    entries, groups = _kdbx_entries(root, stream_id, fields.get(8) or b"")
    limit = max(1, min(int(max_entries), MAX_ENTRIES))
    flags = [
        token
        for entry in entries
        for field in ("password", "notes", "username", "url")
        for token in _flag_tokens(entry.get(field) or "")
    ]
    return {
        "format": f"kdbx{major}.{minor}",
        "rounds": rounds,
        "groups": groups,
        "entries": entries[:limit],
        "entry_count": len(entries),
        "truncated": len(entries) > limit,
        "flags": list(dict.fromkeys(flags)),
    }


def _flag_tokens(text: str) -> list[str]:
    """Return flag-shaped tokens (``THM{...}``, ``HTB{...}``, …) inside ``text``."""
    tokens: list[str] = []
    for prefix in ("THM{", "HTB{", "FLAG{", "flag{", "CTF{", "ctf{"):
        start = 0
        while True:
            index = text.find(prefix, start)
            if index < 0:
                break
            end = text.find("}", index)
            if end < 0:
                break
            token = text[index:end + 1]
            if 6 <= len(token) <= 200:
                tokens.append(token)
            start = end + 1
    return tokens


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _parse_hex(value: str, field: str) -> bytes:
    text = (value or "").strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if len(text) % 2 or not text or any(ch not in "0123456789abcdefABCDEF" for ch in text):
        raise LootError("invalid_hex", f"{field} is not an even-length hex string")
    return bytes.fromhex(text)


def _read_file(path: str, *, limit: int) -> bytes:
    if not path:
        raise LootError("missing_file", "a file path is required")
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise LootError("file_too_large", path)
    return data


def main(argv: list[str]) -> int:
    """Entry point: one JSON object on stdout, always exit code 0 when classified."""
    action = argv[1] if len(argv) > 1 else ""
    payload: dict
    try:
        if action == "unwrap":
            blob_path, masterkey_hex = argv[2], argv[3]
            entropy_hex = argv[4] if len(argv) > 4 else "-"
            entropy = b"" if entropy_hex in ("-", "") else _parse_hex(entropy_hex, "entropy")
            masterkey = _parse_hex(masterkey_hex, "masterkey")
            if len(masterkey) < 16:
                raise LootError("invalid_masterkey", "masterkey is too short")
            raw = _read_file(blob_path, limit=MAX_BLOB_BYTES)
            unwrapped = dpapi_unwrap(raw, masterkey, entropy)
            material = unwrapped.pop("cleartext")
            payload = {
                "ok": True,
                "action": action,
                "material_hex": material.hex(),
                "material_b64": base64.b64encode(material).decode("ascii"),
                "material_bytes": len(material),
                "material_sha256": hashlib.sha256(material).hexdigest(),
                "blob_bytes": len(raw),
                "entropy_used": bool(entropy),
                **unwrapped,
            }
            if len(argv) > 5:
                with open(argv[5], "wb") as handle:
                    handle.write(material)
                payload["material_file"] = argv[5]
        elif action == "open_kdbx":
            kdbx_path, material_hex = argv[2], argv[3]
            max_entries = int(argv[4]) if len(argv) > 4 and argv[4] else MAX_ENTRIES
            material = _parse_hex(material_hex, "material")
            data = _read_file(kdbx_path, limit=MAX_KDBX_BYTES)
            payload = {"ok": True, "action": action, "kdbx_bytes": len(data),
                       **open_kdbx(data, material, max_entries)}
            if len(argv) > 5:
                with open(argv[5], "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, ensure_ascii=False)
                payload["report_file"] = argv[5]
        else:
            payload = {"ok": False, "error": "unsupported_action", "detail": action}
    except LootError as exc:
        payload = {"ok": False, "error": exc.code, "detail": exc.detail}
    except (OSError, ValueError, KeyError, IndexError, struct.error) as exc:
        payload = {"ok": False, "error": "client_error",
                   "detail": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
