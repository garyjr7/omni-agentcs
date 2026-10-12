"""Hermetic tests for the injected ELF analyzer (no target, no network)."""

from __future__ import annotations

import struct

import pytest

from nexus_core.tools.handlers._pwn import ANALYZER_SOURCE, parse_binary, parse_libc

ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_DYNSYM = 11

TEXT_OFF = 0x1000
RW_OFF = 0x2000
DYNSTR_OFF = 0x3000
DYNSYM_OFF = 0x3100
RELA_OFF = 0x3200
DYN_OFF = 0x3400
SHOFF = 0x4000
GOT_ADDR = 0x2018


def _build_elf(
    *,
    e_type: int = ET_EXEC,
    text: bytes | None = None,
    dynstr: bytes = b"\x00",
    dynsym_entries: list[tuple[str, int, int]] | None = None,
    rela_plt: list[tuple[int, int]] | None = None,
    relro: bool = True,
    nx: bool = True,
    bind_now: bool = False,
) -> bytes:
    """Build a minimal x86-64 ELF exercising every branch of parse_binary."""
    dynsym_entries = dynsym_entries or []
    rela_plt = rela_plt or []
    text = text if text is not None else b"\xc3"

    dynsym = b"\x00" * 24
    for name, value, shndx in dynsym_entries:
        name_off = dynstr.find(name.encode()) if name else 0
        dynsym += struct.pack("<IBBHQQ", name_off, 0x12, 0, shndx, value, 0)
    rela = b"".join(struct.pack("<QQq", off, (sym << 32) | 7, 0) for off, sym in rela_plt)
    dynamic = struct.pack("<qQ", 24, 0) + struct.pack("<qQ", 0, 0) if bind_now else b""

    buf = bytearray()

    def place(offset: int, blob: bytes) -> None:
        if len(buf) < offset:
            buf.extend(b"\x00" * (offset - len(buf)))
        buf[offset:offset + len(blob)] = blob

    place(TEXT_OFF, text)
    place(RW_OFF, b"\x00" * 0x100)
    place(DYNSTR_OFF, dynstr)
    place(DYNSYM_OFF, dynsym)
    place(RELA_OFF, rela)
    place(DYN_OFF, dynamic)

    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, SHT_PROGBITS, 0x6, TEXT_OFF, TEXT_OFF, max(len(text), 1), 0, 0, 0),
        (0, SHT_STRTAB, 0x2, DYNSTR_OFF, DYNSTR_OFF, len(dynstr), 0, 0, 0),
        (0, SHT_DYNSYM, 0x2, DYNSYM_OFF, DYNSYM_OFF, len(dynsym), 2, 0, 24),
        (0, SHT_RELA, 0x2, RELA_OFF, RELA_OFF, max(len(rela), 1), 3, 0, 24),
        (0, SHT_NOBITS, 0x3, 0x2100, 0, 0x40, 0, 0, 0),
    ]
    for i, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_ent) in enumerate(sections):
        place(SHOFF + i * 64, struct.pack(
            "<IIQQQQIIQQ", sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
            sh_link, sh_info, 16, sh_ent,
        ))

    phdrs = [
        struct.pack("<IIQQQQQQ", PT_LOAD, 0x5, TEXT_OFF, TEXT_OFF, TEXT_OFF, max(len(text), 1), max(len(text), 1), 0x1000),
        struct.pack("<IIQQQQQQ", PT_LOAD, 0x6, RW_OFF, RW_OFF, RW_OFF, 0x100, 0x100, 0x1000),
        struct.pack("<IIQQQQQQ", PT_GNU_STACK, 0x6 if nx else 0x7, 0, 0, 0, 0, 0, 0x10),
    ]
    if relro:
        phdrs.append(struct.pack("<IIQQQQQQ", PT_GNU_RELRO, 0x4, RW_OFF, RW_OFF, RW_OFF, 0x100, 0x100, 1))
    if dynamic:
        phdrs.append(struct.pack("<IIQQQQQQ", PT_DYNAMIC, 0x6, DYN_OFF, DYN_OFF, DYN_OFF, len(dynamic), len(dynamic), 8))
    for i, ph in enumerate(phdrs):
        place(64 + i * 56, ph)

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    struct.pack_into("<HHI", header, 16, e_type, 62, 1)
    struct.pack_into("<Q", header, 24, TEXT_OFF)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<Q", header, 40, SHOFF)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, len(phdrs), 64, len(sections), 0)
    place(0, bytes(header))
    return bytes(buf)


def _text_with_gets_call() -> bytes:
    text = bytearray(0x40)
    text[0:6] = b"\xff\x25\x00\x00\x00\x00"
    struct.pack_into("<i", text, 2, GOT_ADDR - (TEXT_OFF + 6))  # jmp *got(%rip)
    text[0x10:0x14] = b"\x48\x8d\x45\xf6"                       # lea rax,[rbp-0xa]
    text[0x14] = 0xE8
    struct.pack_into("<i", text, 0x15, TEXT_OFF - (TEXT_OFF + 0x14 + 5))  # call gets@plt
    text[0x20:0x22] = b"\x5f\xc3"                                # pop rdi; ret
    return bytes(text)


# --------------------------------------------------------------------- tests
def test_non_elf_is_rejected():
    with pytest.raises(ValueError):
        parse_binary(b"not an elf at all")


def test_protections_nx_pie_relro_canary():
    info = parse_binary(_build_elf(relro=True, nx=True))
    assert info["bits"] == 64 and info["arch"] == "x86-64"
    assert info["pie"] is False and info["nx"] is True
    assert info["relro"] == "partial" and info["canary"] is False


def test_nx_disabled_is_detected():
    assert parse_binary(_build_elf(nx=False))["nx"] is False


def test_pie_binary_is_detected():
    info = parse_binary(_build_elf(e_type=ET_DYN))
    assert info["pie"] is True and info["type"] == "pie"


def test_full_relro_requires_bind_now():
    assert parse_binary(_build_elf(relro=True, bind_now=False))["relro"] == "partial"
    assert parse_binary(_build_elf(relro=True, bind_now=True))["relro"] == "full"


def test_gadgets_and_writable():
    info = parse_binary(_build_elf(text=_text_with_gets_call()))
    assert TEXT_OFF + 0x20 in info["gadgets"]["pop_rdi"]
    assert TEXT_OFF + 0x21 in info["gadgets"]["ret"]
    assert info["writable"] == 0x2100


def test_plt_got_and_overflow_offset():
    data = _build_elf(
        text=_text_with_gets_call(),
        dynstr=b"\x00gets\x00",
        dynsym_entries=[("gets", 0, 0)],
        rela_plt=[(GOT_ADDR, 1)],
    )
    info = parse_binary(data)
    assert info["plt"]["gets"] == TEXT_OFF
    assert info["got"]["gets"] == GOT_ADDR
    assert info["overflow"] == {
        "buffer_displacement": 10,
        "offset_to_rip": 18,
        "gets_plt": TEXT_OFF,
        "site": TEXT_OFF + 0x10,
    }


def test_parse_libc_reports_offsets():
    data = _build_elf(
        dynstr=b"\x00puts\x00system\x00",
        dynsym_entries=[("puts", 0x84420, 1), ("system", 0x52290, 1)],
    ) + b"/bin/sh\x00"
    info = parse_libc(data)
    assert info["puts"] == 0x84420 and info["system"] == 0x52290
    assert info["binsh"] is not None


def test_elf_undefined_stack_chk_fail_sets_canary():
    """V0-29: the stack protector is an *undefined* import in .dynsym.

    The analyzer used to skip undefined symbols before checking the name, so a
    binary importing ``__stack_chk_fail`` was reported with canary=false.
    """
    data = _build_elf(
        dynstr=b"\x00__stack_chk_fail\x00",
        dynsym_entries=[("__stack_chk_fail", 0, 0)],
    )
    assert parse_binary(data)["canary"] is True
    # The injected copy must agree with the module copy on the same bytes.
    ns: dict = {}
    exec(compile(ANALYZER_SOURCE, "<analyzer>", "exec"), ns)
    assert ns["parse_binary"](data)["canary"] is True


def test_other_undefined_imports_do_not_set_canary():
    """Negative control: an unrelated undefined symbol must not turn it on."""
    data = _build_elf(dynstr=b"\x00gets\x00", dynsym_entries=[("gets", 0, 0)])
    assert parse_binary(data)["canary"] is False


def test_injected_source_compiles_and_matches_module():
    ns: dict = {}
    exec(compile(ANALYZER_SOURCE, "<analyzer>", "exec"), ns)
    data = _build_elf(
        text=_text_with_gets_call(),
        dynstr=b"\x00gets\x00",
        dynsym_entries=[("gets", 0, 0)],
        rela_plt=[(GOT_ADDR, 1)],
    )
    assert ns["parse_binary"](data) == parse_binary(data)
