"""Pure-stdlib ELF analysis for the binary-exploitation handlers.

The two functions here are the single source of truth for reading an ELF from
the target:

* :func:`parse_binary` - protections (PIE/NX/RELRO/canary), symbols, PLT/GOT
  resolution, ``ret``/``pop rdi; ret`` gadgets and the stack-buffer overflow
  offset feeding a ``gets()`` call;
* :func:`parse_libc` - the fixed offsets of ``puts``, ``system`` and the
  ``/bin/sh`` string inside a libc.

They are deliberately self-contained (no helpers, no imports beyond ``struct``)
so :data:`ANALYZER_SOURCE` can be spliced verbatim into the sandbox client
script: the code that runs on the operator's machine and the code that runs
inside the sandbox are literally the same bytes. That keeps the tool honest -
there is one parser to test, not two drifting copies.
"""

from __future__ import annotations

import inspect

#: ELF constants (subset used by the analyzer).
ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 62
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNSYM = 11
DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DF_BIND_NOW = 0x8
R_X86_64_JUMP_SLOT = 7
STT_FUNC = 2

#: Cap on symbols returned, so a huge symbol table cannot flood the agent.
MAX_SYMBOLS = 400


def parse_binary(data: bytes) -> dict:
    """Analyze an ELF executable/executable-lib and return its attack surface."""
    import struct

    out: dict = {}
    if data[:4] != b"\x7fELF" or len(data) < 64:
        raise ValueError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise ValueError("only 64-bit little-endian ELF is supported")
    (e_type, e_machine) = struct.unpack_from("<HH", data, 16)
    if e_machine != 62:
        raise ValueError("only x86-64 is supported")
    (e_phoff,) = struct.unpack_from("<Q", data, 32)
    (e_shoff,) = struct.unpack_from("<Q", data, 40)
    (e_phentsize, e_phnum) = struct.unpack_from("<HH", data, 54)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 58)

    out["bits"] = 64
    out["arch"] = "x86-64"
    out["type"] = "exec" if e_type == ET_EXEC else ("pie" if e_type == ET_DYN else "other")
    out["pie"] = e_type == ET_DYN

    # --- program headers -------------------------------------------------
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 56 > len(data):
            break
        p_type, p_flags = struct.unpack_from("<II", data, off)
        p_offset, p_vaddr, _ppad, p_filesz, p_memsz = struct.unpack_from("<QQQQQ", data, off + 8)
        phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

    out["nx"] = True
    out["relro"] = "none"
    dynamic_off = dynamic_size = None
    for p_type, p_flags, p_offset, p_vaddr, p_filesz, _memsz in phdrs:
        if p_type == PT_GNU_STACK:
            out["nx"] = not (p_flags & 0x1)  # PF_X == 1
        elif p_type == PT_GNU_RELRO:
            out["relro"] = "partial"
        elif p_type == PT_DYNAMIC:
            dynamic_off, dynamic_size = p_offset, p_filesz

    if dynamic_off is not None:
        pos = dynamic_off
        end = dynamic_off + (dynamic_size or 0)
        while pos + 16 <= min(end, len(data)):
            d_tag, d_val = struct.unpack_from("<qQ", data, pos)
            pos += 16
            if d_tag == DT_NULL:
                break
            if d_tag == DT_BIND_NOW or (d_tag == DT_FLAGS and d_val & DF_BIND_NOW):
                if out["relro"] == "partial":
                    out["relro"] = "full"
                break

    # --- sections --------------------------------------------------------
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if off + 64 > len(data):
            break
        sh_name, sh_type = struct.unpack_from("<II", data, off)
        sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, off + 16)
        sh_link, sh_info = struct.unpack_from("<II", data, off + 40)
        (sh_entsize,) = struct.unpack_from("<Q", data, off + 56)
        sections.append(
            {
                "name_off": sh_name, "type": sh_type, "addr": sh_addr,
                "offset": sh_offset, "size": sh_size, "link": sh_link,
                "info": sh_info, "entsize": sh_entsize,
            }
        )

    def _cstr(blob: bytes, start: int) -> str:
        end = blob.find(b"\x00", start)
        if end == -1:
            end = len(blob)
        return blob[start:end].decode("utf-8", "replace")

    # shstrtab is optional here: names are only used to find .rela.plt/.got.plt,
    # and we fall back to structural detection below.
    shstr = b""
    if 0 <= e_shstrndx < len(sections):
        s = sections[e_shstrndx]
        shstr = data[s["offset"]: s["offset"] + s["size"]]
    for s in sections:
        s["name"] = _cstr(shstr, s["name_off"]) if shstr else ""

    # --- symbols ---------------------------------------------------------
    # ``.symtab`` (if present) gives the defined functions; ``.dynsym`` is
    # required to resolve relocation symbol indices. They are parsed separately
    # on purpose: using symtab indices against rela sections would mislabel
    # every PLT entry.
    symbols: dict[str, int] = {}
    dynsym_names: list[str] = []
    canary = False

    def _parse_symtab(sec: dict, want_names: bool) -> list[str]:
        nonlocal canary
        names: list[str] = []
        link = sec["link"]
        if not (0 <= link < len(sections)):
            return names
        strsec = sections[link]
        strtab = data[strsec["offset"]: strsec["offset"] + strsec["size"]]
        count = sec["size"] // sec["entsize"] if sec["entsize"] else 0
        for j in range(count):
            off = sec["offset"] + j * sec["entsize"]
            if off + 24 > len(data):
                break
            st_name, st_info, st_other, st_shndx = struct.unpack_from("<IBBH", data, off)
            (st_value,) = struct.unpack_from("<Q", data, off + 8)
            name = _cstr(strtab, st_name)
            if want_names:
                names.append(name)
            # ``__stack_chk_fail`` is normally an UNDEFINED import from libc, so
            # it has to be checked before the undefined-symbol skip below;
            # otherwise the stack protector is never detected.
            if name == "__stack_chk_fail":
                canary = True
            if not name or st_shndx == 0:  # undefined (imported) symbol
                continue
            if (st_info & 0xF) == STT_FUNC and name not in symbols:
                symbols[name] = st_value
        return names

    symtab = next((s for s in sections if s["type"] == SHT_SYMTAB), None)
    dynsym = next((s for s in sections if s["type"] == SHT_DYNSYM), None)
    if dynsym is not None:
        dynsym_names = _parse_symtab(dynsym, want_names=True)
    if symtab is not None:
        _parse_symtab(symtab, want_names=False)
    out["canary"] = canary
    # The handler trims before handing this to the agent; the raw dict stays
    # complete so libc symbol lookups always succeed.
    out["symbols"] = dict(sorted(symbols.items(), key=lambda kv: kv[1]))

    # --- PLT/GOT via .rela.plt -------------------------------------------
    got: dict[str, int] = {}
    plt: dict[str, int] = {}
    for s in sections:
        if s["type"] != SHT_RELA:
            continue
        reloc_count = s["size"] // 24 if s["size"] else 0
        for j in range(reloc_count):
            off = s["offset"] + j * 24
            if off + 24 > len(data):
                break
            r_offset, r_info = struct.unpack_from("<QQ", data, off)
            r_type = r_info & 0xFFFFFFFF
            sym_idx = r_info >> 32
            if r_type != R_X86_64_JUMP_SLOT:
                continue
            name = dynsym_names[sym_idx] if sym_idx < len(dynsym_names) else ""
            if name:
                got[name] = r_offset
    # Resolve each GOT slot to the `jmp *got(%rip)` PLT stub that feeds it.
    exec_phdrs = [p for p in phdrs if p[0] == PT_LOAD and p[1] & 0x1]
    got_to_name = {v: k for k, v in got.items()}
    for p_type, _flags, p_offset, p_vaddr, p_filesz, _memsz in exec_phdrs:
        seg = data[p_offset: p_offset + p_filesz]
        i = 0
        while True:
            i = seg.find(b"\xff\x25", i)
            if i < 0:
                break
            if i + 6 <= len(seg):
                disp = struct.unpack_from("<i", seg, i + 2)[0]
                target = p_vaddr + i + 6 + disp
                name = got_to_name.get(target)
                if name and name not in plt:
                    plt[name] = p_vaddr + i
            i += 1
    out["got"] = got
    out["plt"] = plt

    # --- gadgets ---------------------------------------------------------
    def _gadgets(pattern: bytes) -> list[int]:
        found: list[int] = []
        for _pt, flags, p_offset, p_vaddr, p_filesz, _memsz in phdrs:
            if _pt != PT_LOAD or not (flags & 0x1):
                continue
            seg = data[p_offset: p_offset + p_filesz]
            i = 0
            while True:
                i = seg.find(pattern, i)
                if i < 0:
                    break
                found.append(p_vaddr + i)
                i += 1
        return found

    out["gadgets"] = {
        "ret": _gadgets(b"\xc3")[:16],
        "pop_rdi": _gadgets(b"\x5f\xc3")[:16],
    }

    # --- gets() stack overflow offset ------------------------------------
    overflow = None
    gets_plt = plt.get("gets")
    if gets_plt is not None:
        for _pt, flags, p_offset, p_vaddr, p_filesz, _memsz in phdrs:
            if _pt != PT_LOAD or not (flags & 0x1):
                continue
            seg = data[p_offset: p_offset + p_filesz]
            i = 0
            while True:
                i = seg.find(b"\xe8", i)  # call rel32
                if i < 0:
                    break
                if i + 5 <= len(seg):
                    rel = struct.unpack_from("<i", seg, i + 1)[0]
                    if p_vaddr + i + 5 + rel == gets_plt:
                        # Look back for `lea rax,[rbp-disp]` (buffer on stack).
                        for k in range(i - 4, max(-1, i - 32), -1):
                            if seg[k: k + 3] == b"\x48\x8d\x45":  # lea rax,[rbp+disp8]
                                disp = struct.unpack_from("<b", seg, k + 3)[0]
                                buffer_disp = -disp
                                overflow = {
                                    "buffer_displacement": buffer_disp,
                                    "offset_to_rip": buffer_disp + 8,
                                    "gets_plt": gets_plt,
                                    "site": p_vaddr + k,
                                }
                                break
                        if overflow:
                            break
                i += 1
            if overflow:
                break
    out["overflow"] = overflow

    # A writable address with room for a planted command string: the loader maps
    # whole pages, so the first page-aligned address past .bss is safe.
    bss = next((s for s in sections if s["name"] == ".bss"), None)
    end = None
    if bss and bss["addr"]:
        end = bss["addr"] + bss["size"]
    else:
        for p_type, p_flags, _p_offset, p_vaddr, _p_filesz, p_memsz in phdrs:
            if p_type == PT_LOAD and p_flags & 0x2:  # PF_W
                end = max(end or 0, p_vaddr + p_memsz)
    out["writable"] = (end + 0xFF) & ~0xFF if end else None
    return out


def parse_libc(data: bytes) -> dict:
    """Return ``puts``/``system``/``/bin/sh`` offsets inside a libc image."""
    info = parse_binary(data)
    symbols = info.get("symbols") or {}
    binsh = data.find(b"/bin/sh")
    return {
        "puts": symbols.get("puts"),
        "system": symbols.get("system"),
        "binsh": binsh if binsh >= 0 else None,
        "symbols_total": len(symbols),
    }


#: Names the injected functions rely on. Kept in one place so the sandbox copy
#: cannot silently diverge from the module copy.
_ANALYZER_CONSTANTS = (
    "ET_EXEC", "ET_DYN", "EM_X86_64", "PT_LOAD", "PT_DYNAMIC", "PT_GNU_STACK",
    "PT_GNU_RELRO", "SHT_SYMTAB", "SHT_STRTAB", "SHT_RELA", "SHT_DYNSYM",
    "DT_NULL", "DT_BIND_NOW", "DT_FLAGS", "DF_BIND_NOW", "R_X86_64_JUMP_SLOT",
    "STT_FUNC",
)


#: Analyzer source injected verbatim into the sandbox client script: the exact
#: same bytes the operator process runs, plus the constants and ``struct``.
ANALYZER_SOURCE = "\n".join(
    ["# --- nexus injected ELF analyzer ---", "import struct"]
    + [f"{name} = {globals()[name]}" for name in _ANALYZER_CONSTANTS]
    + [inspect.getsource(parse_binary), inspect.getsource(parse_libc)]
)


__all__ = [
    "ANALYZER_SOURCE",
    "parse_binary",
    "parse_libc",
]
