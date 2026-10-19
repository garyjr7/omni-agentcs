"""Skills: operator-curated procedures that a *repository* can also ship.

A skill is ``.agents/skills/<name>/SKILL.md``: a short procedure the operator may
activate so the agent follows it. The risk is exactly the supply chain one — you
clone a repo, it ships a poisoned ``SKILL.md``, and the text reaches the agent's
prompt. The model handles it in three tiers:

* **signed and verified** (``SKILL.md.sig`` matches under the shared secret) —
  trusted guidance, still delimited for defence in depth;
* **unsigned** — included only as *untrusted data* with an explicit warning, and
  flagged when it carries injection signals;
* **signed but invalid** (tampered) — **refused outright**; it is never rendered.

Nothing is activated implicitly: a skill must be named by the operator
(``/skills use <name>``, ``--skill <name>``), so the default is fail-closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path

from .injection import scan_untrusted_text, wrap_untrusted_output

#: Directory (relative to the project root) that holds skills.
SKILLS_DIRNAME = ".agents/skills"
#: File name of one skill body.
SKILL_FILENAME = "SKILL.md"
#: Suffix of the optional HMAC signature file.
SIGNATURE_SUFFIX = ".sig"

TRUST_SIGNED = "signed"
TRUST_UNSIGNED = "unsigned"
TRUST_INVALID = "invalid"


def sign_skill(raw: bytes, secret: str) -> str:
    """Return the hex HMAC-SHA256 of the skill bytes (the signature to store)."""
    return hmac.new(
        str(secret).encode("utf-8"), bytes(raw), hashlib.sha256
    ).hexdigest()


def verify_skill_signature(raw: bytes, signature: str, secret: str | None) -> bool:
    """Whether ``signature`` matches the HMAC of ``raw`` under ``secret``."""
    if not signature or not secret:
        return False
    expected = sign_skill(raw, secret)
    return hmac.compare_digest(expected, str(signature).strip().lower())


@dataclass(frozen=True)
class Skill:
    """One discovered skill, with provenance and trust level."""

    name: str
    path: str
    sha256: str
    content: str
    trust: str
    signals: tuple[str, ...] = ()
    signed: bool = False

    @property
    def usable(self) -> bool:
        """A tampered skill is never usable."""
        return self.trust != TRUST_INVALID

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "sha256": self.sha256,
            "trust": self.trust,
            "signed": self.signed,
            "signals": list(self.signals),
            "bytes": len(self.content.encode("utf-8")),
        }


def skills_root(root: str | Path | None = None) -> Path:
    base = Path(root) if root is not None else Path.cwd()
    return base / SKILLS_DIRNAME


#: A skill name is either ``<name>`` or one namespace plus the name
#: (``linux/forensics-basics``). Deeper nesting is refused so the mapping from a
#: name to a directory stays trivial to audit.
MAX_SKILL_NAME_PARTS = 2


def skill_name_parts(name: str) -> tuple[str, ...] | None:
    """Split a skill name into safe path components, or ``None``.

    Only plain components are accepted: no absolute paths, no ``.``/``..``, no
    backslashes and at most :data:`MAX_SKILL_NAME_PARTS` levels. This is what
    keeps ``nexus.skill.load`` from reading arbitrary files through its name.
    """
    text = str(name or "").strip()
    if not text or "\\" in text:
        return None
    parts = tuple(text.split("/"))
    if not 1 <= len(parts) <= MAX_SKILL_NAME_PARTS:
        return None
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return parts


def load_skill(
    name: str, root: str | Path | None = None, *, secret: str | None = None
) -> Skill | None:
    """Load one skill by name (``None`` when it does not exist or is unreadable)."""
    parts = skill_name_parts(str(name))
    if parts is None:
        return None
    directory = skills_root(root).joinpath(*parts)
    body = directory / SKILL_FILENAME
    if not body.is_file():
        return None
    try:
        raw = body.read_bytes()
    except OSError:
        return None
    signature_path = body.with_name(SKILL_FILENAME + SIGNATURE_SUFFIX)
    signature = ""
    if signature_path.is_file():
        try:
            signature = signature_path.read_text(encoding="utf-8").strip()
        except OSError:
            signature = ""
    if signature:
        trust = (
            TRUST_SIGNED
            if verify_skill_signature(raw, signature, secret)
            else TRUST_INVALID
        )
    else:
        trust = TRUST_UNSIGNED
    text = raw.decode("utf-8", errors="replace")
    return Skill(
        name=str(name),
        path=str(body),
        sha256=hashlib.sha256(raw).hexdigest(),
        content=text,
        trust=trust,
        signals=tuple(scan_untrusted_text(text)),
        signed=bool(signature),
    )


def discover_skills(
    root: str | Path | None = None, *, secret: str | None = None
) -> dict[str, Skill]:
    """Return every skill under the skills directory, keyed by name (never raises)."""
    base = skills_root(root)
    found: dict[str, Skill] = {}
    if not base.is_dir():
        return found
    for entry in sorted(base.iterdir()):
        if not entry.is_dir():
            continue
        skill = load_skill(entry.name, root, secret=secret)
        if skill is not None:
            found[entry.name] = skill
            continue
        # A directory without its own SKILL.md is a namespace
        # (``linux/forensics-basics``): publish its children, never the folder.
        for child in sorted(entry.iterdir()):
            if not child.is_dir():
                continue
            nested_name = f"{entry.name}/{child.name}"
            nested = load_skill(nested_name, root, secret=secret)
            if nested is not None:
                found[nested_name] = nested
    return found


def activate_skills(
    names: list[str] | tuple[str, ...],
    root: str | Path | None = None,
    *,
    secret: str | None = None,
) -> tuple[list[Skill], list[str]]:
    """Resolve the requested skill names; return ``(usable, refused)``.

    A name that does not exist, or that is signed but fails verification, lands
    in ``refused`` instead of being silently skipped.
    """
    usable: list[Skill] = []
    refused: list[str] = []
    for name in names or ():
        skill = load_skill(name, root, secret=secret)
        if skill is None or not skill.usable:
            refused.append(str(name))
        else:
            usable.append(skill)
    return usable, refused


#: Characters of a description published in the one-line skill index.
SKILL_DESCRIPTION_CHARS = 160


def _one_line(text: str, limit: int = SKILL_DESCRIPTION_CHARS) -> str:
    """Collapse ``text`` to one bounded line (an index entry is one line)."""
    value = " ".join(str(text or "").strip().strip("\"'").split())
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def skill_description(content: str, *, limit: int = SKILL_DESCRIPTION_CHARS) -> str:
    """One sentence about the skill: frontmatter ``description:`` or first prose.

    The prompt carries one line per skill so the model knows *why* it would load
    it. The author writes that sentence once, in the frontmatter; older skills
    without one fall back to their first non-heading line, so a skill never
    appears in the index with an empty description.
    """
    lines = str(content or "").splitlines()
    body_start = 0
    if lines and lines[0].strip() == "---":
        for index in range(1, len(lines)):
            if lines[index].strip() == "---":
                body_start = index + 1
                for meta in lines[1:index]:
                    key, _, value = meta.partition(":")
                    if key.strip().lower() == "description" and value.strip():
                        return _one_line(value, limit)
                break
    for line in lines[body_start:]:
        text = line.strip()
        if not text or text.startswith(("#", "---", "<!--", "|", "-")):
            continue
        return _one_line(text, limit)
    return "(sin descripción)"


def render_skill_index(
    skills: Mapping[str, Skill] | list[Skill] | tuple[Skill, ...],
) -> str:
    """Render ``name: one sentence`` per skill for the system prompt.

    This is the *index*, not the body: it costs one line per skill on every turn
    and is what lets the model decide to call ``nexus.skill.load``. It is wrapped
    as untrusted data because every field comes from a file that may have arrived
    with a cloned repository.
    """
    items = list(skills.values()) if isinstance(skills, Mapping) else list(skills)
    lines: list[str] = []
    for skill in sorted(items, key=lambda item: item.name):
        if skill.trust == TRUST_SIGNED:
            label = "firmada"
        elif skill.trust == TRUST_INVALID:
            label = "firma inválida: se rechaza al cargar"
        else:
            label = "sin firma"
        if skill.signals:
            label += " · señales de inyección: " + ", ".join(skill.signals)
        lines.append(f"- {skill.name}: {skill_description(skill.content)} ({label})")
    if not lines:
        return "(sin skills disponibles)"
    return wrap_untrusted_output("\n".join(lines))


def render_skills(skills: list[Skill]) -> str:
    """Render the active skills as a prompt block (wrapped as untrusted text)."""
    if not skills:
        return "(sin skills activas)"
    parts: list[str] = []
    for skill in skills:
        label = "firmada" if skill.trust == TRUST_SIGNED else "sin firma"
        header = (
            f"SKILL '{skill.name}' ({label}) · origen={skill.path} "
            f"· sha256={skill.sha256[:16]}…"
        )
        if skill.signals:
            header += " · señales de inyección: " + ", ".join(skill.signals)
        parts.append(f"{header}\n{wrap_untrusted_output(skill.content)}")
    return "\n\n".join(parts)


__all__ = [
    "MAX_SKILL_NAME_PARTS",
    "SIGNATURE_SUFFIX",
    "SKILLS_DIRNAME",
    "SKILL_FILENAME",
    "TRUST_INVALID",
    "TRUST_SIGNED",
    "TRUST_UNSIGNED",
    "Skill",
    "activate_skills",
    "discover_skills",
    "load_skill",
    "render_skill_index",
    "render_skills",
    "sign_skill",
    "skill_description",
    "skill_name_parts",
    "skills_root",
    "verify_skill_signature",
]
