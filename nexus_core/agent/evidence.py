"""Ground the model's findings in the *current* run's observations (B8.2.3).

The E2E run #2 ended with a ``task_complete`` whose findings cited ports, users
and files that this run never observed: they came from the earlier runs sharing
the same work session. A deterministic check is possible because the loop knows
exactly which tool outputs this run produced: a finding that cites evidence must
share at least one substantive token with them.

Nothing here trusts the model: a finding with no evidence at all is not "stale",
it is simply unsupported, and a finding whose only citations appear in *no*
observation of this run is marked ``stale_evidence`` so it cannot be counted as a
verified result. The raw finding is always preserved (annotated, never dropped).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

#: Tokens shorter than this are ignored (ports, ids and versions are longer).
MIN_EVIDENCE_TOKEN_CHARS = 4

#: Cap on the corpus handed to the token check.
MAX_CORPUS_CHARS = 200_000

#: Free-text fields a finding can cite evidence in.
FINDING_TEXT_FIELDS: tuple[str, ...] = (
    "title",
    "evidence",
    "detail",
    "description",
    "summary",
    "impact",
    "proof",
    "output",
    "recommendation",
    "reference",
)

#: Words that carry no evidential weight: prose glue, finding vocabulary and the
#: envelope keys every observation has (so a match must be about the target).
STOPWORDS: frozenset[str] = frozenset(
    {
        # English glue
        "about", "after", "again", "against", "allow", "allows", "also", "although",
        "another", "because", "been", "before", "being", "between", "both", "could",
        "does", "doing", "done", "each", "found", "from", "have", "having", "here",
        "into", "itself", "just", "like", "make", "makes", "many", "might", "more",
        "most", "much", "must", "need", "only", "other", "over", "same", "should",
        "some", "such", "than", "that", "their", "them", "then", "there", "these",
        "they", "this", "those", "through", "under", "until", "used", "using",
        "very", "were", "what", "when", "where", "which", "while", "with", "without",
        "would", "your",
        # Finding vocabulary
        "access", "attacker", "could", "credential", "credentials", "critical",
        "dangerous", "default", "exposed", "exposure", "finding", "findings",
        "high", "impact", "issue", "level", "medium", "password", "passwords",
        "privilege", "privileges", "recommendation", "remote", "risk", "service",
        "services", "severity", "target", "targets", "user", "users", "vulnerability",
        "vulnerabilities", "weak", "weakness",
        # Observation envelope
        "error", "evidence", "exit", "false", "null", "output", "result", "sandbox",
        "shell", "stderr", "stdout", "success", "tool", "true", "verified",
        "verification", "method", "noise", "level",
        # Spanish glue
        "anónimo", "anonimo", "antes", "como", "con", "contra", "cuando", "desde",
        "donde", "este", "esto", "hacia", "hasta", "para", "pero", "porque", "puede",
        "pueden", "según", "segun", "sido", "sobre", "tiene", "todo", "todos", "tras",
        "una", "unas", "unos",
    }
)

#: A token: a run of letters/digits (with ``.``/``_``/``/``/``-`` inside, so
#: ``locks.txt`` and ``10.67.177.81`` stay recognizable).
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{2,}")


def evidence_tokens(text: Any) -> frozenset[str]:
    """Substantive lowercase tokens of a free-text fragment (never raises)."""
    tokens: set[str] = set()
    for raw in _TOKEN_RE.findall(str(text or "").lower()):
        token = raw.strip("._/-")
        if len(token) < MIN_EVIDENCE_TOKEN_CHARS or token in STOPWORDS:
            continue
        tokens.add(token)
        # ``locks.txt`` also contributes ``locks`` so a finding may cite the
        # file name without its extension.
        stem = token.split(".", 1)[0]
        if len(stem) >= MIN_EVIDENCE_TOKEN_CHARS and stem not in STOPWORDS:
            tokens.add(stem)
    return frozenset(tokens)


def looks_distinctive(token: str) -> bool:
    """Whether a token identifies *this* target (vs. vocabulary the corpus shares).

    Tool output is full of structural words (``open``, ``state``, ``port``,
    ``service``) that a fabricated finding can match by accident. A token is only
    treated as evidence-bearing when it looks like an identifier: it carries a
    digit, a separator (``22/tcp``, ``locks.txt``, ``10.67.177.81``) or is a long
    substantive word (``anonymous``).
    """
    if any(char.isdigit() for char in token):
        return True
    if any(char in token for char in "./_-@"):
        return True
    return len(token) >= 8


def distinctive_tokens(tokens: Iterable[str]) -> frozenset[str]:
    """The subset of ``tokens`` that can actually identify evidence."""
    return frozenset(token for token in tokens if looks_distinctive(token))


def finding_text(finding: Any) -> str:
    """Concatenate the free-text fields a finding can cite evidence in."""
    if not isinstance(finding, Mapping):
        return str(finding or "")
    parts: list[str] = []
    for key in FINDING_TEXT_FIELDS:
        value = finding.get(key)
        if value:
            parts.append(str(value))
    references = finding.get("references")
    if isinstance(references, (list, tuple)):
        parts.extend(str(item) for item in references)
    return " ".join(parts)


def _observation_payload(observation: Any) -> Any:
    """The parts of an observation that carry evidence (not the envelope)."""
    if isinstance(observation, Mapping):
        output = observation.get("output")
        evidence = observation.get("evidence")
        if output is None and evidence is None:
            return observation
        return {"output": output, "evidence": evidence}
    return observation


def evidence_corpus(
    observations: Iterable[Any], *, max_chars: int = MAX_CORPUS_CHARS
) -> str:
    """Join this run's successful observations into a bounded token corpus."""
    chunks: list[str] = []
    total = 0
    for observation in observations:
        text = json.dumps(_observation_payload(observation), default=str, ensure_ascii=False)
        if total + len(text) > max_chars:
            break
        chunks.append(text)
        total += len(text)
    return "\n".join(chunks)


def is_grounded(finding: Any, corpus_tokens: frozenset[str]) -> bool:
    """True when the finding cites evidence this run actually observed.

    The *distinctive* tokens of the finding must intersect the corpus (a claim
    about ``10.65.163.65`` is not supported by output that only ever mentioned
    ``10.67.177.81``). Only when a finding is built exclusively from shared
    vocabulary does the check fall back to ordinary overlap.
    """
    tokens = evidence_tokens(finding_text(finding))
    if not tokens:
        return False
    identifiers = distinctive_tokens(tokens)
    if identifiers:
        return bool(identifiers & corpus_tokens)
    return bool(tokens & corpus_tokens)


def annotate_findings(
    findings: Any,
    *,
    observations: Iterable[Any] = (),
    corpus: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Annotate each finding with where its evidence comes from.

    Returns ``(findings, stats)``. Every input finding survives: it gains
    ``evidence_source`` (``current_run`` | ``stale_evidence`` | ``no_evidence``)
    and, when stale, ``stale_evidence: True``.
    """
    if corpus is None:
        materialized = list(observations)
        text = evidence_corpus(materialized)
        observations_seen = len(materialized)
    else:
        text = str(corpus)
        observations_seen = 0
    tokens = evidence_tokens(text)
    annotated: list[dict[str, Any]] = []
    stale = 0
    unsupported = 0
    for finding in findings or ():
        record = dict(finding) if isinstance(finding, Mapping) else {"value": finding}
        if not evidence_tokens(finding_text(record)):
            record["evidence_source"] = "no_evidence"
            unsupported += 1
        elif is_grounded(record, tokens):
            record["evidence_source"] = "current_run"
        else:
            record["evidence_source"] = "stale_evidence"
            record["stale_evidence"] = True
            stale += 1
        annotated.append(record)
    stats = {
        "findings_total": len(annotated),
        "grounded": len(annotated) - stale - unsupported,
        "stale": stale,
        "unsupported": unsupported,
        "corpus_tokens": len(tokens),
        "corpus_observations": observations_seen,
    }
    return annotated, stats


def fabricated_evidence(stats: Mapping[str, int]) -> bool:
    """True when the completion cites evidence that nothing in this run supports.

    Only meaningful when the model *made claims*: an empty findings list is not
    fabrication, it is simply an unsupported completion (handled by the plan
    gate). This is the exact E2E run #2 shape: several findings, none of them
    traceable to an observation of the run.

    A run with **no observations at all** cannot answer the question either way
    (there is no evidence base to be stale against), so it is not flagged here;
    the plan gate is what refuses an engagement run that has done nothing.
    """
    return (
        bool(stats.get("stale"))
        and not stats.get("grounded")
        and bool(stats.get("corpus_tokens"))
    )


__all__ = [
    "FINDING_TEXT_FIELDS",
    "MAX_CORPUS_CHARS",
    "MIN_EVIDENCE_TOKEN_CHARS",
    "STOPWORDS",
    "annotate_findings",
    "distinctive_tokens",
    "evidence_corpus",
    "evidence_tokens",
    "fabricated_evidence",
    "finding_text",
    "is_grounded",
    "looks_distinctive",
]
