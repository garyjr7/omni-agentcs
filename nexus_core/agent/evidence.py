"""Ground findings in typed verifier assertions from the current run."""

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


def is_grounded(finding, observations, *, run_id=None):
    """Require a trusted invocation, current run, exact target and semantic type.

    Token coincidence and server/model-authored verification flags carry no
    authority. Observations must come from gateway verifier assertions.
    """
    if not isinstance(finding, Mapping) or not finding.get("invocation_id") or not run_id:
        return False
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        if (observation.get("verified") is True
                and observation.get("verification_method")
                and observation.get("invocation_id") == finding["invocation_id"]
                and observation.get("run_id") == run_id
                and finding.get("target") and finding.get("target") == observation.get("target")
                and finding.get("fact_type") and finding.get("fact_type") == observation.get("fact_type")):
            # A reference to a host observation cannot substantiate a root claim.
            text = finding_text(finding).lower()
            if any(word in text for word in ("root", "uid=0", "administrator", "privilegio")):
                if observation.get("fact_type") != "privilege":
                    continue
            if "value" in finding and finding["value"] != observation.get("value"):
                continue
            return True
    return False


#: Fields of a rejection that are echoed back to the model verbatim (V1-48).
_CITED_FIELDS = ("invocation_id", "fact_type", "target")

#: Maximum per-finding detail lines carried in the refusal *message*. The event
#: keeps them all; the prompt only needs enough to know what to fix.
CITATION_DETAIL_LIMIT = 5


def _finding_ref(record: Mapping[str, Any], index: int) -> str:
    """How a rejected finding is named in the detail (`title` preferred)."""
    for name in ("title", "name", "summary", "value"):
        text = str(record.get(name) or "").strip()
        if text:
            return text[:120]
    return f"finding #{index + 1}"


def _cited_reference(record: Mapping[str, Any]) -> dict[str, str]:
    """The citation a finding made, field by field (empty strings when absent)."""
    return {name: str(record.get(name) or "") for name in _CITED_FIELDS}


def _corpus_observations(observations, run_id) -> list[Mapping[str, Any]]:
    """The observations grounding accepts at all: verified, and from this run.

    Anything else is not part of the corpus ``is_grounded`` reasons over, so it
    cannot be offered as a suggestion either.
    """
    return [
        observation
        for observation in observations
        if isinstance(observation, Mapping)
        and observation.get("verified") is True
        and observation.get("verification_method")
        and str(observation.get("run_id") or "") == str(run_id or "")
    ]


def _cited_in_corpus(cited: Mapping[str, str], corpus: list[Mapping[str, Any]]) -> bool:
    """Whether the cited ``invocation_id`` exists in the corpus at all.

    It separates the two mistakes a model makes: "I invented this invocation"
    from "the invocation is real but I attached the wrong type/target to it".
    """
    wanted = cited.get("invocation_id") or ""
    if not wanted:
        return False
    return any(str(item.get("invocation_id") or "") == wanted for item in corpus)


def _closest_corpus_match(
    cited: Mapping[str, str], corpus: list[Mapping[str, Any]]
) -> dict[str, str] | None:
    """The corpus observation closest to what the finding cited (``None`` if none).

    Scored by coincidence -the invocation is worth more than the type, which is
    worth as much as the target- and only returned when something *does*
    coincide: a suggestion with nothing in common would be a guess.
    """
    best: Mapping[str, Any] | None = None
    best_score = 0
    for item in corpus:
        score = 0
        if cited.get("invocation_id") and str(item.get("invocation_id") or "") == cited["invocation_id"]:
            score += 2
        if cited.get("fact_type") and str(item.get("fact_type") or "") == cited["fact_type"]:
            score += 1
        if cited.get("target") and str(item.get("target") or "") == cited["target"]:
            score += 1
        if score > best_score:
            best, best_score = item, score
    if best is None:
        return None
    return {name: str(best.get(name) or "") for name in _CITED_FIELDS}


def annotate_findings(findings, *, observations=(), corpus=None, run_id=None):
    materialized = list(observations)
    verified_corpus = _corpus_observations(materialized, run_id)
    annotated = []
    grounded = stale = unsupported = 0
    #: One record per finding the gate refuses, so the model is told *what* it
    #: cited wrong instead of only how many findings failed (V1-48). Measured in
    #: rerun 13: the event said `{findings_total: 8, grounded: 4, stale: 4}` and
    #: nothing else, so the next turn could not know which citation to repair.
    rejected: list[dict[str, Any]] = []
    for index, finding in enumerate(findings or ()):
        record = dict(finding) if isinstance(finding, Mapping) else {"value": finding}
        # Always overwrite model-provided status flags.
        record.pop("stale_evidence", None)
        if is_grounded(record, materialized, run_id=run_id):
            proof = next(item for item in materialized if is_grounded(record, [item], run_id=run_id))
            # A valid reference authenticates the typed fact, never arbitrary
            # model prose (e.g. a SQL-injection title attached to a host fact).
            declared = dict(record, verification_status="hypothesis", verified=False)
            record = {"title": f"{proof['fact_type']}: {proof['target']}",
                      "severity": "info", "value": proof.get("value"),
                      "fact_type": proof["fact_type"], "target": proof["target"],
                      "invocation_id": proof["invocation_id"], "run_id": proof["run_id"],
                      "verification_method": proof["verification_method"],
                      "evidence_source": "current_run", "verification_status": "confirmed_finding",
                      "declared_finding": declared}
            grounded += 1
        elif finding_text(record) or record.get("invocation_id"):
            record.update(evidence_source="stale_evidence", stale_evidence=True, verification_status="hypothesis")
            stale += 1
            cited = _cited_reference(record)
            rejected.append({
                "finding_ref": _finding_ref(record, index),
                "reason": "stale_evidence",
                "cited": cited,
                "found_in_corpus": _cited_in_corpus(cited, verified_corpus),
                "closest_match": _closest_corpus_match(cited, verified_corpus),
            })
        else:
            record.update(evidence_source="no_evidence", verification_status="hypothesis")
            unsupported += 1
            rejected.append({
                "finding_ref": _finding_ref(record, index),
                "reason": "unsupported_evidence",
                "cited": _cited_reference(record),
                "found_in_corpus": False,
                "closest_match": None,
            })
        annotated.append(record)
    return annotated, {"findings_total": len(annotated), "grounded": grounded,
                       "stale": stale, "unsupported": unsupported,
                       "corpus_tokens": len(evidence_tokens(evidence_corpus(materialized))),
                       "corpus_observations": len(materialized),
                       "rejected_findings": rejected}


def fabricated_evidence(stats):
    """Any unsupported claimed evidence blocks completion, including mixed lists."""
    return bool(stats.get("stale") or stats.get("unsupported"))
