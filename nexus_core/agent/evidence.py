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


#: A *claim* of root access in a finding's prose. A bare ``root`` is not one:
#: measured in Simple CTF (2026-10-18), a loot finding titled with the file it
#: captured (``root.txt``) cited the loot fact that proved it and the gate
#: refused it as if it had claimed the escalation. Paths and file names are
#: excluded, the words that describe the escalation are not.
_ROOT_CLAIM_RE = re.compile(r"(?<![\w/])root(?![\w./])|uid=0|administrator", re.IGNORECASE)


def _flag_tokens(value: Any) -> frozenset[str]:
    """Flag-shaped tokens inside *value* (imported lazily: the planner is heavy)."""
    from .planner import flag_tokens

    return frozenset(flag_tokens(value))


def _declared_flags(finding: Mapping[str, Any]) -> frozenset[str]:
    """Flags the finding itself asserts, in its ``value`` or in its prose."""
    return _flag_tokens(finding.get("value")) | _flag_tokens(finding_text(finding))


def _observed_flags(observation: Mapping[str, Any]) -> frozenset[str]:
    """Flags the observation actually captured (its whole payload, ``value`` included)."""
    return _flag_tokens(observation)


def _flag_conflict(finding: Mapping[str, Any], observation: Mapping[str, Any]) -> str:
    """The flags the finding claims that the observation does not carry (or "").

    A citation may summarize the observation freely -its prose, its extra keys
    and its own view of the target all get replaced by the observation's value
    when the finding grounds- but a **flag** is the one value that is either the
    captured one or a fabrication. Changing it is the only value contradiction
    that still refuses a citation (V1-50): measured in Simple CTF (2026-10-18),
    the gate refused three real citations in a row for keys such as ``port`` and
    the run never closed with both flags already on the board.
    """
    declared = _declared_flags(finding)
    observed = _observed_flags(observation)
    if not declared or not observed:
        # Nothing to contradict: a citation that names no flag can only be a
        # summary, and an assertion that captured no flag has no flag to
        # disagree with. Neither case can put a model-written flag into the
        # report -grounding replaces the finding's value with the observation's.
        return ""
    unexpected = declared - observed
    return ",".join(sorted(unexpected))


def grounding_proof(finding, observations, *, run_id=None):
    """The observation that substantiates *finding*, or ``None`` (V1-50).

    The invocation is the identity: a citation names an assertion the gateway
    produced in this run, and any assertion of that invocation can substantiate
    it. ``fact_type`` and ``target`` only **rank** the candidates (exact first,
    then same type, then the rest), so a model that cites ``access`` where the
    invocation also asserted ``host`` -or that writes the target differently- is
    still pointing at real evidence instead of at a guess. The invocation must
    exist: an id that is not in the corpus is still ``stale_evidence``.

    Two guards survive the relaxation, because they are about truth rather than
    about wording: a finding whose prose claims root needs a verified
    ``privilege`` assertion, and a finding may not name a flag the cited
    observation did not capture.
    """
    if not isinstance(finding, Mapping) or not finding.get("invocation_id") or not run_id:
        return None
    wanted = str(finding["invocation_id"])
    cited_type = str(finding.get("fact_type") or "")
    cited_target = str(finding.get("target") or "")
    claims_root = bool(_ROOT_CLAIM_RE.search(finding_text(finding)))
    exact: list[Mapping[str, Any]] = []
    typed: list[Mapping[str, Any]] = []
    rest: list[Mapping[str, Any]] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        if not (observation.get("verified") is True
                and observation.get("verification_method")
                and str(observation.get("invocation_id") or "") == wanted
                and str(observation.get("run_id") or "") == str(run_id)):
            continue
        # A reference to anything but a privilege assertion cannot substantiate a
        # root claim, however well it matches.
        if claims_root and observation.get("fact_type") != "privilege":
            continue
        fact_type = str(observation.get("fact_type") or "")
        target = str(observation.get("target") or "")
        if fact_type == cited_type and target == cited_target:
            exact.append(observation)
        elif fact_type == cited_type:
            typed.append(observation)
        else:
            rest.append(observation)
    for tier in (exact, typed, rest):
        for observation in tier:
            if not _flag_conflict(finding, observation):
                return observation
    return None


def _refusal_reason(finding: Mapping[str, Any], observations, run_id) -> str:
    """Why no observation substantiates *finding* (the refusal's detail)."""
    wanted = str(finding.get("invocation_id") or "")
    candidates = [
        observation
        for observation in observations
        if isinstance(observation, Mapping)
        and observation.get("verified") is True
        and observation.get("verification_method")
        and str(observation.get("invocation_id") or "") == wanted
        and str(observation.get("run_id") or "") == str(run_id)
    ]
    if not candidates:
        return "no_matching_observation"
    if _ROOT_CLAIM_RE.search(finding_text(finding)) and not any(
        observation.get("fact_type") == "privilege" for observation in candidates
    ):
        return "root_claim_needs_privilege_fact"
    flags = sorted(
        {
            flag
            for observation in candidates
            for flag in _flag_conflict(finding, observation).split(",")
            if flag
        }
    )
    if flags:
        return "flag_conflict:" + ",".join(flags)
    return "no_matching_observation"


def is_grounded(finding, observations, *, run_id=None, objections=None):
    """Whether a verified assertion of this run substantiates *finding*.

    Token coincidence and server/model-authored verification flags carry no
    authority. Observations must come from gateway verifier assertions. When
    ``objections`` is a list, the reason the check failed is appended to it, so
    the refusal can name it instead of only its bucket (V1-48).
    """
    def refuse(reason: str) -> bool:
        if objections is not None:
            objections.append(reason)
        return False

    if not isinstance(finding, Mapping) or not finding.get("invocation_id") or not run_id:
        return refuse("missing_citation_or_run")
    materialized = list(observations or ())
    if grounding_proof(finding, materialized, run_id=run_id) is not None:
        return True
    return refuse(_refusal_reason(finding, materialized, run_id))


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
        proof = grounding_proof(record, materialized, run_id=run_id)
        if proof is not None:
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
            # ``reason`` stays the bucket the counters already use; ``objection``
            # carries the precise cause when the citation was real (the model was
            # told "no coincide con ninguna observación" for findings whose
            # invocation/type/target matched the observation exactly).
            objections: list[str] = []
            is_grounded(record, materialized, run_id=run_id, objections=objections)
            rejected.append({
                "finding_ref": _finding_ref(record, index),
                "reason": "stale_evidence",
                "objection": objections[0] if objections else "",
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
