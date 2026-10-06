"""Engagement reporting: findings extraction, enrichment and rendering.

The report layer is **read-only with respect to the engagement**: it reads the
durable audit trail, the persisted ToolResults (the ReAct observations) and the
artifact metadata, and it never invents a finding. Anything the toolkit did not
actually observe is either omitted or reported as a *failed attempt*.

No third-party dependency is used: the Markdown and the (self-contained) HTML
are produced with plain string templates.
"""

from .models import (
    SEVERITY_ORDER,
    EngagementReport,
    Evidence,
    FailedAttempt,
    Finding,
    FrameworkMapping,
)
from .extractor import extract_engagement_metadata, extract_findings
from .markdown import render_markdown, render_markdown_json
from .html import render_html
from .sarif import render_sarif

__all__ = [
    "SEVERITY_ORDER",
    "EngagementReport",
    "Evidence",
    "FailedAttempt",
    "Finding",
    "FrameworkMapping",
    "extract_engagement_metadata",
    "extract_findings",
    "render_html",
    "render_markdown",
    "render_markdown_json",
    "render_sarif",
]
