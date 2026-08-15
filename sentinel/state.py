"""Shared state object passed through the LangGraph run.

Mirrors Section 6 of the spec. Uses a TypedDict so LangGraph can merge partial
updates returned by each node.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict

# The five MVP categories plus recon.
Category = Literal["recon", "sqli", "xss", "auth", "misconfig"]
Severity = Literal["informational", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]

Status = Literal["pending", "recon", "scanning", "confirming", "reporting", "done", "error"]


def merge_raw(
    existing: dict[str, list] | None, incoming: dict[str, list] | None
) -> dict[str, list]:
    """Reducer so category agents can write into raw_results concurrently.

    Each agent owns a distinct category key, so merging is a plain dict update.
    """
    merged: dict[str, list] = dict(existing or {})
    for key, value in (incoming or {}).items():
        merged[key] = value
    return merged


def append_lists(existing: list | None, incoming: list | None) -> list:
    """Reducer so parallel nodes can append log/error lines without clobbering."""
    return list(existing or []) + list(incoming or [])


class RawFinding(TypedDict, total=False):
    """A single unconfirmed hit straight from a tool (ZAP alert / Nmap service)."""

    category: Category
    endpoint: str
    param: str
    name: str
    description: str
    evidence: str
    solution: str
    risk: str
    confidence: str
    cweid: str
    source: str  # "zap" | "nmap"


class ConfirmedFinding(TypedDict, total=False):
    category: Category
    endpoint: str
    name: str
    severity: Severity
    confidence: Confidence
    evidence: str
    description: str
    remediation: str
    false_positive: bool
    reasoning: str


class ScanState(TypedDict, total=False):
    scan_id: str
    target: str
    host: str
    status: Status
    mock: bool

    # raw_results[category] -> list[RawFinding]
    raw_results: Annotated[dict[str, list], merge_raw]

    confirmed_findings: list[ConfirmedFinding]
    report_markdown: str
    report_path: str
    pdf_path: str

    errors: Annotated[list[str], append_lists]
    log: Annotated[list[str], append_lists]
    meta: dict[str, Any]
