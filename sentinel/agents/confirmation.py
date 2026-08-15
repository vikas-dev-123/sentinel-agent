"""Findings Confirmation agent.

Collects all raw findings, filters false positives, deduplicates, and assigns
severity. This is the step that makes the system 'smart' rather than a wrapper
around five scanners (spec Section 5 / Phase 4).
"""

from __future__ import annotations

from .base import AgentContext


def confirmation_agent(ctx: AgentContext, state: dict) -> dict:
    target = state["target"]
    raw_results = state.get("raw_results", {})
    confirmed = ctx.llm.confirm(target, raw_results)

    kept = [f for f in confirmed if not f.get("false_positive")]
    dropped = len(confirmed) - len(kept)

    return {
        "status": "confirming",
        "confirmed_findings": confirmed,
        "log": [
            f"[confirm] {len(kept)} confirmed finding(s), "
            f"{dropped} discarded as false positive/noise "
            f"(via {ctx.llm.backend})."
        ],
    }
