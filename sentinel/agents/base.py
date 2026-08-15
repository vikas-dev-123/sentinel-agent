"""Shared context and helpers for agent nodes.

Each agent follows the same pattern (spec Section 5):
  1. call the appropriate tool (ZAP scan rule / Nmap scan)
  2. receive raw tool output
  3. pass raw output to the LLM with a narrow, category-specific prompt
  4. emit structured findings back into the graph state
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Settings
from ..llm import RoutedLLM
from ..tools import NmapClient, ZapClient


@dataclass
class AgentContext:
    settings: Settings
    llm: RoutedLLM  # routes parse vs reason to (possibly) different backends
    zap: ZapClient
    nmap: NmapClient


def run_zap_category(ctx: AgentContext, state: dict, category: str) -> dict:
    """Generic ZAP-backed category agent (SQLi / XSS / Auth / Misconfig)."""
    target = state["target"]
    raw = ctx.zap.alerts_for(target, category)
    findings = ctx.llm.interpret(category, target, raw)
    # Be explicit about whether this is live ZAP data or a sample-data fallback.
    src = "sample data" if ctx.zap.used_mock else "live ZAP"
    # Return only deltas; state reducers merge raw_results and append log lines.
    return {
        "raw_results": {category: findings},
        "log": [
            f"[{category}] {src}: {len(raw)} raw alert(s), "
            f"{len(findings)} interpreted finding(s)."
        ],
    }
