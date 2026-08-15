"""Recon agent — drives Nmap and interprets the service map."""

from __future__ import annotations

from .base import AgentContext


def recon_agent(ctx: AgentContext, state: dict) -> dict:
    host = state.get("host") or state["target"]
    raw = ctx.nmap.recon(host, scan_type="quick")
    findings = ctx.llm.interpret("recon", state["target"], raw)
    src = "sample data" if ctx.nmap.used_mock else "live Nmap"
    return {
        "raw_results": {"recon": findings},
        "log": [
            f"[recon] {src}: {len(raw)} open service(s), "
            f"{len(findings)} interpreted finding(s)."
        ],
    }
