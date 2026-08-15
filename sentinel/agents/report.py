"""Report Generator agent — turns confirmed findings into Markdown + PDF."""

from __future__ import annotations

import re
from pathlib import Path

from ..reporting import markdown_to_pdf
from .base import AgentContext


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "target"


def report_agent(ctx: AgentContext, state: dict) -> dict:
    target = state["target"]
    confirmed = state.get("confirmed_findings", [])
    meta = dict(state.get("meta", {}))

    # Be honest about where the data came from: if a live scan was requested but
    # ZAP/Nmap were unreachable, the tools fall back to bundled sample data.
    live_requested = not state.get("mock")
    fell_back = live_requested and (ctx.zap.used_mock or ctx.nmap.used_mock)
    if state.get("mock"):
        data_source = "sample data (mock mode)"
    elif fell_back:
        data_source = "live requested — fell back to bundled sample data"
    else:
        data_source = "live tools (OWASP ZAP + Nmap)"

    meta.update(
        {
            "scan_id": state.get("scan_id"),
            "mock": state.get("mock"),
            "data_source": data_source,
            "llm_backend": ctx.llm.backend,
            "model": ctx.llm.model,
        }
    )

    markdown = ctx.llm.write_report(target, confirmed, meta)

    reports_dir = Path(ctx.settings.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    stem = f"{_slug(state.get('host') or target)}-{state.get('scan_id', 'scan')[:8]}"
    md_path = reports_dir / f"{stem}.md"
    pdf_path = reports_dir / f"{stem}.pdf"

    md_path.write_text(markdown, encoding="utf-8")

    log: list[str] = []
    if fell_back:
        log.append(
            "[WARN] live ZAP/Nmap were unreachable — results are from bundled "
            "sample data, NOT a live scan of the target."
        )
    log.append(f"[report] Markdown written to {md_path}")
    pdf_written: str | None = None
    try:
        markdown_to_pdf(markdown, str(pdf_path))
        pdf_written = str(pdf_path)
        log.append(f"[report] PDF written to {pdf_path}")
    except Exception as exc:  # PDF is a nice-to-have; never fail the run on it
        log.append(f"[report] PDF generation skipped: {exc}")

    return {
        "status": "done",
        "report_markdown": markdown,
        "report_path": str(md_path),
        "pdf_path": pdf_written or "",
        "log": log,
    }
