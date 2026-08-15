"""Gradio UI for Hugging Face Spaces (and local use).

This is the web front-end for a *deployed* demo. On Hugging Face Spaces there is
no ZAP daemon, no Nmap, and no real target, so the app runs in **mock mode**
against bundled sample data and only permits the approved practice targets. The
reasoning backend is Hugging Face when HF_API_KEY is set as a Space secret,
otherwise the deterministic heuristic.

Run locally:   python app.py
Deploy:        push to a Hugging Face Space (sdk: gradio). See DEPLOY.md.
"""

from __future__ import annotations

import gradio as gr

from sentinel.config import Settings
from sentinel.llm import LLMClient
from sentinel.orchestrator import run_scan

# Practice targets only — deployed demo never scans real hosts.
PRACTICE_TARGETS = [
    "http://localhost/dvwa",
    "http://localhost:8081",
    "http://localhost:3000",
]


def _backend_label() -> str:
    return LLMClient(Settings()).backend


def run_demo(target: str):
    settings = Settings()
    settings.mock = True          # no live tools in a hosted Space
    settings.allow_any_target = False

    state = run_scan(target, settings)

    confirmed = [
        f for f in state.get("confirmed_findings", []) if not f.get("false_positive")
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    confirmed.sort(key=lambda f: order.get(f.get("severity", "low"), 5))

    table = [
        [
            f.get("category", ""),
            f.get("severity", ""),
            f.get("confidence", ""),
            f.get("name", ""),
            f.get("endpoint", ""),
        ]
        for f in confirmed
    ]
    log = "\n".join(state.get("log", []))
    return table, state.get("report_markdown", ""), log


with gr.Blocks(title="SentinelAgent") as demo:
    gr.Markdown(
        "# 🛡️ SentinelAgent — AI Multi-Agent Pentest Engine\n"
        "Multi-agent (LangGraph) pipeline: **Recon · SQLi · XSS · Auth · Misconfig "
        "→ Confirmation → Report**. Tools (OWASP ZAP / Nmap) drive the scans; an LLM "
        "interprets, confirms, and explains — never fabricates.\n\n"
        f"> Hosted demo runs in **mock mode** on sample data. Reasoning backend: "
        f"**{_backend_label()}**."
    )
    with gr.Row():
        target = gr.Dropdown(
            PRACTICE_TARGETS, value=PRACTICE_TARGETS[0], label="Practice target"
        )
        run_btn = gr.Button("Run scan", variant="primary")

    findings = gr.Dataframe(
        headers=["Category", "Severity", "Confidence", "Finding", "Endpoint"],
        label="Confirmed findings",
        wrap=True,
    )
    report = gr.Markdown(label="Report")
    log = gr.Textbox(label="Scan log", lines=8)

    run_btn.click(run_demo, inputs=target, outputs=[findings, report, log])


if __name__ == "__main__":
    # Gradio 4.x on Spaces: no SSR/Node proxy. HF sets host/port via env.
    demo.launch(server_name="0.0.0.0", server_port=7860)
