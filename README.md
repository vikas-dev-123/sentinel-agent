# SentinelAgent — AI Multi-Agent Penetration Testing Engine

A multi-agent system (LangGraph) that automates web-app security testing. Specialized
LLM agents drive real security tools (**OWASP ZAP**, **Nmap**), and an LLM (Claude or a
Hugging Face model) interprets, confirms, and explains the tool output — filtering false
positives and producing a structured penetration-test report.

**🔗 [Live demo](https://huggingface.co/spaces/vikas434433434/sentinel-agent)** (static
showcase of real sample output) · run it live locally with the CLI/API below.

> **Core principle:** agents never guess vulnerabilities from LLM knowledge. Every
> finding originates from an actual tool scan. The LLM's job is to *interpret, confirm,
> and explain* — never to fabricate.

Built from [`pentest-agent-CLAUDE.md`](pentest-agent-CLAUDE.md).

---

## Architecture

```
                    [ target URL ]
                          │
                   ┌──────▼───────┐
                   │ Orchestrator │  (LangGraph root)
                   └──────┬───────┘
        ┌────────┬────────┼─────────┬───────────┐
        ▼        ▼        ▼         ▼           ▼
     Recon     SQLi      XSS       Auth     Misconfig      (fan-out, run in parallel)
     (Nmap)    (ZAP)     (ZAP)     (ZAP)     (ZAP)
        └────────┴────────┼─────────┴───────────┘
                          ▼
              ┌───────────────────────┐
              │ Findings Confirmation │  (LLM: filter FPs, assign severity)
              └───────────┬───────────┘
                          ▼
              ┌───────────────────────┐
              │   Report Generator    │  (Markdown + PDF)
              └───────────────────────┘
```

Each category agent follows one pattern: **call tool → get raw output → interpret with a
narrow, category-specific LLM prompt → emit structured findings** into shared graph state.

---

## Runs anywhere — two modes

The project is designed to run today and be "real" when the lab is up:

| Dependency | If present | If absent |
|---|---|---|
| LLM key (Claude **or** Hugging Face) | that model does interpret / confirm / report | Deterministic **heuristic** analyzer does the same steps |
| OWASP ZAP daemon | Live spider + active scan | Falls back to bundled sample alerts |
| Nmap binary | Live service discovery | Falls back to bundled sample recon |
| `--mock` flag | — | Forces sample data for everything |

So `--mock` gives a complete, deterministic, offline demo; wiring up ZAP/Nmap/an LLM makes
it a real scanner with no code changes.

### Choosing the reasoning backend

Set `SENTINEL_LLM_PROVIDER` to `auto` (default) / `claude` / `hf` / `ollama` / `heuristic`.

```bash
# Hugging Face (hosted, OpenAI-compatible router):
export SENTINEL_LLM_PROVIDER=hf
export HF_API_KEY=hf_xxx
export HF_MODEL=Qwen/Qwen2.5-7B-Instruct     # any chat model your token can access
python -m sentinel.cli scan http://localhost/dvwa --mock

# Ollama (local, free):
export SENTINEL_LLM_PROVIDER=ollama
export OLLAMA_MODEL=llama3.1:8b              # after: ollama pull llama3.1:8b
python -m sentinel.cli scan http://localhost/dvwa --mock
```

Hugging Face and Ollama are both called via the OpenAI-compatible `/v1/chat/completions`
API, so any instruct/chat model works — just change the model name. If a call fails or
returns unparseable output, it falls back to the heuristic so a run never breaks.

---

## Quick start

```bash
pip install -r requirements.txt

# Offline demo (no ZAP, no Nmap, no API key needed):
python -m sentinel.cli scan http://localhost/dvwa --mock

# Phase-1 loop only (single tool -> single LLM interpretation):
python scripts/phase1_demo.py --mock --category sqli

# API server:
uvicorn sentinel.api:app --reload
curl -X POST localhost:8000/scan \
  -H 'content-type: application/json' \
  -d '{"target":"http://localhost/dvwa","mock":true}'
```

Reports (Markdown + PDF) are written to `reports/`.

### With the real lab

```bash
docker compose up -d          # DVWA (:8081), Juice Shop (:3000), ZAP (:8080)
export ANTHROPIC_API_KEY=...   # optional, enables Claude reasoning
python -m sentinel.cli scan http://localhost:8081
```

---

## Configuration

Copy `.env.example` to `.env`. Key variables: `ANTHROPIC_API_KEY`, `SENTINEL_CLAUDE_MODEL`
(default `claude-opus-5`), `ZAP_API_URL`, `ZAP_API_KEY`, `NMAP_BINARY`, `SENTINEL_MOCK`,
`SENTINEL_ALLOW_ANY`, `SENTINEL_APPROVED_HOSTS`, `SENTINEL_REPORTS_DIR`.

 ---

## Project layout

```
sentinel/
  config.py          # settings + scope/authorization enforcement
  state.py           # shared LangGraph state (TypedDict + reducers)
  llm/               # Claude client + heuristic fallback + prompts
  tools/             # ZAP and Nmap wrappers (live + sample fallback)
  agents/            # recon, scanners (sqli/xss/auth/misconfig), confirmation, report
  reporting/         # Markdown template + Markdown->PDF
  orchestrator.py    # LangGraph graph wiring
  cli.py             # command-line entrypoint
  api.py             # FastAPI layer
scripts/phase1_demo.py
sample_data/         # realistic ZAP alerts + Nmap output for offline runs
tests/               # end-to-end pipeline tests (offline)
```

## Build phases (from the spec)

1. Single tool → LLM loop — `scripts/phase1_demo.py`
2. LangGraph, 2 agents — subset of `orchestrator.py`
3. All 5 category agents — `agents/recon.py`, `agents/scanners.py`
4. Findings Confirmation — `agents/confirmation.py`
5. Report Generator (Markdown → PDF) — `agents/report.py`, `reporting/`
6. FastAPI layer — `api.py`

## Tests

```bash
python -m pytest tests/ -q
```
