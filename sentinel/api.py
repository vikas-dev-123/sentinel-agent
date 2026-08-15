"""FastAPI layer (spec Phase 6): trigger scans and fetch reports over HTTP.

    uvicorn sentinel.api:app --reload
    curl -X POST localhost:8000/scan -d '{"target":"http://localhost/dvwa","mock":true}' \
         -H 'content-type: application/json'
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from .config import ScopeError, Settings
from .llm import LLMClient
from .orchestrator import run_scan

app = FastAPI(title="SentinelAgent", version="0.1.0")


class ScanRequest(BaseModel):
    target: str
    mock: bool = False
    allow_any: bool = False
    model: str | None = None


class Finding(BaseModel):
    category: str = ""
    name: str = ""
    severity: str = ""
    confidence: str = ""
    endpoint: str = ""
    remediation: str = ""


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    analysis_backend: str
    mock: bool
    findings: list[Finding]
    report_path: str
    pdf_path: str
    log: list[str]


@app.get("/health")
def health() -> dict:
    llm = LLMClient(Settings())
    return {"status": "ok", "llm": llm.backend, "model": llm.model}


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest) -> ScanResponse:
    settings = Settings()
    if req.mock:
        settings.mock = True
    if req.allow_any:
        settings.allow_any_target = True
    if req.model:
        settings.claude_model = req.model

    try:
        state = run_scan(req.target, settings)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    confirmed = [
        Finding(**{k: f.get(k, "") for k in Finding.model_fields})
        for f in state.get("confirmed_findings", [])
        if not f.get("false_positive")
    ]
    return ScanResponse(
        scan_id=state.get("scan_id", ""),
        target=state.get("target", ""),
        status=state.get("status", ""),
        analysis_backend=str(state.get("meta", {}).get("llm_backend", "heuristic")),
        mock=bool(state.get("mock")),
        findings=confirmed,
        report_path=state.get("report_path", ""),
        pdf_path=state.get("pdf_path", ""),
        log=state.get("log", []),
    )


@app.get("/reports/{name}", response_class=PlainTextResponse)
def get_report(name: str):
    settings = Settings()
    path = (Path(settings.reports_dir) / name).resolve()
    reports_root = Path(settings.reports_dir).resolve()
    if reports_root not in path.parents and path != reports_root:
        raise HTTPException(status_code=400, detail="Invalid report path")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    if path.suffix == ".pdf":
        return FileResponse(str(path), media_type="application/pdf")
    return PlainTextResponse(path.read_text(encoding="utf-8"))
