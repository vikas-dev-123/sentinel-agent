"""Build a self-contained static demo page (index.html) for a free HF Static Space.

Runs the pipeline once (mock data) and bakes the real confirmed findings into a
single interactive HTML file — no server, no Python at runtime. Clearly labelled
as a sample-output showcase; the live scanning app runs locally (see GitHub).

    python scripts/build_static.py
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.config import Settings  # noqa: E402
from sentinel.orchestrator import run_scan  # noqa: E402

GITHUB_URL = "https://github.com/vikas-dev-123/sentinel-agent"


def gather() -> dict:
    s = Settings()
    s.mock = True
    s.anthropic_api_key = None
    s.hf_api_key = None
    s.llm_provider = "heuristic"
    st = run_scan("http://localhost/dvwa", s)
    findings = [f for f in st["confirmed_findings"] if not f.get("false_positive")]
    fps = [f for f in st["confirmed_findings"] if f.get("false_positive")]
    return {"target": st["target"], "findings": findings, "false_positives": fps}


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SentinelAgent — AI Pentest Engine</title>
<style>
:root{
  --bg:#f7f8fa; --card:#ffffff; --text:#1a1d24; --muted:#5b6472; --border:#e3e7ee;
  --accent:#4f46e5; --code:#f1f3f7;
  --crit:#b91c1c; --high:#e0562b; --med:#c2820a; --low:#2563eb; --info:#6b7280;
}
@media (prefers-color-scheme: dark){
  :root{ --bg:#0f1116; --card:#171a21; --text:#e6e9ef; --muted:#9aa4b2;
    --border:#262b36; --accent:#8b93ff; --code:#1c2029;
    --crit:#f4635a; --high:#ff8a5c; --med:#e6b23e; --low:#5b9bff; --info:#9aa4b2; }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  line-height:1.55}
.wrap{max-width:1000px;margin:0 auto;padding:28px 20px 60px}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
.hero{padding:8px 0 22px;border-bottom:1px solid var(--border);margin-bottom:26px}
.hero h1{font-size:2rem;margin:0 0 6px;letter-spacing:-.02em}
.hero p{color:var(--muted);margin:0 0 14px;max-width:70ch}
.badges{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.badge{font-size:.72rem;padding:4px 9px;border:1px solid var(--border);border-radius:999px;
  background:var(--card);color:var(--muted)}
.note{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--accent);
  border-radius:8px;padding:12px 14px;margin:22px 0;font-size:.9rem;color:var(--muted)}
.note b{color:var(--text)}
h2{font-size:1.15rem;margin:34px 0 12px;letter-spacing:-.01em}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.tile{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px}
.tile .n{font-size:1.6rem;font-weight:700} .tile .l{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.diagram{background:var(--code);border:1px solid var(--border);border-radius:10px;padding:16px;
  overflow-x:auto;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.8rem;white-space:pre;color:var(--muted)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.filters button{cursor:pointer;font:inherit;font-size:.8rem;padding:5px 11px;border-radius:999px;
  border:1px solid var(--border);background:var(--card);color:var(--muted)}
.filters button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.finding{background:var(--card);border:1px solid var(--border);border-radius:10px;margin:10px 0;overflow:hidden}
.finding summary{cursor:pointer;list-style:none;padding:13px 15px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.finding summary::-webkit-details-marker{display:none}
.sev{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em;
  padding:3px 8px;border-radius:6px;color:#fff;white-space:nowrap}
.sev.critical{background:var(--crit)} .sev.high{background:var(--high)}
.sev.medium{background:var(--med)} .sev.low{background:var(--low)} .sev.informational{background:var(--info)}
.fname{font-weight:600} .cat{font-size:.72rem;color:var(--muted);border:1px solid var(--border);padding:2px 7px;border-radius:6px}
.ep{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.74rem;color:var(--muted);margin-left:auto;
  overflow:hidden;text-overflow:ellipsis;max-width:100%}
.body{padding:0 15px 15px;border-top:1px solid var(--border)}
.body h4{margin:14px 0 4px;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.body p{margin:0 0 6px} pre.ev{background:var(--code);border-radius:8px;padding:10px 12px;overflow-x:auto;
  font-size:.78rem;white-space:pre-wrap;word-break:break-word}
footer{margin-top:44px;padding-top:18px;border-top:1px solid var(--border);color:var(--muted);font-size:.85rem}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>🛡️ SentinelAgent</h1>
    <p>An AI multi-agent penetration-testing engine. Specialized LangGraph agents drive
       real security tools (OWASP ZAP, Nmap); an LLM interprets, confirms, and explains
       every finding — it never fabricates. Findings originate only from actual tool scans.</p>
    <div class="badges">
      <span class="badge">LangGraph</span><span class="badge">OWASP ZAP</span>
      <span class="badge">Nmap</span><span class="badge">Claude / Hugging Face</span>
      <span class="badge">FastAPI</span><span class="badge">Python</span>
    </div>
    <p style="margin-top:14px"><a href="__GH__">→ Source code on GitHub</a></p>
  </div>

  <div class="note">
    <b>This is a static showcase.</b> It displays <b>real sample output</b> from a scan of a
    local DVWA practice app. The live, interactive scanner runs on your own machine
    (<code>python -m sentinel.cli scan …</code>) or as an API — see the GitHub repo.
    Nothing here scans any live system.
  </div>

  <h2>Findings by severity</h2>
  <div class="tiles" id="tiles"></div>

  <h2>Architecture</h2>
  <div class="diagram">                    [ target URL ]
                          |
                   +--------------+
                   | Orchestrator |   (LangGraph root)
                   +--------------+
       +--------+--------+--------+---------+-----------+
     Recon     SQLi     XSS      Auth     Misconfig      (run in parallel)
     (Nmap)   (ZAP)    (ZAP)    (ZAP)     (ZAP)
       +--------+--------+--------+---------+-----------+
                          |
              +-----------------------+
              | Findings Confirmation |   (LLM: filter FPs, assign severity)
              +-----------------------+
                          |
              +-----------------------+
              |   Report Generator    |   (Markdown + PDF)
              +-----------------------+</div>

  <h2>Confirmed findings <span id="count" style="color:var(--muted);font-weight:400;font-size:.9rem"></span></h2>
  <div class="filters" id="filters"></div>
  <div id="list"></div>

  <footer>
    Target: <code id="tgt"></code> · Generated offline from bundled sample data.
    <br/>Built with LangGraph + Claude/Hugging Face. <a href="__GH__">GitHub</a>.
    <br/><b>Ethics:</b> only scan systems you own or are authorized to test (DVWA / Juice Shop locally).
  </footer>
</div>

<script>
const DATA = __DATA__;
const SEV_ORDER = ["critical","high","medium","low","informational"];
const esc = s => (s||"").replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

document.getElementById('tgt').textContent = DATA.target;

// severity tiles
const counts = {};
DATA.findings.forEach(f => counts[f.severity]=(counts[f.severity]||0)+1);
document.getElementById('tiles').innerHTML = SEV_ORDER
  .filter(s => counts[s]).map(s =>
    `<div class="tile"><div class="n" style="color:var(--${s==='critical'?'crit':s==='high'?'high':s==='medium'?'med':s==='low'?'low':'info'})">${counts[s]}</div><div class="l">${s}</div></div>`
  ).join('') || '<div class="tile"><div class="n">0</div><div class="l">findings</div></div>';

// filters
const cats = Array.from(new Set(DATA.findings.map(f=>f.category)));
let active = "all";
const filters = document.getElementById('filters');
function chip(id,label){const b=document.createElement('button');b.textContent=label;b.dataset.f=id;
  if(id==="all")b.classList.add('active');b.onclick=()=>{active=id;render();
  [...filters.children].forEach(c=>c.classList.toggle('active',c.dataset.f===id));};return b;}
filters.appendChild(chip("all","All"));
cats.forEach(c=>filters.appendChild(chip(c,c)));

function sevKey(f){return SEV_ORDER.indexOf(f.severity);}
function render(){
  const list = document.getElementById('list');
  const items = DATA.findings.filter(f=>active==="all"||f.category===active)
    .sort((a,b)=>sevKey(a)-sevKey(b));
  document.getElementById('count').textContent = `(${items.length})`;
  list.innerHTML = items.map(f=>`
    <details class="finding">
      <summary>
        <span class="sev ${f.severity}">${f.severity}</span>
        <span class="fname">${esc(f.name)}</span>
        <span class="cat">${esc(f.category)}</span>
        <span class="ep">${esc(f.endpoint)}</span>
      </summary>
      <div class="body">
        ${f.description?`<h4>Description</h4><p>${esc(f.description)}</p>`:''}
        <h4>Confidence</h4><p>${esc(f.confidence)}</p>
        ${f.evidence?`<h4>Evidence</h4><pre class="ev">${esc(f.evidence)}</pre>`:''}
        ${f.remediation?`<h4>Remediation</h4><p>${esc(f.remediation)}</p>`:''}
      </div>
    </details>`).join('');
}
render();
</script>
</body>
</html>
"""


def _safe_json(obj) -> str:
    """JSON safe to embed inside a <script> tag.

    Evidence/payloads can contain literal `</script>` (e.g. an XSS payload),
    which would close the script tag early. Unicode-escape the HTML-significant
    characters; they decode back to the same values in the JS string literal.
    """
    return (
        json.dumps(obj)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def main() -> int:
    data = gather()
    out = PAGE.replace("__DATA__", _safe_json(data)).replace("__GH__", GITHUB_URL)
    Path("index.html").write_text(out, encoding="utf-8")
    print(f"index.html written ({len(data['findings'])} findings baked in)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
