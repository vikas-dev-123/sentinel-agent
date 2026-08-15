# Deploying SentinelAgent to Hugging Face Spaces

Two things people confuse — keep them separate:

1. **Using HF as the LLM** → you upload **nothing**. The model is hosted by HF.
   You just provide a token (`HF_API_KEY`). Done already in the code.
2. **Deploying this app** → you push this repo to a **Hugging Face Space** so
   anyone can run it in a browser.

> The hosted Space has no ZAP daemon, no Nmap, and no real target, so it runs in
> **mock mode** on the bundled sample data — which still demonstrates the full
> multi-agent pipeline and report generation. Add an `HF_API_KEY` secret to make
> the reasoning use a real Hugging Face model instead of the heuristic.

---

## Option A — Gradio Space (simplest, recommended)

### 1. Create the Space
- Go to <https://huggingface.co/new-space>
- Owner: your account · Space name: `sentinel-agent`
- **SDK: Gradio** · Hardware: CPU basic (free) · Visibility: Public

### 2. Add the Space frontmatter
A Gradio Space's `README.md` must start with this YAML block. Paste it at the
**very top** of `README.md` before pushing (or edit the README in the Space UI):

```yaml
---
title: SentinelAgent
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: gradio
app_file: app.py
pinned: false
---
```

Spaces reads `requirements.txt` and runs `app.py` automatically.

### 3. Push the code
```bash
# from the project folder
git init
git add .
git commit -m "SentinelAgent"

# 'hf' is the Hugging Face git remote for your Space
git remote add hf https://huggingface.co/spaces/<your-username>/sentinel-agent
git push hf HEAD:main
```
(You authenticate with your HF username + an **access token** as the password,
or run `huggingface-cli login` first: `pip install huggingface_hub` then
`huggingface-cli login`.)

### 4. Add the LLM secret (optional but nice)
In the Space: **Settings → Variables and secrets → New secret**
- `HF_API_KEY` = your `hf_...` token
- `SENTINEL_LLM_PROVIDER` = `hf`
- `HF_MODEL` = `Qwen/Qwen2.5-7B-Instruct`  (or any chat model your token can use)

The Space rebuilds and your demo is live at
`https://huggingface.co/spaces/<your-username>/sentinel-agent`.

---

## Option B — Docker Space (uses the Dockerfile)

Same as above but pick **SDK: Docker** when creating the Space, and use this
frontmatter instead:

```yaml
---
title: SentinelAgent
emoji: 🛡️
colorFrom: indigo
colorTo: purple
sdk: docker
app_port: 7860
pinned: false
---
```

The included `Dockerfile` installs deps and runs `app.py` on port 7860. Add the
same secrets as in Option A.

---

## Local sanity check before deploying

```bash
pip install -r requirements.txt
python app.py           # opens the same UI at http://localhost:7860
```

---

## Notes
- **Do not** set `SENTINEL_ALLOW_ANY=1` on a public Space — the demo must stay on
  practice targets only.
- Real ZAP/Nmap scanning is for your **local** machine (`docker compose up -d`),
  not for a public Space.
- If a Hugging Face model call fails or a model is gated/out of credits, the app
  falls back to the heuristic so the demo never breaks.
