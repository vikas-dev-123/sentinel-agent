"""Minimal Markdown -> PDF renderer using reportlab.

Not a full Markdown implementation — it handles the subset the report template
produces (headings, bullets, tables-as-text, fenced code) well enough to yield
a clean, readable PDF.
"""

from __future__ import annotations

from pathlib import Path

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Preformatted,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)


def _styles():
    styles = getSampleStyleSheet()
    # Use distinct names to avoid clashing with reportlab's built-in styles.
    styles.add(
        ParagraphStyle(
            name="SentinelCode",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8,
            leftIndent=12,
            backColor="#f4f4f4",
        )
    )
    styles.add(
        ParagraphStyle(
            name="SentinelBullet",
            parent=styles["Normal"],
            leftIndent=16,
            bulletIndent=6,
            alignment=TA_LEFT,
        )
    )
    return styles


def _inline(text: str) -> str:
    """Convert a little Markdown inline syntax to reportlab mini-HTML."""
    import re

    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`(.+?)`", r'<font face="Courier">\1</font>', text)
    return text


def markdown_to_pdf(markdown_text: str, path: str) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    styles = _styles()
    doc = SimpleDocTemplate(
        path,
        pagesize=letter,
        leftMargin=0.9 * inch,
        rightMargin=0.9 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.9 * inch,
    )
    flow = []
    in_code = False
    code_buf: list[str] = []

    for line in markdown_text.splitlines():
        if line.strip().startswith("```"):
            if in_code:
                flow.append(Preformatted("\n".join(code_buf), styles["SentinelCode"]))
                flow.append(Spacer(1, 6))
                code_buf = []
            in_code = not in_code
            continue
        if in_code:
            code_buf.append(line)
            continue

        stripped = line.strip()
        if not stripped:
            flow.append(Spacer(1, 6))
        elif stripped.startswith("### "):
            flow.append(Paragraph(_inline(stripped[4:]), styles["Heading3"]))
        elif stripped.startswith("## "):
            flow.append(Paragraph(_inline(stripped[3:]), styles["Heading2"]))
        elif stripped.startswith("# "):
            flow.append(Paragraph(_inline(stripped[2:]), styles["Title"]))
        elif stripped.startswith("|"):
            # Render table rows as monospace lines (skip separator rows).
            if set(stripped) <= set("|-: "):
                continue
            flow.append(Preformatted(stripped, styles["SentinelCode"]))
        elif stripped.startswith("- "):
            flow.append(Paragraph(_inline(stripped[2:]), styles["SentinelBullet"], bulletText="•"))
        elif stripped.startswith("*") and stripped.endswith("*"):
            flow.append(Paragraph(f"<i>{_inline(stripped.strip('*'))}</i>", styles["Normal"]))
        else:
            flow.append(Paragraph(_inline(stripped), styles["Normal"]))

    if code_buf:
        flow.append(Preformatted("\n".join(code_buf), styles["SentinelCode"]))

    doc.build(flow)
    return path
