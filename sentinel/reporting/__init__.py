"""Report rendering: deterministic Markdown template + Markdown->PDF."""

from .markdown import render_markdown
from .pdf import markdown_to_pdf

__all__ = ["render_markdown", "markdown_to_pdf"]
