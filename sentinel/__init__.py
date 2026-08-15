"""SentinelAgent — AI Multi-Agent Penetration Testing Engine.

A LangGraph multi-agent system that drives real security tools (OWASP ZAP, Nmap),
uses Claude to interpret and confirm findings, and produces a structured report.

Every finding must originate from an actual tool scan — the LLM interprets and
confirms tool output, it never fabricates vulnerabilities.
"""

__version__ = "0.1.0"
