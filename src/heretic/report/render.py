"""Render confirmed findings. Every finding carries an Oracle-proven, reproducible
PoC + a confidence score (see docs/03-ORACLE.md) — the report never contains
speculative findings. Chained findings surface higher-impact escalations."""
from __future__ import annotations

import html
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ..core.models import Finding

_SEV_COLOR = {"critical": "red", "high": "orange1", "medium": "yellow",
              "low": "cyan", "info": "grey50"}
_SEV_HEX = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207",
            "low": "#0e7490", "info": "#475569"}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def render(findings: list[Finding], *, fmt: str = "table",
           html_path: Path | None = None, console: Console | None = None) -> None:
    console = console or Console()
    findings = sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity.value, 9))

    if fmt == "json":
        console.print_json(json.dumps([_as_dict(f) for f in findings]))
    elif fmt == "md":
        console.print(_as_markdown(findings))
    else:
        _as_table(findings, console)

    if html_path:
        html_path.write_text(_as_html(findings))
        console.print(f"[green]report written:[/] {html_path}")


def _conf(f: Finding) -> float:
    return float(f.proof.get("confidence", 1.0)) if isinstance(f.proof, dict) else 1.0


def _as_dict(f: Finding) -> dict:
    return {
        "title": f.title, "invariant": f.invariant_id, "class": f.bug_class,
        "severity": f.severity.value, "confidence": _conf(f),
        "expected": f.expected, "observed": f.observed, "impact": f.impact,
        "proof": f.proof, "remediation": f.remediation, "chained_from": f.chained_from,
    }


def _as_table(findings: list[Finding], console: Console) -> None:
    t = Table(title=f"HERETIC — {len(findings)} confirmed findings")
    for col in ("severity", "conf", "class", "invariant", "title"):
        t.add_column(col)
    for f in findings:
        color = _SEV_COLOR.get(f.severity.value, "white")
        t.add_row(f"[{color}]{f.severity.value.upper()}[/]", f"{_conf(f):.0%}",
                  f.bug_class, f.invariant_id, f.title)
    console.print(t)


def _as_markdown(findings: list[Finding]) -> str:
    out = [f"# HERETIC report — {len(findings)} confirmed findings\n"]
    for f in findings:
        out += [
            f"## [{f.severity.value.upper()}] {f.title}",
            f"- **Class:** {f.bug_class}  ·  **Invariant:** {f.invariant_id}  ·  "
            f"**Confidence:** {_conf(f):.0%}",
            f"- **Expected:** {f.expected}",
            f"- **Observed:** {f.observed}",
        ]
        if f.impact:
            out.append(f"- **Business impact:** {f.impact}")
        if f.chained_from:
            out.append(f"- **Chained from:** {', '.join(f.chained_from)}")
        out += [
            f"- **Remediation:** {f.remediation}",
            f"- **PoC:** `{json.dumps(f.proof.get('poc', f.chained_from))}`\n",
        ]
    return "\n".join(out)


def _as_html(findings: list[Finding]) -> str:
    def esc(x: object) -> str:
        return html.escape(str(x))

    cards = []
    for f in findings:
        sev = f.severity.value
        hexc = _SEV_HEX.get(sev, "#475569")
        rows = [
            ("Class", f.bug_class), ("Invariant", f.invariant_id),
            ("Confidence", f"{_conf(f):.0%}"),
            ("Expected", f.expected), ("Observed", f.observed),
        ]
        if f.impact:
            rows.append(("Business impact", f.impact))
        if f.chained_from:
            rows.append(("Chained from", ", ".join(f.chained_from)))
        rows.append(("Remediation", f.remediation))
        body = "".join(
            f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in rows if v
        )
        poc = esc(json.dumps(f.proof.get("poc", f.chained_from), indent=2))
        cards.append(
            f'<article class="card">'
            f'<header><span class="badge" style="background:{hexc}">{esc(sev.upper())}</span>'
            f'<h2>{esc(f.title)}</h2></header>'
            f'<table>{body}</table>'
            f'<details><summary>Proof of concept</summary><pre>{poc}</pre></details>'
            f'</article>'
        )

    n = len(findings)
    crit = sum(1 for f in findings if f.severity.value == "critical")
    style = (
        "body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0b1020;color:#e5e7eb}"
        ".wrap{max-width:900px;margin:0 auto;padding:32px}"
        "h1{font-size:24px;margin:0 0 4px}.sub{color:#94a3b8;margin:0 0 24px}"
        ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px 20px;margin:16px 0}"
        ".card header{display:flex;align-items:center;gap:12px;margin-bottom:10px}"
        ".card h2{font-size:17px;margin:0}"
        ".badge{color:#fff;font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;letter-spacing:.04em}"
        "table{width:100%;border-collapse:collapse}"
        "th{text-align:left;color:#93c5fd;font-weight:600;width:150px;vertical-align:top;padding:3px 8px 3px 0}"
        "td{padding:3px 0;vertical-align:top}"
        "details{margin-top:10px}summary{cursor:pointer;color:#a78bfa}"
        "pre{background:#0b1020;border:1px solid #1f2937;border-radius:8px;padding:10px;overflow:auto;font-size:13px}"
    )
    return (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>HERETIC report</title><style>{style}</style></head><body><div class='wrap'>"
        f"<h1>HERETIC — business-logic findings</h1>"
        f"<p class='sub'>{n} confirmed · {crit} critical · authorized testing only</p>"
        f"{''.join(cards)}</div></body></html>"
    )
