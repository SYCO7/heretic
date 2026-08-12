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
           html_path: Path | None = None, sarif_path: Path | None = None,
           target: str = "", console: Console | None = None) -> None:
    console = console or Console()
    findings = sorted(findings, key=lambda f: _SEV_ORDER.get(f.severity.value, 9))

    if fmt == "json":
        console.print_json(json.dumps([_as_dict(f) for f in findings]))
    elif fmt == "md":
        console.print(_as_markdown(findings))
    else:
        _as_table(findings, console)

    if html_path:
        html_path.write_text(_as_html(findings, target))
        console.print(f"[green]report written:[/] {html_path}")
    if sarif_path:
        sarif_path.write_text(json.dumps(to_sarif(findings, target), indent=2))
        console.print(f"[green]SARIF written:[/] {sarif_path} (upload to GitHub code scanning)")


# CVSS-like scores for GitHub code-scanning severity
_SEV_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.1", "info": "1.0"}
_SEV_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(findings: list[Finding], target: str = "") -> dict:
    """SARIF 2.1.0 — ingestible by GitHub / GitLab / Azure code scanning."""
    classes = {f.bug_class for f in findings}
    rules = [{
        "id": c,
        "name": c.replace("_", " ").title().replace(" ", ""),
        "shortDescription": {"text": c.replace("_", " ")},
        "fullDescription": {"text": _RULE_DESC.get(c, "A confirmed business-logic vulnerability.")},
        "helpUri": "https://github.com/SYCO7/heretic",
        "properties": {"tags": ["security", "business-logic"]},
    } for c in sorted(classes)]

    results = []
    for f in findings:
        sev = f.severity.value
        poc = f.proof.get("poc") if isinstance(f.proof, dict) else None
        uri = _finding_uri(f, target)
        results.append({
            "ruleId": f.bug_class,
            "level": _SEV_LEVEL.get(sev, "warning"),
            "message": {"text": f"{f.title}\nObserved: {f.observed}\nRemediation: {f.remediation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
            "properties": {
                "security-severity": _SEV_SCORE.get(sev, "5.0"),
                "confidence": _conf(f), "invariant": f.invariant_id,
                "poc": poc, "oracle": (f.proof or {}).get("oracle"),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "HERETIC", "informationUri": "https://github.com/SYCO7/heretic",
                "version": _version(), "rules": rules,
            }},
            "results": results,
        }],
    }


_RULE_DESC = {
    "bola": "Broken Object-Level Authorization (IDOR): a user reads another user's object.",
    "bfla": "Broken Function-Level Authorization: an admin function reachable by the wrong role.",
    "excessive_data_exposure": "An endpoint returns records belonging to other users / exposes PII.",
    "mass_assignment": "A privileged field is accepted from the client (e.g. role at registration).",
    "price_tamper": "The server trusts a client-supplied price / quantity.",
    "workflow_bypass": "A workflow step is finalized without its prerequisite (e.g. order without payment).",
    "race_condition": "A check-then-act flow is not atomic (double-spend / limit bypass).",
    "chain": "Confirmed primitives compose into a higher-impact attack.",
}


def _finding_uri(f: Finding, target: str) -> str:
    poc = (f.proof or {}).get("poc") if isinstance(f.proof, dict) else None
    path = (f.proof or {}).get("path") or (f.proof or {}).get("list_url")
    if not path and isinstance(poc, list) and poc and isinstance(poc[0], dict):
        path = poc[0].get("url")
    return f"{target.rstrip('/')}{path}" if (target and path) else (path or f.invariant_id)


def _version() -> str:
    from .. import __version__
    return __version__


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


def _as_html(findings: list[Finding], target: str = "") -> str:
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

    from collections import Counter

    n = len(findings)
    sev_counts = Counter(f.severity.value for f in findings)
    cls_counts = Counter(f.bug_class for f in findings)
    sev_summary = " · ".join(f"{sev_counts[s]} {s}"
                             for s in ("critical", "high", "medium", "low", "info") if sev_counts.get(s))
    chips = "".join(f"<span class='chip'>{esc(c.replace('_', ' '))} ×{cls_counts[c]}</span>"
                    for c in sorted(cls_counts))
    tgt = f"<span class='tgt'>{esc(target)}</span> · " if target else ""
    style = (
        "body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0b1020;color:#e5e7eb}"
        ".wrap{max-width:900px;margin:0 auto;padding:32px}"
        "h1{font-size:24px;margin:0 0 4px}.sub{color:#94a3b8;margin:0 0 14px}"
        ".chips{margin:0 0 24px;display:flex;flex-wrap:wrap;gap:6px}"
        ".chip{background:#1f2937;border:1px solid #374151;border-radius:999px;padding:3px 10px;font-size:12px;color:#cbd5e1}"
        ".tgt{color:#93c5fd;font-family:ui-monospace,monospace}"
        ".card{background:#111827;border:1px solid #1f2937;border-radius:12px;padding:18px 20px;margin:16px 0}"
        ".card header{display:flex;align-items:center;gap:12px;margin-bottom:10px}"
        ".card h2{font-size:17px;margin:0}"
        ".badge{color:#fff;font-size:11px;font-weight:700;padding:3px 8px;border-radius:999px;letter-spacing:.04em}"
        "table{width:100%;border-collapse:collapse}"
        "th{text-align:left;color:#93c5fd;font-weight:600;width:150px;vertical-align:top;padding:3px 8px 3px 0}"
        "td{padding:3px 0;vertical-align:top}"
        "details{margin-top:10px}summary{cursor:pointer;color:#a78bfa}"
        "pre{background:#0b1020;border:1px solid #1f2937;border-radius:8px;padding:10px;overflow:auto;font-size:13px}"
        ".footer{margin-top:28px;color:#64748b;font-size:12px;border-top:1px solid #1f2937;padding-top:14px}"
        ".footer a{color:#a78bfa;text-decoration:none}"
    )
    return (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>HERETIC report</title><style>{style}</style></head><body><div class='wrap'>"
        f"<h1>HERETIC — business-logic findings</h1>"
        f"<p class='sub'>{tgt}{n} confirmed{' · ' + sev_summary if sev_summary else ''} · authorized testing only</p>"
        f"<div class='chips'>{chips}</div>"
        f"{''.join(cards)}"
        f"<div class='footer'>Every finding is Oracle-proven (deterministic verification) — no "
        f"speculative results. Generated by <a href='https://github.com/SYCO7/heretic'>HERETIC "
        f"v{esc(_version())}</a>.</div>"
        f"</div></body></html>"
    )
