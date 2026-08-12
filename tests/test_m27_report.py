"""M27: the HTML report is a self-describing deliverable — it carries the target,
a per-class summary, a severity breakdown, and an Oracle-proven footer.
"""
from __future__ import annotations

from heretic.core.models import Finding, Severity
from heretic.report.render import _as_html

_FINDINGS = [
    Finding(title="BOLA — userB reads userA's book", invariant_id="BOLA:book", bug_class="bola",
            severity=Severity.HIGH, expected="owner only", observed="200 identical",
            proof={"oracle": "cross_session_diff", "poc": [{"method": "GET", "url": "/books/v1/x"}]},
            remediation="scope to owner"),
    Finding(title="mass_assignment — role accepted", invariant_id="MASS:registration",
            bug_class="mass_assignment", severity=Severity.CRITICAL, expected="ignore role",
            observed="role=admin reflected", proof={"oracle": "reflected_privileged_field"},
            remediation="whitelist fields"),
]


def test_html_report_is_self_describing():
    h = _as_html(_FINDINGS, target="http://localhost:5001")
    assert "http://localhost:5001" in h                 # target on the report
    assert "bola (1)" in h and "mass assignment (1)" in h  # per-class summary chips
    assert "1 critical" in h and "1 high" in h           # severity breakdown
    assert "Oracle-proven" in h and "github.com/SYCO7/heretic" in h   # provenance footer


def test_html_report_escapes_untrusted_content():
    evil = [Finding(title="<script>alert(1)</script>", invariant_id="X", bug_class="bola",
                    severity=Severity.LOW, expected="", observed="<img src=x onerror=1>",
                    proof={}, remediation="")]
    h = _as_html(evil, target="http://t")
    assert "<script>alert(1)</script>" not in h          # escaped, not injected
    assert "&lt;script&gt;" in h
