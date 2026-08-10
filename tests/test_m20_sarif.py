"""M20: SARIF 2.1.0 output for CI / code-scanning integration."""
from __future__ import annotations

from heretic.benchmark import fixtures as F
from heretic.report.render import to_sarif


def test_sarif_shape_and_severity_mapping():
    findings = F.build_orchestrator().run()
    sarif = to_sarif(findings, target="http://bench.local")

    assert sarif["version"] == "2.1.0"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "HERETIC"
    assert driver["rules"]                                       # one rule per bug class

    results = sarif["runs"][0]["results"]
    assert len(results) == len(findings)
    r = results[0]
    assert r["ruleId"] and r["level"] in ("error", "warning", "note")
    assert "security-severity" in r["properties"]               # drives GitHub severity
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    # a critical finding maps to error / high score
    crit = [x for x in results if x["properties"]["security-severity"] == "9.5"]
    assert all(x["level"] == "error" for x in crit)


def test_sarif_uri_uses_target_and_endpoint():
    findings = [f for f in F.build_orchestrator().run() if f.bug_class == "bola"]
    sarif = to_sarif(findings, target="http://bench.local")
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"]]
    assert any(u.startswith("http://bench.local/") for u in uris)   # target + endpoint path
