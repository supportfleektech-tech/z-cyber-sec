"""AppSec: scan runs, SARIF import, suppression (SEC-036)."""
from __future__ import annotations

SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "SemgrepOSS",
                    "rules": [
                        {"id": "semgrep.audit.python.eval",
                         "shortDescription": {"text": "eval() found"}},
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "semgrep.audit.python.eval",
                    "level": "error",
                    "message": {"text": "eval usage"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/util.py"},
                                "region": {"startLine": 12},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "semgrep.security.json-load",
                    "level": "warning",
                    "message": {"text": "json.load of untrusted data"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app/parse.py"},
                                "region": {"startLine": 77},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}


def test_scan_run_and_sarif_import(client, seeded):
    r = client.post("/api/appsec/scan-runs", json={"repo": "test-repo", "kind": "sast",
                                                   "ci_url": "ci://run-1"})
    assert r.status_code == 201
    run_id = r.json()["id"]
    r = client.post("/api/appsec/sarif", json={"scan_run_id": run_id, "sarif": SARIF})
    assert r.status_code == 201
    assert r.json()["imported"] == 2
    r = client.get("/api/appsec/findings", params={"scan_run_id": run_id})
    items = r.json()["items"]
    assert len(items) == 2
    assert items[0]["severity"] in {"high", "medium"}
    # dedupe on re-import
    r = client.post("/api/appsec/sarif", json={"scan_run_id": run_id, "sarif": SARIF})
    assert r.json()["imported"] == 0
    # suppression with rationale
    fid = items[0]["id"]
    r = client.post(f"/api/appsec/findings/{fid}/suppress",
                    json={"reason": "False positive: input is internally generated, reviewed 2026-09."})
    assert r.status_code == 200
    item = client.get("/api/appsec/findings", params={"scan_run_id": run_id}).json()["items"]
    sup = [i for i in item if i["id"] == fid][0]
    assert sup["status"] == "suppressed"
    assert sup["suppression_reason"]
    # bad sarif
    r = client.post("/api/appsec/sarif", json={"scan_run_id": run_id, "sarif": {"version": "1.0"}})
    assert r.status_code == 400
    # missing run
    r = client.post("/api/appsec/sarif", json={"scan_run_id": 9999, "sarif": SARIF})
    assert r.status_code == 404


def test_scan_runs_listing(client, seeded):
    r = client.get("/api/appsec/scan-runs")
    assert r.status_code == 200
    assert r.json()["total"] >= 1
    r = client.get("/api/appsec/scan-runs", params={"repo": "nope"})
    assert r.json()["total"] == 0
