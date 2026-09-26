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


def test_scan_run_counts_describe_the_run_not_the_last_import(client, seeded):
    """SEC-106: `findings_total` was set to the number of findings *created by that
    import call*, so re-importing the same SARIF (idempotent — it creates nothing)
    reset the run's total to 0 while the findings stayed attached, and
    `findings_new` was never written after creation. Live repro before the fix:
    run 2 → import → `findings_total: 2`; import again → `findings_total: 0` with 2
    findings still on the run."""
    run = client.post("/api/appsec/scan-runs", json={"repo": "acme/api", "kind": "sast"}).json()
    rid = run["id"]
    assert run["findings_total"] == 0

    first = client.post("/api/appsec/sarif", json={"scan_run_id": rid, "sarif": SARIF}).json()
    assert first["imported"] >= 2
    assert first["findings_total"] == first["imported"] == first["findings_new"]
    row = next(r for r in client.get("/api/appsec/scan-runs").json()["items"] if r["id"] == rid)
    assert row["findings_total"] == first["imported"] and row["findings_new"] == first["imported"]

    # Re-import: nothing new, but the run's total must still describe the run.
    again = client.post("/api/appsec/sarif", json={"scan_run_id": rid, "sarif": SARIF}).json()
    assert again["imported"] == 0 and again["findings_new"] == 0
    assert again["findings_total"] == first["imported"]
    row = next(r for r in client.get("/api/appsec/scan-runs").json()["items"] if r["id"] == rid)
    assert row["findings_total"] == first["imported"], "a re-import must not zero the run's total"

    # The count also matches what the findings list says.
    listed = client.get("/api/appsec/findings", params={"scan_run_id": rid}).json()["total"]
    assert listed == row["findings_total"]


def test_sarif_import_does_not_rewrite_a_reported_run_status(client, seeded):
    """SEC-106: an import used to set `status = 'completed'` unconditionally, so a run
    the CI reported as `failed` became `completed` the moment findings were uploaded —
    the platform rewriting the run's own lifecycle state."""
    run = client.post("/api/appsec/scan-runs", json={"repo": "acme/api", "kind": "sast",
                                                    "status": "failed"}).json()
    assert run["status"] == "failed"
    out = client.post("/api/appsec/sarif", json={"scan_run_id": run["id"], "sarif": SARIF}).json()
    assert out["status"] == "failed" and "failed" in out["note"]
    row = next(r for r in client.get("/api/appsec/scan-runs").json()["items"] if r["id"] == run["id"])
    assert row["status"] == "failed"
    assert row["findings_total"] > 0        # the results are still recorded

    # A run that was merely running does advance to completed.
    running = client.post("/api/appsec/scan-runs", json={"repo": "acme/api", "kind": "sast",
                                                        "status": "running"}).json()
    assert client.post("/api/appsec/sarif",
                       json={"scan_run_id": running["id"], "sarif": SARIF}).status_code == 201
    row = next(r for r in client.get("/api/appsec/scan-runs").json()["items"] if r["id"] == running["id"])
    assert row["status"] == "completed"
