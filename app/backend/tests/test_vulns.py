"""Vulnerability management: import, triage, remediation, exceptions (SEC-035)."""
from __future__ import annotations

import io

from app import db

CSV = """asset,cve,title,cvss,severity,status
lab-web-01,CVE-2026-10001,CSV imported vuln,7.2,high,new
lab-db-01,,No CVE finding,4.5,,new
"""


def test_create_and_dedupe(client, seeded):
    r = client.post("/api/vulns", json={"asset_id": 1, "cve_id": "CVE-2026-10002",
                                        "title": "API created vuln", "cvss": 8.0})
    assert r.status_code == 201
    assert r.json()["created"] is True
    r = client.post("/api/vulns", json={"asset_id": 1, "cve_id": "CVE-2026-10002",
                                        "title": "API created vuln", "cvss": 8.0})
    assert r.json()["created"] is False
    # severity auto-derived from CVSS
    r = client.post("/api/vulns", json={"title": "Auto sev", "cve_id": "CVE-2026-10003", "cvss": 9.7})
    assert r.status_code == 201
    item = client.get("/api/vulns", params={"q": "Auto sev"}).json()["items"][0]
    assert item["severity"] == "critical"
    # bad asset
    r = client.post("/api/vulns", json={"title": "Bad asset vuln", "asset_id": 9999})
    assert r.status_code == 400


def test_csv_import(client, seeded):
    files = {"file": ("vulns.csv", io.BytesIO(CSV.encode()), "text/csv")}
    r = client.post("/api/vulns/import/csv", files=files)
    assert r.status_code == 201
    body = r.json()
    assert body["created"] == 2
    assert body["errors"] == 0
    item = client.get("/api/vulns", params={"q": "CSV imported"}).json()["items"][0]
    assert item["severity"] == "high"
    # re-import dedupes
    files = {"file": ("vulns.csv", io.BytesIO(CSV.encode()), "text/csv")}
    r = client.post("/api/vulns/import/csv", files=files)
    assert r.json()["created"] == 0 and r.json()["updated"] == 2


def test_json_import(client, seeded):
    body = [{"title": "JSON vuln A", "cvss": 6.0}, {"title": "JSON vuln B", "cvss": 2.0}]
    r = client.post("/api/vulns/import/json", json=body)
    assert r.status_code == 201
    assert r.json()["created"] == 2


def test_triage_flow_exceptions_remediation(client, seeded):
    r = client.post("/api/vulns", json={"title": "Triage me", "cve_id": "CVE-2026-10004", "cvss": 7.5})
    assert r.status_code == 201
    vid = client.get("/api/vulns", params={"q": "Triage me"}).json()["items"][0]["id"]
    r = client.patch(f"/api/vulns/{vid}", json={"status": "triaged"})
    assert r.status_code == 200
    r = client.patch(f"/api/vulns/{vid}", json={"status": "weird"})
    assert r.status_code == 400
    # remediation task moves status to in_progress
    r = client.post(f"/api/vulns/{vid}/remediation", json={"title": "Patch it", "owner": "platform"})
    assert r.status_code == 201
    item = client.get("/api/vulns", params={"q": "Triage me"}).json()["items"][0]
    assert item["status"] == "in_progress"
    assert client.get(f"/api/vulns/{vid}/remediation").json()["total"] == 1
    # exception -> accepted_risk
    r = client.post(f"/api/vulns/{vid}/exceptions",
                    json={"reason": "Risk accepted: isolated segment, compensating control in place.",
                          "expires_at": "2026-12-01"})
    assert r.status_code == 201
    item = client.get("/api/vulns", params={"q": "Triage me"}).json()["items"][0]
    assert item["status"] == "accepted_risk"
    assert client.get(f"/api/vulns/{vid}/exceptions").json()["total"] == 1
    # too-short reason rejected
    r = client.post(f"/api/vulns/{vid}/exceptions", json={"reason": "nope"})
    assert r.status_code == 422
    # fix flow
    r = client.patch(f"/api/vulns/{vid}", json={"status": "fixed"})
    assert r.status_code == 200
    item = client.get("/api/vulns", params={"q": "Triage me"}).json()["items"][0]
    assert item["fixed_at"]


def test_filters(client, seeded):
    r = client.get("/api/vulns", params={"status": "fixed"})
    assert all(v["status"] == "fixed" for v in r.json()["items"])
    r = client.get("/api/vulns", params={"severity": "critical"})
    assert all(v["severity"] == "critical" for v in r.json()["items"])


def test_risk_acceptance_must_be_recorded_as_an_exception(client, seeded, conn):
    """SEC-082: `accepted_risk` via the status PATCH skipped the exception
    record — no rationale, no approver, no expiry. One decision, one record."""
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.patch("/api/vulns/1", json={"status": "accepted_risk"})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "use_exception_endpoint"
    assert db.one(conn, "SELECT status FROM vuln_findings WHERE id=1")["status"] != "accepted_risk"

    r = client.post("/api/vulns/1/exceptions", json={"reason": "compensating control on the WAF"})
    assert r.status_code == 201
    assert db.one(conn, "SELECT status FROM vuln_findings WHERE id=1")["status"] == "accepted_risk"
    exc = db.one(conn, "SELECT * FROM finding_exceptions WHERE vuln_id=1 ORDER BY id DESC LIMIT 1")
    assert exc["approved_by"] == "admin" and "compensating control" in exc["reason"]


def test_finding_severity_is_validated(client, seeded, conn):
    """An imported severity of "banana" used to be stored and counted nowhere."""
    client.post("/api/auth/login", json={"username": "admin", "password": "CyberSecAdmin1!"})
    r = client.post("/api/vulns", json={"title": "Bad severity finding", "severity": "banana"})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "bad_severity"
    r = client.post("/api/vulns", json={"title": "Info finding", "cvss": 0.0})
    assert r.status_code == 201
    assert db.one(conn, "SELECT severity FROM vuln_findings WHERE id=?",
                  (r.json()["id"],))["severity"] == "info"              # derived, and valid

    csv = ("asset,cve,title,cvss,severity\n"
           "lab-web-01,CVE-2021-44228,Good row,9.8,\n"
           "lab-web-01,,Bad row,3.0,banana\n")
    r = client.post("/api/vulns/import/csv", files={"file": ("f.csv", io.BytesIO(csv.encode()), "text/csv")})
    body = r.json()
    assert body["created"] == 1 and body["errors"] == 1
    assert "bad_severity" in body["error_sample"][0]
    assert db.one(conn, "SELECT severity FROM vuln_findings WHERE title='Bad row'") is None


def test_reopening_a_finding_clears_fixed_at(client, seeded):
    """SEC-092: `fixed_at` was stamped on `fixed` and left set when the finding
    was reopened (and rewritten by a repeat `fixed`), so "when was this fixed?"
    had no reliable answer."""
    from app import db as dbmod

    fid = client.post("/api/vulns", json={"title": "Reopen me too", "severity": "high"}).json()["id"]
    r = client.patch(f"/api/vulns/{fid}", json={"status": "fixed"})
    assert r.status_code == 200
    fixed_at = r.json()["fixed_at"]
    assert fixed_at

    r = client.patch(f"/api/vulns/{fid}", json={"status": "fixed"})
    assert r.json()["fixed_at"] == fixed_at          # not rewritten

    r = client.patch(f"/api/vulns/{fid}", json={"status": "in_progress"})
    assert r.status_code == 200 and r.json()["fixed_at"] is None
    ev = dbmod.jload(dbmod.q(seeded, "SELECT detail FROM audit_events WHERE action = 'vuln.updated' "
                                     "ORDER BY seq DESC LIMIT 1")[0]["detail"])
    assert ev["from_status"] == "fixed" and ev["to_status"] == "in_progress"

    r = client.patch(f"/api/vulns/{fid}", json={"status": "fixed"})
    assert r.json()["fixed_at"] and r.json()["fixed_at"] >= fixed_at   # second-granularity
