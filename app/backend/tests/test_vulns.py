"""Vulnerability management: import, triage, remediation, exceptions (SEC-035)."""
from __future__ import annotations

import io

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
