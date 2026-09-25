"""Deterministic synthetic seed data (SEC-025).

Everything here is fiction, generated from a fixed RNG seed, and every record
carries data_class='synthetic'. Attacks are benign patterns against our own
synthetic hosts — never external systems.

Usage:  .venv/bin/python -m app.seed.seed_demo
"""
from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta

import yaml

from .. import db, security
from ..audit import record_audit
from ..config import settings
from ..services.detection import rule_health

SYSTEM = {"type": "system", "id": "seed", "name": "seed-demo"}


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _seeded_events(conn, now: datetime) -> int:
    rng = random.Random(42)
    hosts = ["lab-web-01", "lab-db-01", "lab-jump-01", "ws-analyst-01"]
    users = ["svc_ci", "svc_backup", "operator", "auditor"]
    benign_actions = [
        ("login_success", "success", "info", "user login"),
        ("process_create", "success", "info", "routine process start"),
        ("file_read", "success", "info", "scheduled file read"),
        ("network_in", "success", "info", "inbound request"),
        ("audit_log_write", "success", "info", "audit write"),
    ]
    n = 0
    for day in range(7, 0, -1):
        base = now - timedelta(days=day)
        for _ in range(45):
            h = base + timedelta(minutes=rng.randint(0, 1440))
            host = rng.choice(hosts)
            user = rng.choice(users)
            action, outcome, sev, msg = rng.choice(benign_actions)
            conn.execute(
                "INSERT INTO events (idempotency_key, ts, source_type, source_name, host, user, action, "
                "outcome, severity, msg, data, data_class, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"seed-b{n}", _ts(h), "syslog", "synthetic-agent", host, user, action, outcome, sev,
                 msg, db.jdump({"pid": rng.randint(100, 99999), "uid": rng.randint(0, 400)}),
                 "synthetic", db.utcnow()))
            n += 1
    # ---------------- attack bursts (benign synthetic patterns, MITRE-mapped)
    def ev(key, h, host, user, action, outcome, sev, msg, data, source_name="synthetic-agent"):
        nonlocal n
        conn.execute(
            "INSERT INTO events (idempotency_key, ts, source_type, source_name, host, user, action, "
            "outcome, severity, msg, data, data_class, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (key, _ts(h), "syslog", source_name, host, user, action, outcome, sev, msg,
             db.jdump(data), "synthetic", db.utcnow()))
        n += 1

    d3 = now - timedelta(days=3, hours=2)
    for i in range(8):  # SSH brute force on jump host -> cs-0001
        ev(f"seed-a1-{i}", d3 + timedelta(seconds=20 * i), "lab-jump-01", "admin",
           "ssh_failed_login", "failure", "low", "Failed password from 203.0.113.5",
           {"src_ip": "203.0.113.5", "port": 22}, source_name="sshd")

    d4 = now - timedelta(days=4, hours=1)
    for i in range(12):  # login storm -> cs-0002
        ev(f"seed-a2-{i}", d4 + timedelta(seconds=25 * i), "lab-web-01", "svc_ci",
           "login_failed", "failure", "low", "Failed web login (credential stuffing pattern)",
           {"src_ip": "192.0.2.77", "path": "/login"})

    d2 = now - timedelta(days=2, hours=5)
    ev("seed-a3-0", d2, "ws-analyst-01", "operator", "process_create", "success", "high",
       "powershell -enc (obfuscated)", {"program": "powershell",
                                        "flags": ["-enc"], "cmdline": "powershell -enc QQlFWD..."})
    ev("seed-a3-1", d2 + timedelta(minutes=4), "ws-analyst-01", "operator", "process_create", "success",
       "high", "powershell DownloadString", {"program": "powershell",
                                             "flags": ["DownloadString"], "cmdline": "IEX (New-Object ...)"})

    ev("seed-a4-0", d2 + timedelta(hours=1), "lab-db-01", "svc_backup", "network_out", "success",
       "critical", "250 MB outbound to 203.0.113.66",
       {"bytes_out": 262144000, "dst_ip": "203.0.113.66", "port": 443})

    ev("seed-a5-0", d2 + timedelta(hours=3), "lab-db-01", "operator", "auth_success", "success",
       "high", "SMB session from ws-analyst-01", {"method": "smb", "src_host": "ws-analyst-01"})
    ev("seed-a5-1", d2 + timedelta(hours=3, minutes=9), "lab-db-01", "operator", "rdp_login",
       "success", "high", "RDP login from 10.0.0.40", {"method": "rdp", "src_ip": "10.0.0.40"})

    ev("seed-a6-0", d2 + timedelta(hours=5), "lab-jump-01", "operator", "sudo", "failure", "high",
       "sudo: operator : incorrect password", {"cmd": "sudo su -"})
    ev("seed-a6-1", d2 + timedelta(hours=5, minutes=2), "lab-jump-01", "operator", "priv_escalation",
       "failure", "high", "setuid anomaly (synthetic)", {"bin": "/usr/bin/su"})
    return n


def _seed_rules(conn) -> int:
    n = 0
    for f in sorted(settings.rules_dir.glob("*.yaml")):
        spec = yaml.safe_load(f.read_text())
        # SEC-074: a shipped rule that cannot compile would be stocked as
        # "active" and then quietly ignored by detection forever. Refuse it at
        # seed time and name the file — this is a repository bug, not operator
        # input. `scripts/lint_rules.py` catches it earlier, in CI.
        health = rule_health(spec or {})
        if not health["compiles"]:
            raise RuntimeError(
                f"shipped rule {f.name} does not compile and would be INERT: {health['error']}"
            )
        if db.one(conn, "SELECT id FROM detection_rules WHERE uid = ?", (spec.get("uid"),)):
            continue
        conn.execute(
            "INSERT INTO detection_rules (uid, name, description, severity, status, spec, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (spec["uid"], spec.get("name"), spec.get("description"), spec.get("severity"),
             spec.get("status", "active"), db.jdump(spec), db.utcnow(), db.utcnow()))
        n += 1
    conn.commit()
    return n


def seed_all(conn) -> dict:
    """Idempotent seed. Returns record counts created."""
    if db.one(conn, "SELECT id FROM users LIMIT 1"):
        return {"skipped": True, "reason": "users already exist (database not fresh)"}
    now = datetime.now(UTC)
    counts = {}

    # ------------------------------------------------------------- users
    users = [
        ("admin", "Platform Admin", "CyberSecAdmin1!", "admin"),
        ("iris", "Iris Okonkwo (IR Lead)", "IrisLeadPass1!", "ir_lead"),
        ("sasha", "Sasha Petrov (SOC)", "SashaSocPass1!", "soc_analyst"),
        ("viewer", "Read Only Viewer", "ViewerRead1!", "viewer"),
        ("agent-svc", "Agent Service Account", "AgentSvcPass1!", "agent_service"),
    ]
    for uname, dname, pw, role in users:
        conn.execute("INSERT INTO users (username, display_name, password_hash, role, active, created_at, updated_at) "
                     "VALUES (?, ?, ?, ?, 1, ?, ?)",
                     (uname, dname, security.hash_password(pw), role, db.utcnow(), db.utcnow()))
    counts["users"] = len(users)
    record_audit(conn, SYSTEM, "seed.users", detail={"count": len(users)})

    # ----------------------------------------------------------- assets
    assets = [
        ("lab-web-01", "server", "LAB", "platform", "web-tier", "active",
         {"ip": "10.0.0.11", "os": "debian-12"}),
        ("lab-db-01", "server", "LAB", "platform", "data-tier", "active",
         {"ip": "10.0.0.12", "os": "debian-12"}),
        ("lab-jump-01", "server", "LAB", "platform", "edge", "active",
         {"ip": "10.0.0.10", "os": "debian-12"}),
        ("ws-analyst-01", "workstation", "LAB", "analysts", "workstations", "active",
         {"os": "pop-os-24.04"}),
        ("lab-ctf-target-01", "server", "EXERCISE", "redteam", "ctf", "active",
         {"ip": "172.16.99.10", "note": "disposable isolated target"}),
        ("csp-syn-account", "cloud", "LAB", "cloud", "accounts", "active",
         {"provider": "synthetic-cloud"}),
    ]
    for name, atype, env, owner, group, status, meta in assets:
        conn.execute("INSERT INTO assets (name, type, environment, owner, group_name, status, meta, "
                     "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (name, atype, env, owner, group, status, db.jdump(meta), db.utcnow(), db.utcnow()))
    counts["assets"] = len(assets)

    # ----------------------------------------------------- integrations
    integrations = [
        ("syslog-internal", "exporter", "ok", "forwarded by synthetic agents"),
        ("osint-feed-synthetic", "feed", "ok", "daily synthetic IOCs (demo)"),
        ("ci-pipeline", "ci", "ok", "GitHub Actions (free tier)"),
        ("vuln-db-scan", "scanner", "degraded", "offline NVD mirror, stale 48h"),
    ]
    for name, kind, status, prov in integrations:
        conn.execute("INSERT INTO integrations (name, kind, status, last_run_at, last_status, config, "
                     "provenance, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (name, kind, status, db.utcnow(), "last-check-ok", db.jdump({"schedule": "15m"}),
                      prov, db.utcnow(), db.utcnow()))
    counts["integrations"] = len(integrations)

    # ------------------------------------------------- detection rules
    counts["rules"] = _seed_rules(conn)

    # ----------------------------------------------------------- events
    counts["events"] = _seeded_events(conn, now)
    conn.commit()

    # ------------------------------------------ intel (sources + indicators)
    conn.execute("INSERT INTO intel_sources (name, kind, reliability, description, created_at) "
                 "VALUES ('OSINT Synthetic Feed', 'ioc_feed', 'c', 'Demo IOC feed; all values fictitious.', ?)",
                 (db.utcnow(),))
    src_id = db.one(conn, "SELECT id FROM intel_sources WHERE name='OSINT Synthetic Feed'")["id"]
    ind_src_id = src_id
    conn.execute("INSERT INTO intel_sources (name, kind, reliability, description, created_at) "
                 "VALUES ('Internal IR', 'internal', 'a', 'Analyst-curated findings.', ?)", (db.utcnow(),))
    internal_src = db.one(conn, "SELECT id FROM intel_sources WHERE name='Internal IR'")["id"]
    indicators = [
        ("ip", "203.0.113.5", 85, ind_src_id, ["credential-access"], ["T1110"], "SSH brute force source (synthetic)"),
        ("ip", "203.0.113.66", 70, ind_src_id, ["exfiltration"], ["T1041"], "Exfil destination (synthetic)"),
        ("domain", "evil-c2.example", 60, ind_src_id, ["command-and-control"], ["T1071"], "C2 domain (synthetic)"),
        ("url", "http://evil-c2.example/beacon", 55, ind_src_id, ["command-and-control"], ["T1071.001"], "C2 beacon URL (synthetic)"),
        ("sha256", "3f6c8e2a91b0d4f7a5c2e8b1d6f3a9c0e7b5d2f4a8c1e9b0d3f6a2c5e8b1d4f7", 80,
         internal_src, ["impact"], ["T1486"], "Ransomware sample hash (synthetic)"),
        ("email", "phish-sender@synthetic-evil.example", 65, ind_src_id, ["initial-access"], ["T1566"],
         "Phishing sender (synthetic)"),
    ]
    for typ, value, conf, sid, tactics, techs, notes in indicators:
        conn.execute(
            "INSERT INTO threat_indicators (type, value, confidence, source_id, status, first_seen, last_seen, "
            "mitre_tactics, mitre_techniques, notes, created_at, updated_at) VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)",
            (typ, value, conf, sid, db.utcnow(), db.utcnow(), db.jdump(tactics), db.jdump(techs),
             notes, db.utcnow(), db.utcnow()))
    counts["indicators"] = len(indicators)

    # -------------------------------------------------------- vulns
    asset_ids = {a["name"]: a["id"] for a in db.q(conn, "SELECT id, name FROM assets")}
    vulns = [
        ("lab-web-01", "CVE-2024-21762", "curl memory corruption via crafted SOCKS5 URL", 8.1, "high", "in_progress",
         "Affects curl; upgrade to 8.9.0+."),
        ("lab-db-01", "CVE-2023-4911", "libwebp heap overflow in ImageDecoder", 9.6, "critical", "triaged",
         "Parser triggered by malformed WebP; patch libwebp."),
        ("lab-jump-01", "CVE-2024-6387", "glibc iconv heap overflow (Looney Tunables)", 8.1, "high", "new",
         "Local privilege escalation path."),
        ("ws-analyst-01", "CVE-2024-23897", "nginx HTTP/2 rapid reset DoS", 7.5, "high", "new",
         "Mitigate with kernel tuning until patch."),
        ("lab-web-01", "CVE-2021-44228", "Apache Log4j2 JNDI injection (Log4Shell)", 10.0, "critical", "fixed",
         "Patched 2026-08; retained for audit trail."),
        ("csp-syn-account", None, "Outdated base image (debian:bookworm-20250101)", 5.4, "medium", "new",
         "Rebuild with current base image."),
        ("lab-db-01", "CVE-2024-45801", "OpenSSH regreSSHion (client-side RCE)", 8.1, "high", "triaged",
         "Disable SSH client connections from DB tier."),
        ("lab-ctf-target-01", None, "Intentional CVE-2023-0286 (unpatched, isolated CTF box)", 8.4, "high",
         "accepted_risk", "Authorized exercise target; isolated network."),
    ]
    for name, cve, title, cvss, sev, status, desc in vulns:
        conn.execute(
            "INSERT INTO vuln_findings (asset_id, cve_id, title, cvss, severity, status, description, source, "
            "discovered_at, due_date, fixed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (asset_ids.get(name), cve, title, cvss, sev, status, desc, "synthetic-scan",
             db.utcnow(), (now + timedelta(days=14)).strftime("%Y-%m-%d"),
             db.utcnow() if status == "fixed" else None))
    counts["vulns"] = len(vulns)
    v1 = db.one(conn, "SELECT id FROM vuln_findings WHERE cve_id='CVE-2023-4911'")
    conn.execute("INSERT INTO remediation_tasks (vuln_id, title, status, owner, due, created_at, updated_at) "
                 "VALUES (?, ?, 'open', 'platform', ?, ?, ?)",
                 (v1["id"], "Patch libwebp on lab-db-01 and verify",
                  (now + timedelta(days=7)).strftime("%Y-%m-%d"), db.utcnow(), db.utcnow()))
    v8 = db.one(conn, "SELECT id FROM vuln_findings WHERE title LIKE 'Intentional CVE-2023-0286%'")
    conn.execute("INSERT INTO finding_exceptions (vuln_id, reason, approved_by, expires_at, created_at) "
                 "VALUES (?, ?, ?, ?, ?)",
                 (v8["id"], "Authorized CTF target on isolated network; risk accepted by IR lead.",
                  "iris", (now + timedelta(days=30)).strftime("%Y-%m-%d"), db.utcnow()))

    # -------------------------------------------------------- appsec
    conn.execute("INSERT INTO scan_runs (repo, kind, status, started_at, finished_at, findings_total, "
                 "findings_new, ci_url, meta) VALUES (?, ?, 'completed', ?, ?, 0, 0, ?, ?)",
                 ("z-cyber-sec", "sast", db.utcnow(), db.utcnow(), "ci://free-tier", db.jdump({"tool": "semgrep-ci"})))
    run1 = db.one(conn, "SELECT id FROM scan_runs ORDER BY id DESC")["id"]
    sarif_f = [
        ("semgrep.security.audit.python.subprocess-without-shell-false", "medium", "app/main.py", 30,
         "subprocess call reviewed; no shell=True"),
        ("pylint.security.use-of-exec", "low", "app/db.py", 41, "executescript used on trusted migrations only"),
        ("bandit.B108", "low", "app/seed/seed_demo.py", 120, "hardcoded demo password (synthetic seed, labeled)"),
    ]
    for rid, sev, fp, line, msg in sarif_f:
        conn.execute("INSERT INTO appsec_findings (scan_run_id, rule_id, severity, file, line, message, status, "
                     "created_at) VALUES (?, ?, ?, ?, ?, ?, 'open', ?)",
                     (run1, rid, sev, fp, line, msg, db.utcnow()))
    conn.execute("UPDATE scan_runs SET findings_total = ? WHERE id = ?", (len(sarif_f), run1))
    counts["scan_runs"] = 1
    counts["appsec_findings"] = len(sarif_f)

    # ---------------------------------------------------------- cloud
    conn.execute("INSERT INTO cloud_assets (provider, account, region, type, name, status, meta, created_at) "
                 "VALUES ('synthetic-cloud', 'syn-account', 'eu-central-syn', 'bucket', 'syn-bucket-public', "
                 "'active', ?, ?)", (db.jdump({"acl": "public-read"}), db.utcnow()))
    ca1 = db.one(conn, "SELECT id FROM cloud_assets WHERE name='syn-bucket-public'")["id"]
    conn.execute("INSERT INTO cloud_assets (provider, account, region, type, name, status, meta, created_at) "
                 "VALUES ('synthetic-cloud', 'syn-account', 'eu-central-syn', 'instance', 'syn-web-01', "
                 "'active', ?, ?)", (db.jdump({"image": "debian-12"}), db.utcnow()))
    ca2 = db.one(conn, "SELECT id FROM cloud_assets WHERE name='syn-web-01'")["id"]
    conn.execute("INSERT INTO cloud_assets (provider, account, region, type, name, status, meta, created_at) "
                 "VALUES ('synthetic-cloud', 'syn-account', 'eu-central-syn', 'identity', 'syn-iam-admin', "
                 "'active', ?, ?)", (db.jdump({"mfa": False}), db.utcnow()))
    ca3 = db.one(conn, "SELECT id FROM cloud_assets WHERE name='syn-iam-admin'")["id"]
    posture = [
        (ca1, "csp-001", "Bucket is publicly readable", "high", "open", "ACL public-read on data bucket."),
        (ca2, "csp-002", "Security group opens 0.0.0.0/0 on 22/tcp", "high", "open", "SSH exposed to all."),
        (ca3, "csp-003", "Admin identity without MFA", "critical", "open", "Root-equivalent identity lacks MFA."),
        (ca2, "csp-004", "TLS certificate expires in 6 days", "medium", "open", "cert expiry 2026-09-27."),
    ]
    for aid, rid, title, sev, status, detail in posture:
        conn.execute("INSERT INTO posture_findings (asset_id, rule_id, title, severity, status, detail, "
                     "checked_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (aid, rid, title, sev, status, detail, db.utcnow()))
    counts["cloud_assets"] = 3
    counts["posture"] = len(posture)

    # ------------------------------------------------------------- GRC
    controls = [
        ("NIST CSF 2.0", "GV-OC-01", "Organization-wide cybersecurity policy is established",
         "Govern", "admin", "met", (now + timedelta(days=180)).strftime("%Y-%m-%d")),
        ("NIST CSF 2.0", "PR.AC-01", "Access to systems and assets is managed", "Protect",
         "platform", "met", (now + timedelta(days=90)).strftime("%Y-%m-%d")),
        ("NIST CSF 2.0", "DE.CM-01", "The network is monitored to detect potential cybersecurity events",
         "Detect", "soc", "in_progress", (now + timedelta(days=90)).strftime("%Y-%m-%d")),
        ("NIST CSF 2.0", "RS.RP-01", "Response planning is managed", "Respond", "ir", "met",
         (now + timedelta(days=180)).strftime("%Y-%m-%d")),
        ("NIST CSF 2.0", "RC.RP-01", "Recovery planning is managed", "Recover", "platform", "gap",
         (now + timedelta(days=30)).strftime("%Y-%m-%d")),
        ("CIS Top 20 v8", "CIS-05", "Implement and Manage Account Lifecycle", "Identity",
         "admin", "in_progress", (now + timedelta(days=60)).strftime("%Y-%m-%d")),
    ]
    for fw, code, title, cat, owner, status, review in controls:
        conn.execute("INSERT INTO controls (framework, code, title, category, owner, status, next_review, "
                     "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (fw, code, title, cat, owner, status, review, db.utcnow(), db.utcnow()))
    counts["controls"] = len(controls)
    # SEC-102: this row used to be a phantom — `path` NULL and a placeholder digest
    # ("synthetic" * 10), so the demo claimed audit evidence for a control with no
    # artifact behind it. Write a real review note and record its real digest.
    c1 = db.one(conn, "SELECT id FROM controls WHERE code='GV-OC-01'")
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    review = settings.evidence_dir / "demo-policy-review-2026Q3.md"
    review.write_text(
        "# Policy review — 2026 Q3\n\n"
        "Scope: information-security policy set (GV-OC-01).\n\n"
        "- Reviewed by: platform\n"
        "- Outcome: policies current; no material changes required this quarter.\n"
        "- Next review: 2026 Q4.\n\n"
        "Synthetic demo artifact (seeded, not a real review).\n"
    )
    import hashlib
    policy_sha = hashlib.sha256(review.read_bytes()).hexdigest()
    conn.execute("INSERT INTO audit_evidence (control_id, name, path, sha256, created_at) VALUES (?, ?, ?, ?, ?)",
                 (c1["id"], review.name, str(review), policy_sha, db.utcnow()))

    risks = [
        ("Laptop lab host overloaded", 3, 4, "mitigating", "platform",
         ["Small service profile", "Offload heavy indexing", "Watch /metrics"]),
        ("Port/volume collision with other stacks", 2, 4, "open", "platform",
         ["Inventory before deploy", "Unique project names"]),
        ("Lab target reaches trusted network", 2, 5, "mitigating", "network",
         ["Isolated exercise network", "Default deny", "Route validation"]),
        ("Agent prompt injection", 3, 4, "mitigating", "security",
         ["Tool allowlist", "Approval gates", "Evals in CI"]),
    ]
    for title, lik, imp, status, owner, mits in risks:
        conn.execute("INSERT INTO risks (title, likelihood, impact, score, status, owner, mitigations, "
                     "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (title, lik, imp, lik * imp, status, owner, db.jdump(mits), db.utcnow(), db.utcnow()))
    counts["risks"] = len(risks)

    # -------------------------------------------------------- exercises
    conn.execute(
        "INSERT INTO exercises (name, scope, status, owner, starts_at, ends_at, targets, meta, created_at, updated_at) "
        "VALUES (?, ?, 'authorized', 'iris', ?, ?, ?, ?, ?, ?)",
        ("Synthetic Phish Drill Q3",
         "Authorized internal simulation ONLY: synthetic phishing email to volunteer test accounts on the lab "
         "identity provider. No external sending. Scope limited to accounts: test1@test.local, test2@test.local. "
         "Written authorization on file (synthetic).",
         # SEC-077: the window must be IN FORCE — an expired authorization
         # authorizes nothing (the scope guard enforces the end date), and a
         # seeded example that had lapsed would teach the wrong pattern.
         (now - timedelta(days=10)).strftime("%Y-%m-%d"), (now + timedelta(days=30)).strftime("%Y-%m-%d"),
         db.jdump(["test1@test.local", "test2@test.local"]), db.jdump({"kind": "phish-sim"}),
         db.utcnow(), db.utcnow()))
    ex1 = db.one(conn, "SELECT id FROM exercises WHERE name='Synthetic Phish Drill Q3'")
    conn.execute("INSERT INTO exercise_runs (exercise_id, started_at, finished_at, result, detail) "
                 "VALUES (?, ?, ?, 'completed', ?)",
                 (ex1["id"], (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  (now - timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  db.jdump({"clicks": 1, "reports": 1})))
    conn.execute(
        "INSERT INTO exercises (name, scope, status, owner, starts_at, ends_at, targets, meta, created_at, updated_at) "
        "VALUES (?, ?, 'planned', 'redteam', ?, ?, ?, ?, ?, ?)",
        ("Local CTF: Broken Web App",
         "Authorized practice exercise against lab-ctf-target-01 (isolated /172.16.99.0/24). Write-up and scope "
         "approved by owner. No external scanning. Isolation verified before each run.",
         (now + timedelta(days=7)).strftime("%Y-%m-%d"), (now + timedelta(days=8)).strftime("%Y-%m-%d"),
         db.jdump(["lab-ctf-target-01"]), db.jdump({"kind": "ctf"}), db.utcnow(), db.utcnow()))
    counts["exercises"] = 2

    # ----------------------------------------------------------- agents
    agents = [
        ("opencode-repo", "opencode", "repo implementation agent",
         {"modules": ["soc", "cases", "vulns", "assets"]},
         ["query_events", "get_alerts", "get_case", "summarize_alerts", "list_assets",
          "list_vulns", "request_report"]),
        ("openclaw-ops", "openclaw", "operations coordinator",
         {"modules": ["soc", "cases", "automation"]},
         ["query_events", "get_alerts", "get_case", "summarize_alerts", "list_assets",
          "create_case", "contain_asset"]),
        ("hermes-specialist", "hermes", "specialist triage (read-only)",
         {"modules": ["soc", "intel"]},
         ["query_events", "fetch_indicator", "summarize_alerts", "list_vulns"]),
        ("internal-automation", "internal", "playbook executor (consequential steps require approval)",
         {"modules": ["automation"]},
         ["query_events", "get_alerts", "summarize_alerts", "list_assets", "list_vulns",
          "fetch_indicator", "create_case"]),
        ("the-xploiter", "local-llm", "offensive security reasoning, validation and reporting",
         {"kind": "adversary-tradecraft"},
         ["list_scope_targets", "get_finding", "record_exploitability_review", "propose_attack_chain"]),
    ]
    for name, provider, role, scope, tools in agents:
        conn.execute("INSERT INTO agents (name, provider, role, scope, tools, status, created_at, updated_at) "
                     "VALUES (?, ?, ?, ?, ?, 'active', ?, ?)",
                     (name, provider, role, db.jdump(scope), db.jdump(tools), db.utcnow(), db.utcnow()))
    # SEC-076: The-Xploiter (SEC-075) is discoverable on a fresh install. Its
    # adapter points at a local OpenAI-compatible model (Ollama is the
    # zero-budget option); without one running, prompts fail loudly while the
    # explicit tool path still works. The persona shapes the system prompt only.
    conn.execute(
        "UPDATE agents SET adapter = 'openai_compat', adapter_config = ? WHERE name = 'the-xploiter'",
        (db.jdump({"base_url": "http://127.0.0.1:11434/v1", "model": "llama3",
                   "persona": "the-xploiter"}),))
    counts["agents"] = len(agents)

    # historical agent task (completed read-only)
    oc = db.one(conn, "SELECT id FROM agents WHERE name='opencode-repo'")
    now_s = db.utcnow()
    conn.execute("INSERT INTO agent_tasks (agent_id, title, status, request, result, created_at, started_at, finished_at) "
                 "VALUES (?, ?, 'completed', ?, ?, ?, ?, ?)",
                 (oc["id"], "Daily alert summary (seed)",
                  db.jdump({"steps": [{"tool": "summarize_alerts", "args": {}}], "original": {"tool": "summarize_alerts"}}),
                  db.jdump({"results": [{"tool": "summarize_alerts", "result": {"note": "seeded summary"}}],
                            "errors": [], "truthful": True}),
                 now_s, now_s, now_s))
    t1 = db.one(conn, "SELECT id FROM agent_tasks ORDER BY id DESC")["id"]
    conn.execute("INSERT INTO tool_calls (task_id, tool, args, allowed, reason, result, ts) "
                 "VALUES (?, 'summarize_alerts', ?, 1, NULL, ?, ?)",
                 (t1, db.jdump({}), db.jdump({"note": "seeded summary"}), now_s))
    counts["agent_tasks"] = 1

    # -------------------------------------------------------- playbooks
    playbooks = [
        ("alert-triage-summary", "Summarize high-severity alerts for triage", "on_alert:high",
         [{"tool": "summarize_alerts", "args": {}}, {"tool": "get_alerts", "args": {"status": "new"}}], False),
        ("exfil-response-check", "Read-only checks for critical exfil alerts (consequential steps need approval)",
         "on_alert:critical",
         [{"tool": "query_events", "args": {"action": "network_out"}},
          {"tool": "fetch_indicator", "args": {"value": "203.0.113.66"}},
          {"tool": "create_case", "args": {"title": "Exfiltration response", "severity": "critical"}}], True),
        ("daily-standup-brief", "Manual morning brief", "manual",
         [{"tool": "summarize_alerts", "args": {}}, {"tool": "list_vulns", "args": {}}], False),
    ]
    for name, desc, trigger, steps, auto in playbooks:
        conn.execute("INSERT INTO playbooks (name, description, trigger, steps, status, auto_run, created_at, updated_at) "
                     "VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
                     (name, desc, trigger, db.jdump(steps), int(auto), db.utcnow(), db.utcnow()))
    counts["playbooks"] = len(playbooks)

    # NOTE: the demo case is created by demo_case_and_evidence() AFTER the
    # detection backfill, because it links the first detected alert.
    counts["cases"] = 0

    # ------------------------------------------------- flags & settings
    conn.execute("INSERT INTO feature_flags (key, value, description, updated_at) VALUES (?, 1, "
                 "'Synthetic demo dataset loaded', ?)", ("synthetic_demo", db.utcnow()))
    conn.execute("INSERT INTO feature_flags (key, value, description, updated_at) VALUES (?, 0, "
                 "'Experimental UI layout', ?)", ("ui_experiments", db.utcnow()))
    conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('platform_version', '1.0.0', ?)",
                 (db.utcnow(),))
    conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('owner', 'security-platform-team', ?)",
                 (db.utcnow(),))

    conn.commit()
    record_audit(conn, SYSTEM, "seed.completed", detail=counts)
    counts["skipped"] = False
    return counts


def demo_case_and_evidence(conn) -> bool:
    """Create the demo case from the first detected alert (idempotent).

    Must run AFTER detection (backfill or live) so an alert exists to link.
    """
    import hashlib

    if db.one(conn, "SELECT id FROM cases LIMIT 1"):
        return False
    alerts = db.q(conn, "SELECT id, title, severity FROM alerts ORDER BY id")
    if not alerts:
        return False
    top = alerts[0]
    now = datetime.now(UTC)
    conn.execute(
        "INSERT INTO cases (number, title, description, status, priority, severity, assigned_to, "
        "source, created_at, updated_at) VALUES (?, ?, ?, 'investigating', 'high', ?, 'iris', 'alert', ?, ?)",
        (f"CASE-{now.year}-0001", top["title"], "Synthetic investigation seeded by demo data.",
         top["severity"], db.utcnow(), db.utcnow()))
    case1 = db.one(conn, "SELECT id FROM cases ORDER BY id DESC")["id"]
    conn.execute("UPDATE alerts SET case_id = ?, status='confirmed', updated_at=? WHERE id = ?",
                 (case1, db.utcnow(), top["id"]))
    conn.execute("INSERT INTO case_tasks (case_id, title, status, assigned_to, created_at, updated_at) "
                 "VALUES (?, 'Verify host isolation', 'open', 'iris', ?, ?)",
                 (case1, db.utcnow(), db.utcnow()))
    conn.execute("INSERT INTO case_timeline (case_id, ts, actor, entry_type, message) VALUES (?, ?, 'iris', "
                 "'note', 'Triage started (synthetic demo).')", (case1, db.utcnow()))
    ev_path = settings.evidence_dir / "seeded-incident-summary.txt"
    ev_path.write_text(
        "SYNTHETIC DEMO EVIDENCE\nCase: CASE-%d-0001\nSummary: seeded incident summary for the demo lab.\n"
        "Source: seed_demo.py (deterministic, seed=42)\n" % now.year)
    ev_path.chmod(0o600)
    sha = hashlib.sha256(ev_path.read_bytes()).hexdigest()
    conn.execute("INSERT INTO evidence (case_id, name, path, sha256, size, classification, retention, "
                 "uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, 'internal', '365d', 'seed', ?)",
                 (case1, "incident-summary.txt", str(ev_path), sha, ev_path.stat().st_size, db.utcnow()))
    conn.commit()
    record_audit(conn, SYSTEM, "seed.demo_case", target_type="case", target_id=str(case1))
    return True


if __name__ == "__main__":
    conn = db.raw_connection()
    out = seed_all(conn)
    if not out.get("skipped"):
        # Run detection over the seeded events and create the linked demo case,
        # so a fresh install has alerts + a case out of the box.
        from ..routers.soc import _run_detections
        events = db.q(conn, "SELECT id, ts, host, user, action, outcome, severity, "
                            "source_name, source_type, data FROM events ORDER BY ts")
        if events:
            raised = _run_detections(conn, events, threshold_context=events)
            out["alerts"] = len(raised)
        out["demo_case"] = demo_case_and_evidence(conn)
    conn.close()
    print(json.dumps(out, indent=2))
