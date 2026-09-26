import { useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, StBadge, useApi, useFlash } from "../components";

interface ScanRun {
  id: number;
  repo: string;
  kind: string;
  status: string;
  ci_url: string | null;
  created_at: string;
  // SEC-106: these describe the run (total attached, added by the last import).
  findings_total: number;
  findings_new: number;
}
interface Finding {
  id: number;
  scan_run_id: number;
  rule_id: string | null;
  title: string | null;
  file: string | null;
  line: number | null;
  severity: string;
  status: string;
  suppression_reason: string | null;
}
interface Paged<T> {
  items: T[];
  total: number;
}

export default function Appsec() {
  const [flash, flashShow] = useFlash();
  const runs = useApi<Paged<ScanRun>>(() => api.get<Paged<ScanRun>>("/api/appsec/scan-runs?page_size=50"), []);
  const findings = useApi<Paged<Finding>>(() => api.get<Paged<Finding>>("/api/appsec/findings?page_size=100"), []);

  return (
    <>
      <PageHead
        title="AppSec"
        sub="SAST/dependency scan runs, SARIF import, findings, and suppressions (rationale required)"
        actions={
          <>
            <SarifImport onDone={() => findings.reload()} />
            <NewRun onDone={() => runs.reload()} />
          </>
        }
      />
      {flash}

      <div className="panel">
        <h2>Scan runs</h2>
        <LoadBlock loading={runs.loading} error={runs.error} empty={!runs.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>ID</th><th>Repo</th><th>Kind</th><th>Status</th><th>Findings</th><th>CI</th><th>Created</th></tr>
            </thead>
            <tbody>
              {runs.data!.items.map((r) => (
                <tr key={r.id}>
                  <td className="mono dim">{r.id}</td>
                  <td>{r.repo}</td>
                  <td className="dim">{r.kind}</td>
                  <td><StBadge value={r.status} /></td>
                  <td className="dim" title="findings attached to this run / added by the last import">
                    {r.findings_total ?? 0}{r.findings_new ? ` (+${r.findings_new})` : ""}
                  </td>
                  <td className="dim mono">{r.ci_url || "—"}</td>
                  <td className="dim">{fmtTs(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      <div className="panel">
        <h2>Findings</h2>
        <LoadBlock loading={findings.loading} error={findings.error} empty={!findings.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Rule</th><th>Location</th><th>Severity</th><th>Status</th><th>Suppression rationale</th></tr>
            </thead>
            <tbody>
              {findings.data!.items.map((f) => (
                <tr key={f.id}>
                  <td className="mono">{f.rule_id || "—"}</td>
                  <td className="dim">
                    {f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "—"}
                  </td>
                  <td><StBadge value={f.severity} /></td>
                  <td>
                    {f.status === "suppressed" ? (
                      <StBadge value="suppressed" />
                    ) : (
                      <SuppressButton f={f} onDone={() => { findings.reload(); flashShow(`Finding ${f.rule_id} suppressed`); }} />
                    )}
                  </td>
                  <td className="dim" style={{ maxWidth: 320 }}>{f.suppression_reason || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>
    </>
  );
}

function NewRun({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [repo, setRepo] = useState("");
  const [kind, setKind] = useState("sast");
  const [ciUrl, setCiUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ New scan run</button>
      {open && (
        <Modal title="Register scan run" onClose={() => setOpen(false)}>
          <label className="f">Repository</label>
          <input value={repo} onChange={(e) => setRepo(e.target.value)} autoFocus placeholder="test-repo" />
          <div className="formrow mt">
            <div>
              <label className="f">Kind</label>
              <select value={kind} onChange={(e) => setKind(e.target.value)}>
                {["sast", "dependency", "secret_scan", "container"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="f">CI URL (optional)</label>
              <input value={ciUrl} onChange={(e) => setCiUrl(e.target.value)} placeholder="ci://run-1" style={{ width: 180 }} />
            </div>
          </div>
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !repo}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/appsec/scan-runs", { repo, kind, ci_url: ciUrl || undefined });
                  setOpen(false);
                  onDone();
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Creating…" : "Create"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function SarifImport({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [runId, setRunId] = useState("");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button onClick={() => { setErr(null); setOpen(true); }}>Import SARIF</button>
      {open && (
        <Modal title="Import SARIF 2.1 report" onClose={() => setOpen(false)}>
          <div className="formrow">
            <div>
              <label className="f">Scan run id</label>
              <input value={runId} onChange={(e) => setRunId(e.target.value)} placeholder="1" style={{ width: 90 }} />
            </div>
          </div>
          <label className="f">SARIF JSON</label>
          <textarea rows={9} value={text} onChange={(e) => setText(e.target.value)}
                    placeholder='{"version":"2.1.0","runs":[{"tool":{"driver":{...}},"results":[...]}]}' />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !text || !runId}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  const out = await api.post<{ imported: number }>("/api/appsec/sarif", {
                    scan_run_id: Number(runId),
                    sarif: JSON.parse(text),
                  });
                  setOpen(false);
                  onDone();
                  void out;
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Importing…" : "Import"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function SuppressButton({ f, onDone }: { f: Finding; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <>
      <button className="small" onClick={() => { setReason(""); setOpen(true); }}>Suppress</button>
      {open && (
        <Modal title={`Suppress ${f.rule_id || `finding ${f.id}`}`} onClose={() => setOpen(false)}>
          <p>
            Suppressions are recorded with a mandatory rationale and remain auditable. This is a lab action only.
          </p>
          <label className="f">Rationale (min 10 chars)</label>
          <textarea rows={3} value={reason} onChange={(e) => setReason(e.target.value)} autoFocus
                    placeholder="e.g. Input is internally generated; reviewed by AppSec on 2026-09-21." />
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="danger"
              disabled={busy || reason.trim().length < 10}
              onClick={async () => {
                setBusy(true);
                try {
                  await api.post(`/api/appsec/findings/${f.id}/suppress`, { reason });
                  setOpen(false);
                  onDone();
                } catch (e) {
                  setOpen(true);
                  setReason(reason + "\nERROR: " + (e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Suppressing…" : "Suppress"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
