import { useRef, useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, Pager, SevBadge, StBadge, useApi, useFlash } from "../components";

interface Vuln {
  id: number;
  cve_id: string | null;
  title: string;
  severity: string;
  status: string;
  cvss: number | null;
  asset: string | null;
  due_date: string | null;
  discovered_at: string;
}
interface Paged<T> {
  items: T[];
  total: number;
}

const VULN_STATUSES = ["new", "triaged", "in_progress", "fixed", "accepted_risk"];
// SEC-082: `accepted_risk` is not settable from the status dropdown — it is the
// result of recording an exception (rationale + approver + expiry), which is the
// form below. It stays in VULN_STATUSES so it can still be filtered for.
const SETTABLE_STATUSES = ["new", "triaged", "in_progress", "fixed"];

export default function Vulns() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState<Vuln | null>(null);
  const [flash, flashShow] = useFlash();
  const fileRef = useRef<HTMLInputElement>(null);
  const [busyImport, setBusyImport] = useState(false);

  const vulns = useApi<Paged<Vuln>>(
    () =>
      api.get<Paged<Vuln>>(
        `/api/vulns?status=${encodeURIComponent(status)}&severity=${encodeURIComponent(severity)}&q=${encodeURIComponent(q)}&page=${page}&page_size=25`,
      ),
    [status, severity, q, page],
  );

  return (
    <>
      <PageHead
        title="Vulnerabilities"
        sub="Findings with triage state, exceptions (rationale required), and remediation tracking"
        actions={
          <>
            <button onClick={vulns.reload}>Refresh</button>
            <NewVuln onDone={() => vulns.reload()} />
          </>
        }
      />
      {flash}
      <div className="toolbar">
        <input type="search" placeholder="Search CVE / title…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
          <option value="">All statuses</option>
          {VULN_STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <input ref={fileRef} type="file" accept=".csv" style={{ display: "none" }} />
        <button
          className="small"
          disabled={busyImport}
          onClick={async () => {
            const f = fileRef.current?.files?.[0];
            if (!f) return;
            setBusyImport(true);
            try {
              const fd = new FormData();
              fd.append("file", f);
              const out = await api.post<{ created: number; updated: number; errors: number; error_sample?: string[] }>("/api/vulns/import/csv", fd);
              flashShow(
                `CSV import: ${out.created} created, ${out.updated} updated, ${out.errors} error(s)` +
                  (out.error_sample?.length ? ` — ${out.error_sample[0]}` : ""),
                out.errors === 0,
              );
              vulns.reload();
            } catch (e) {
              flashShow((e as Error).message, false);
            } finally {
              setBusyImport(false);
            }
          }}
        >
          {busyImport ? "Importing…" : "Import CSV"}
        </button>
      </div>

      <div className="panel">
        <LoadBlock loading={vulns.loading} error={vulns.error} empty={!vulns.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>CVE</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Status</th><th>Asset</th><th>Due</th></tr>
            </thead>
            <tbody>
              {vulns.data!.items.map((v) => (
                <tr key={v.id} style={{ cursor: "pointer" }} onClick={() => setSel(v)}>
                  <td className="mono dim">{v.cve_id || "—"}</td>
                  <td>{v.title}</td>
                  <td><SevBadge value={v.severity} /></td>
                  <td>{v.cvss ?? "—"}</td>
                  <td><StBadge value={v.status} /></td>
                  <td className="dim">{v.asset || "—"}</td>
                  <td className="dim">{v.due_date || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={page} page_size={25} total={vulns.data!.total} onPage={setPage} />
        </LoadBlock>
      </div>

      {sel && <VulnModal v={sel} onClose={() => setSel(null)} onFlash={flashShow} onReload={() => vulns.reload()} />}
    </>
  );
}

function NewVuln({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [cve, setCve] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [cvss, setCvss] = useState("5.0");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ New finding</button>
      {open && (
        <Modal title="New vulnerability finding" onClose={() => setOpen(false)}>
          <label className="f">Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          <div className="formrow mt">
            <div>
              <label className="f">CVE id</label>
              <input value={cve} onChange={(e) => setCve(e.target.value)} placeholder="CVE-2026-00001" style={{ width: 170 }} />
            </div>
            <div>
              <label className="f">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="f">CVSS</label>
              <input value={cvss} onChange={(e) => setCvss(e.target.value)} style={{ width: 70 }} />
            </div>
          </div>
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !title}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/vulns", { title, cve_id: cve || undefined, severity, cvss: Number(cvss) || undefined });
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

function VulnModal({ v, onClose, onFlash, onReload }: { v: Vuln; onClose: () => void; onFlash: (m: string, ok?: boolean) => void; onReload: () => void }) {
  const ex = useApi<{ items: { id: number; reason: string; expires_at: string; requested_by: string }[] }>(
    () => api.get(`/api/vulns/${v.id}/exceptions`),
    [v.id],
  );
  const rem = useApi<{ items: { id: number; title: string; status: string; owner: string | null; due: string | null }[] }>(
    () => api.get(`/api/vulns/${v.id}/remediation`),
    [v.id],
  );
  const detail = {
    loading: ex.loading || rem.loading,
    error: ex.error || rem.error,
    exceptions: ex.data?.items || [],
    remediation: rem.data?.items || [],
    reload: () => {
      ex.reload();
      rem.reload();
    },
  };
  const [exReason, setExReason] = useState("");
  const [remTitle, setRemTitle] = useState("");
  const [remOwner, setRemOwner] = useState("");

  const patch = async (body: Record<string, unknown>) => {
    await api.patch(`/api/vulns/${v.id}`, body);
    detail.reload();
    onReload();
  };

  return (
    <Modal title={`${v.cve_id || "finding"} — ${v.title}`} onClose={onClose}>
      <div className="kv mb">
        <div className="k">Severity</div><div><SevBadge value={v.severity} /> <span className="faint">CVSS {v.cvss ?? "—"}</span></div>
        <div className="k">Status</div>
        <div>
          <select
            defaultValue={v.status}
            style={{ width: 170 }}
            onChange={async (e) => {
              try {
                await patch({ status: e.target.value });
                onFlash(`Finding → ${e.target.value}`);
              } catch (e) {
                onFlash((e as Error).message, false);
              }
            }}
          >
            {SETTABLE_STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
          <span className="faint" style={{ marginLeft: 8 }}>
            accept a risk by recording an exception below
          </span>
        </div>
        <div className="k">Asset</div><div>{v.asset || "—"}</div>
        <div className="k">Discovered</div><div className="mono">{fmtTs(v.discovered_at)}</div>
        <div className="k">Due</div><div>{v.due_date || "—"}</div>
      </div>

      <h2 style={{ fontSize: 13, marginTop: 14 }}>Exceptions</h2>
      <LoadBlock loading={detail.loading} error={detail.error} empty={!detail.exceptions.length}>
        {(detail.exceptions || []).map((e) => (
          <div key={(e as { id: number }).id} className="mb">
            <div>{(e as { reason: string }).reason}</div>
            <div className="faint">
              requested by {(e as { requested_by: string }).requested_by} · expires {(e as { expires_at: string }).expires_at}
            </div>
          </div>
        ))}
      </LoadBlock>
      <div className="row mt">
        <input value={exReason} onChange={(e) => setExReason(e.target.value)} placeholder="Exception rationale (required)" style={{ flex: 1 }} />
        <button
          className="small"
          disabled={exReason.trim().length < 10}
          onClick={async () => {
            try {
              await api.post(`/api/vulns/${v.id}/exceptions`, { reason: exReason });
              setExReason("");
              detail.reload();
              onReload();
              onFlash("Exception recorded (status → accepted_risk)");
            } catch (e) {
              onFlash((e as Error).message, false);
            }
          }}
        >
          Add exception
        </button>
      </div>

      <h2 style={{ fontSize: 13, marginTop: 14 }}>Remediation</h2>
      <table className="tbl">
        <tbody>
          {(detail.remediation || []).map((t) => (
            <tr key={(t as { id: number }).id}>
              <td>{(t as { title: string }).title}</td>
              <td><StBadge value={(t as { status: string }).status} /></td>
              <td className="dim">{(t as { owner: string | null }).owner || "—"}</td>
            </tr>
          ))}
          {!detail.remediation.length && (
            <tr><td className="empty">No remediation tasks.</td></tr>
          )}
        </tbody>
      </table>
      <div className="row mt">
        <input value={remTitle} onChange={(e) => setRemTitle(e.target.value)} placeholder="Remediation task" style={{ flex: 1 }} />
        <input value={remOwner} onChange={(e) => setRemOwner(e.target.value)} placeholder="owner" style={{ width: 110 }} />
        <button
          className="small"
          disabled={!remTitle}
          onClick={async () => {
            try {
              await api.post(`/api/vulns/${v.id}/remediation`, { title: remTitle, owner: remOwner || undefined });
              setRemTitle("");
              setRemOwner("");
              detail.reload();
              onReload();
              onFlash("Remediation task added");
            } catch (e) {
              onFlash((e as Error).message, false);
            }
          }}
        >
          Add
        </button>
      </div>
    </Modal>
  );
}
