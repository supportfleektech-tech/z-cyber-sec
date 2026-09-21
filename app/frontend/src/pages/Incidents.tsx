import { useRef, useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, Pager, SevBadge, StBadge, useApi, useFlash } from "../components";

interface CaseRow {
  id: number;
  number: string;
  title: string;
  status: string;
  priority: string;
  severity: string | null;
  assigned_to: string | null;
  created_at: string;
  closed_at: string | null;
}
interface CaseDetail extends CaseRow {
  description: string | null;
  source: string | null;
  alert_id: number | null;
  tasks: { id: number; title: string; status: string; assigned_to: string | null }[];
  timeline: { ts: string; actor: string; entry_type: string; message: string }[];
  evidence: { id: number; name: string; size: number; classification: string; retention: string | null; uploaded_by: string; created_at: string; sha256: string }[];
}
interface Paged<T> {
  items: T[];
  total: number;
}

const CASE_STATUSES = ["open", "investigating", "containment", "recovered", "closed"];

export default function Incidents() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [sel, setSel] = useState<CaseRow | null>(null);
  const [flash, flashShow] = useFlash();

  const cases = useApi<Paged<CaseRow>>(
    () => api.get<Paged<CaseRow>>(`/api/cases?status=${encodeURIComponent(status)}&page=${page}&page_size=20`),
    [status, page],
  );

  return (
    <>
      <PageHead
        title="Incidents"
        sub="Cases with timeline, tasks, and integrity-checked evidence"
        actions={<NewCase onCreated={() => { cases.reload(); }} />}
      />
      {flash}
      <div className="toolbar">
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
          <option value="">All statuses</option>
          {CASE_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>
      <div className="panel">
        <LoadBlock loading={cases.loading} error={cases.error} empty={!cases.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Number</th><th>Title</th><th>Priority</th><th>Severity</th><th>Status</th><th>Assignee</th><th>Created</th></tr>
            </thead>
            <tbody>
              {cases.data!.items.map((c) => (
                <tr key={c.id} style={{ cursor: "pointer" }} onClick={() => setSel(c)}>
                  <td className="mono dim">{c.number}</td>
                  <td>{c.title}</td>
                  <td><StBadge value={c.priority} /></td>
                  <td><SevBadge value={c.severity} /></td>
                  <td><StBadge value={c.status} /></td>
                  <td className="dim">{c.assigned_to || "—"}</td>
                  <td className="dim">{fmtTs(c.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={page} page_size={20} total={cases.data!.total} onPage={setPage} />
        </LoadBlock>
      </div>

      {sel && <CaseModal c={sel} onClose={() => setSel(null)} onFlash={flashShow} />}
    </>
  );
}

function NewCase({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState("medium");
  const [severity, setSeverity] = useState("");
  const [alertId, setAlertId] = useState("");
  const [desc, setDesc] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ New case</button>
      {open && (
        <Modal title="New case" onClose={() => setOpen(false)}>
          <label className="f">Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          <div className="formrow mt">
            <div>
              <label className="f">Priority</label>
              <select value={priority} onChange={(e) => setPriority(e.target.value)}>
                {["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="f">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                <option value="">—</option>
                {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="f">Linked alert id</label>
              <input value={alertId} onChange={(e) => setAlertId(e.target.value)} placeholder="optional" style={{ width: 110 }} />
            </div>
          </div>
          <label className="f">Description</label>
          <textarea rows={3} value={desc} onChange={(e) => setDesc(e.target.value)} />
          {err && <div className="error-box">{err}</div>}
          <div className="foot" style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !title}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/cases", {
                    title,
                    priority,
                    severity: severity || undefined,
                    description: desc || undefined,
                    alert_id: alertId ? Number(alertId) : undefined,
                  });
                  setOpen(false);
                  onCreated();
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

function CaseModal({ c, onClose, onFlash }: { c: CaseRow; onClose: () => void; onFlash: (m: string, ok?: boolean) => void }) {
  const detail = useApi<CaseDetail>(() => api.get<CaseDetail>(`/api/cases/${c.id}`), [c.id]);
  const [taskTitle, setTaskTitle] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const [classification, setClassification] = useState("internal");
  const [busy, setBusy] = useState(false);

  const patchCase = async (body: Record<string, unknown>) => {
    await api.patch(`/api/cases/${c.id}`, body);
    detail.reload();
  };

  return (
    <Modal title={`${c.number} — ${c.title}`} onClose={onClose}>
      <LoadBlock loading={detail.loading} error={detail.error}>
        {detail.data && (
          <>
            <div className="kv mb">
              <div className="k">Status</div>
              <div className="row">
                <select
                  defaultValue={detail.data.status}
                  style={{ width: 160 }}
                  onChange={async (e) => {
                    try {
                      await patchCase({ status: e.target.value });
                      onFlash(`Case → ${e.target.value}`);
                    } catch (e) {
                      onFlash((e as Error).message, false);
                    }
                  }}
                >
                  {CASE_STATUSES.map((s) => <option key={s}>{s}</option>)}
                </select>
                <SevBadge value={detail.data.severity} />
              </div>
              <div className="k">Source</div><div>{detail.data.source || "manual"}</div>
              <div className="k">Assignee</div><div>{detail.data.assigned_to || "—"}</div>
              <div className="k">Window</div>
              <div className="mono">{fmtTs(detail.data.created_at)} → {fmtTs(detail.data.closed_at)}</div>
            </div>
            {detail.data.description && <div className="note-box">{detail.data.description}</div>}

            <h2 style={{ fontSize: 13, marginTop: 16 }}>Timeline</h2>
            <ul className="timeline">
              {(detail.data.timeline || []).map((t, i) => (
                <li key={i}>
                  <div className="ts">{fmtTs(t.ts)} · {t.actor} · {t.entry_type}</div>
                  {t.message}
                </li>
              ))}
              {!detail.data.timeline?.length && <div className="empty">No timeline entries.</div>}
            </ul>

            <h2 style={{ fontSize: 13, marginTop: 16 }}>Tasks</h2>
            <table className="tbl">
              <tbody>
                {(detail.data.tasks || []).map((t) => (
                  <tr key={t.id}>
                    <td>{t.title}</td>
                    <td><StBadge value={t.status} /></td>
                    <td className="dim">{t.assigned_to || "—"}</td>
                    <td>
                      <select
                        defaultValue={t.status}
                        className="small"
                        onChange={async (e) => {
                          try {
                            await api.patch(`/api/cases/tasks/${t.id}`, { status: e.target.value });
                            detail.reload();
                          } catch (e) {
                            onFlash((e as Error).message, false);
                          }
                        }}
                      >
                        {["open", "in_progress", "done"].map((s) => <option key={s}>{s}</option>)}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="row mt">
              <input value={taskTitle} onChange={(e) => setTaskTitle(e.target.value)} placeholder="New task title" style={{ flex: 1 }} />
              <button
                className="small"
                disabled={!taskTitle}
                onClick={async () => {
                  await api.post(`/api/cases/${c.id}/tasks`, { title: taskTitle });
                  setTaskTitle("");
                  detail.reload();
                }}
              >
                Add task
              </button>
            </div>

            <h2 style={{ fontSize: 13, marginTop: 16 }}>Evidence (sha256-verified on download)</h2>
            <table className="tbl">
              <thead>
                <tr><th>File</th><th>Size</th><th>Class</th><th>Retention</th><th>Uploaded by</th><th></th></tr>
              </thead>
              <tbody>
                {(detail.data.evidence || []).map((e) => (
                  <tr key={e.id}>
                    <td>{e.name}</td>
                    <td className="dim">{e.size} B</td>
                    <td><StBadge value={e.classification} /></td>
                    <td className="dim">{e.retention || "—"}</td>
                    <td className="dim">{e.uploaded_by}</td>
                    <td>
                      <a className="btn small" href={`/api/cases/evidence/${e.id}/download`} download>
                        Download
                      </a>
                    </td>
                  </tr>
                ))}
                {!detail.data.evidence?.length && (
                  <tr><td colSpan={6} className="empty">No evidence attached.</td></tr>
                )}
              </tbody>
            </table>
            <div className="row mt">
              <input ref={fileRef} type="file" style={{ display: "none" }} />
              <select value={classification} onChange={(e) => setClassification(e.target.value)}>
                {["public", "internal", "confidential", "restricted"].map((s) => <option key={s}>{s}</option>)}
              </select>
              <button
                className="small"
                disabled={busy}
                onClick={async () => {
                  const f = fileRef.current?.files?.[0];
                  if (!f) return;
                  setBusy(true);
                  try {
                    const fd = new FormData();
                    fd.append("file", f);
                    fd.append("classification", classification);
                    await api.post(`/api/cases/${c.id}/evidence`, fd);
                    detail.reload();
                    onFlash(`Evidence "${f.name}" uploaded`);
                  } catch (e) {
                    onFlash((e as Error).message, false);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                {busy ? "Uploading…" : "Attach evidence file"}
              </button>
              <button className="small" onClick={() => fileRef.current?.click()}>Choose file…</button>
              <span className="faint right">max 5 MB · ACL 0600 · download requires evidence.download</span>
            </div>
          </>
        )}
      </LoadBlock>
    </Modal>
  );
}
