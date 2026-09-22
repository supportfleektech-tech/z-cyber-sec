import { useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, StBadge, useApi, useFlash } from "../components";

interface Report {
  id: number;
  kind: string;
  title: string;
  filters: Record<string, unknown> | null;
  generated_by: string;
  created_at: string;
  path: string;
  meta: { input_rows?: number; input_sha256?: string } | null;
}
interface Paged<T> {
  items: T[];
  total: number;
}

interface Schedule {
  id: number;
  kind: string;
  title: string;
  filters: Record<string, unknown>;
  interval_minutes: number;
  last_run_at: string | null;
  next_run_at: string | null;
  status: string;
  created_by: string;
}

const KINDS = ["overview", "soc", "cases", "intel", "vulns", "tradecraft"];

export default function Reports() {
  const [flash, flashShow] = useFlash();
  const [kind, setKind] = useState("");
  const reports = useApi<Paged<Report>>(
    () => api.get<Paged<Report>>(`/api/reports?kind=${encodeURIComponent(kind)}&page_size=50`),
    [kind],
  );

  return (
    <>
      <PageHead
        title="Reports"
        sub="Static HTML with provenance: generator, actor, timestamp, input row counts, snapshot sha256, environment label"
        actions={<Generate onDone={() => reports.reload()} />}
      />
      {flash}
      <div className="toolbar">
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All kinds</option>
          {KINDS.map((k) => <option key={k}>{k}</option>)}
        </select>
        <span className="faint">Download requires reports.generate (admin / ir_lead / soc_analyst)</span>
      </div>

      <div className="panel">
        <LoadBlock loading={reports.loading} error={reports.error} empty={!reports.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>ID</th><th>Title</th><th>Kind</th><th>By</th><th>Generated</th><th>Provenance</th><th></th></tr>
            </thead>
            <tbody>
              {reports.data!.items.map((r) => (
                <tr key={r.id}>
                  <td className="mono dim">{r.id}</td>
                  <td>{r.title}</td>
                  <td><StBadge value={r.kind} /></td>
                  <td className="dim">{r.generated_by}</td>
                  <td className="dim">{fmtTs(r.created_at)}</td>
                  <td className="dim" title={r.meta?.input_sha256}>
                    {r.meta?.input_rows ?? "—"} rows ·{" "}
                    {r.meta?.input_sha256 ? <span className="mono">{r.meta.input_sha256.slice(0, 12)}…</span> : "—"}
                  </td>
                  <td>
                    <a className="btn small" href={`/api/reports/${r.id}/download`} target="_blank" rel="noreferrer">
                      Open (HTML)
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>
      <Schedules onRan={() => reports.reload()} />
      <div className="note-box">
        Reports are generated from the current database snapshot. The embedded <code>input_sha256</code> pins the
        snapshot that produced the document; print-to-PDF via the browser is the export path (no paid export services).
        Scheduled runs are performed by the in-process scheduler (stdlib threading) and labeled
        <code> scheduler:&lt;user&gt;</code> in the report's generator field.
      </div>
    </>
  );
}

function Schedules({ onRan }: { onRan: () => void }) {
  const [flash, flashShow] = useFlash();
  const [kind, setKind] = useState("overview");
  const [title, setTitle] = useState("");
  const [interval, setIntervalMin] = useState(1440);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const list = useApi<{ items: Schedule[]; total: number }>(
    () => api.get<{ items: Schedule[]; total: number }>("/api/reports/schedules"), []);
  return (
    <div className="panel mt">
      <h2>Scheduled reports</h2>
      {flash}
      <div className="row mb">
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => <option key={k}>{k}</option>)}
        </select>
        <input placeholder="Title (optional)" value={title} onChange={(e) => setTitle(e.target.value)} style={{ width: 180 }} />
        <select value={interval} onChange={(e) => setIntervalMin(Number(e.target.value))}>
          <option value={60}>hourly</option>
          <option value={360}>6-hourly</option>
          <option value={1440}>daily</option>
          <option value={10080}>weekly</option>
        </select>
        <button className="small" disabled={busy}
          onClick={async () => {
            setBusy(true); setErr(null);
            try {
              await api.post("/api/reports/schedules", { kind, title: title || undefined, interval_minutes: interval });
              setTitle("");
              flashShow("Schedule created");
              list.reload();
            } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
          }}>
          + Schedule
        </button>
        <span style={{ flex: 1 }} />
        <button className="small" disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              const out = await api.post<{ built: number }>("/api/reports/schedules/run-due", {});
              flashShow(`Ran ${out.built} due schedule(s)`);
              list.reload(); onRan();
            } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
          }}>
          Run due now
        </button>
      </div>
      {err && <div className="error-box">{err}</div>}
      <LoadBlock loading={list.loading} error={list.error} empty={!list.data?.items?.length}>
        <table className="tbl">
          <thead>
            <tr><th>Title</th><th>Kind</th><th>Interval</th><th>Last run</th><th>Next run</th><th>Status</th><th></th></tr>
          </thead>
          <tbody>
            {list.data!.items.map((s) => (
              <tr key={s.id}>
                <td>{s.title}</td>
                <td className="dim">{s.kind}</td>
                <td className="dim">{Math.round(s.interval_minutes / 60)}h</td>
                <td className="dim">{s.last_run_at ? fmtTs(s.last_run_at) : "—"}</td>
                <td className="dim">{s.next_run_at ? fmtTs(s.next_run_at) : "—"}</td>
                <td><StBadge value={s.status} /></td>
                <td>
                  <button className="small"
                    onClick={async () => {
                      await api.patch(`/api/reports/schedules/${s.id}`, { status: s.status === "active" ? "paused" : "active" });
                      list.reload();
                    }}>
                    {s.status === "active" ? "Pause" : "Resume"}
                  </button>{" "}
                  <button className="small danger"
                    onClick={async () => {
                      await api.delete(`/api/reports/schedules/${s.id}`);
                      list.reload();
                    }}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </LoadBlock>
    </div>
  );
}

function Generate({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState("overview");
  const [title, setTitle] = useState("");
  const [filterText, setFilterText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ Generate report</button>
      {open && (
        <Modal title="Generate report" onClose={() => setOpen(false)}>
          <div className="formrow">
            <div>
              <label className="f">Kind</label>
              <select value={kind} onChange={(e) => setKind(e.target.value)}>
                {KINDS.map((k) => <option key={k}>{k}</option>)}
              </select>
            </div>
            <div>
              <label className="f">Title (optional)</label>
              <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="auto" style={{ width: 180 }} />
            </div>
          </div>
          <label className="f">Filters (JSON — e.g. {kind === "soc" ? '{"severity":"high"}' : '{"status":"open"}'})</label>
          <textarea rows={2} value={filterText} onChange={(e) => setFilterText(e.target.value)} placeholder="{}" />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  let filters: unknown = {};
                  if (filterText.trim()) filters = JSON.parse(filterText);
                  await api.post("/api/reports", { kind, title: title || undefined, filters });
                  setOpen(false);
                  onDone();
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Generating…" : "Generate"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
