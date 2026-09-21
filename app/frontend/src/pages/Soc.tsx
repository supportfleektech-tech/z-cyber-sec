import { useState } from "react";
import { api, fmtTs } from "../api";
import { ConfirmButton, LoadBlock, Modal, PageHead, Pager, SevBadge, StBadge, useApi, useFlash } from "../components";

interface Alert {
  id: number;
  title: string;
  severity: string;
  status: string;
  count: number;
  first_seen: string;
  last_seen: string;
  assigned_to: string | null;
  rule_name: string | null;
  case_id: number | null;
}
interface EventRow {
  id: number;
  ts: string;
  host: string;
  user: string | null;
  action: string;
  outcome: string | null;
  severity: string;
  source_name: string | null;
  data: Record<string, unknown> | null;
}
interface Rule {
  id: number;
  uid: string;
  name: string;
  severity: string;
  status: string;
}
interface Paged<T> {
  items: T[];
  total: number;
}

const TRIAGE_STATUSES = ["new", "triaging", "confirmed", "false_positive", "closed"];

export default function Soc() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState<Alert | null>(null);
  const [flash, flashShow] = useFlash();

  const alerts = useApi<Paged<Alert>>(
    () =>
      api.get<Paged<Alert>>(
        `/api/soc/alerts?status=${encodeURIComponent(status)}&severity=${encodeURIComponent(severity)}&q=${encodeURIComponent(q)}&page=${page}&page_size=25`,
      ),
    [status, severity, q, page],
  );
  const rules = useApi<Paged<Rule>>(() => api.get<Paged<Rule>>("/api/soc/rules?page_size=100"), []);
  const events = useApi<Paged<EventRow>>(() => api.get<Paged<EventRow>>("/api/soc/events?page_size=40"), []);

  const patchAlert = async (a: Alert, body: Record<string, unknown>) => {
    await api.patch(`/api/soc/alerts/${a.id}`, body);
    setSel(null);
    alerts.reload();
  };

  return (
    <>
      <PageHead
        title="Alerts & Detection"
        sub="Sigma-subset rules evaluated over the embedded event store — dedupe prevents alert spam on refresh"
        actions={
          <>
            <button onClick={alerts.reload}>Refresh</button>
            <ConfirmButton
              label="Re-run backfill"
              confirmLabel="Re-run all active detection rules over stored events?"
              impact="Existing open alerts are refreshed (count/last_seen); only genuinely new detections are raised. Triggers on_alert playbooks for new alerts."
              onConfirm={async () => {
                const out = await api.post<{ events_checked: number; alerts: Alert[]; updated: number }>("/api/soc/detections/backfill");
                flashShow(`Backfill: ${out.alerts.length} new alert(s), ${out.updated} refreshed (of ${out.events_checked} events)`);
                alerts.reload();
              }}
            />
          </>
        }
      />
      {flash}

      <div className="toolbar">
        <input type="search" placeholder="Search title / rule…" value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} />
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
          <option value="">All statuses</option>
          {TRIAGE_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div className="panel">
        <LoadBlock loading={alerts.loading} error={alerts.error} empty={!alerts.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>ID</th><th>Alert</th><th>Rule</th><th>Severity</th><th>Status</th><th>Count</th><th>Last seen</th><th>Case</th><th>Assignee</th></tr>
            </thead>
            <tbody>
              {alerts.data!.items.map((a) => (
                <tr key={a.id} style={{ cursor: "pointer", background: sel?.id === a.id ? "var(--bg-hover)" : undefined }}
                    onClick={() => setSel(a)}>
                  <td className="mono">{a.id}</td>
                  <td>{a.title}</td>
                  <td className="dim">{a.rule_name || "—"}</td>
                  <td><SevBadge value={a.severity} /></td>
                  <td><StBadge value={a.severity && a.status} /></td>
                  <td>{a.count}</td>
                  <td className="dim">{fmtTs(a.last_seen)}</td>
                  <td className="dim">{a.case_id ? `#${a.case_id}` : "—"}</td>
                  <td className="dim">{a.assigned_to || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={page} page_size={25} total={alerts.data!.total} onPage={setPage} />
        </LoadBlock>
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <h2>Detection rules</h2>
          <LoadBlock loading={rules.loading} error={rules.error} empty={!rules.data?.items?.length}>
            <table className="tbl">
              <tbody>
                {rules.data!.items.map((r) => (
                  <tr key={r.id}>
                    <td className="mono dim">{r.uid}</td>
                    <td>{r.name}</td>
                    <td><SevBadge value={r.severity} /></td>
                    <td><StBadge value={r.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
          <RuleForm onCreated={() => rules.reload()} />
        </div>

        <div className="panel">
          <h2>Recent ingested events</h2>
          <LoadBlock loading={events.loading} error={events.error} empty={!events.data?.items?.length}>
            <table className="tbl">
              <thead>
                <tr><th>ts</th><th>host</th><th>action</th><th>outcome</th><th>src</th></tr>
              </thead>
              <tbody>
                {events.data!.items.map((e) => (
                  <tr key={e.id}>
                    <td className="dim mono">{fmtTs(e.ts)}</td>
                    <td>{e.host}</td>
                    <td>{e.action}</td>
                    <td>{e.outcome || "—"}</td>
                    <td className="dim">{e.source_name || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
        </div>
      </div>

      {sel && (
        <Modal title={`Alert #${sel.id} — ${sel.title}`} onClose={() => setSel(null)}>
          <div className="kv mb">
            <div className="k">Severity</div><div><SevBadge value={sel.severity} /></div>
            <div className="k">Status</div><div><StBadge value={sel.status} /></div>
            <div className="k">Rule</div><div>{sel.rule_name || "—"}</div>
            <div className="k">Count</div><div>{sel.count}</div>
            <div className="k">First / last seen</div>
            <div className="mono">{fmtTs(sel.first_seen)} → {fmtTs(sel.last_seen)}</div>
            <div className="k">Linked case</div><div>{sel.case_id ? `#${sel.case_id}` : "none"}</div>
          </div>
          <AlertEvents alertId={sel.id} />
          <div className="row mt">
            <label className="f" style={{ margin: 0 }}>Triage status</label>
            <select
              defaultValue={sel.status}
              onChange={async (e) => {
                await patchAlert(sel, { status: e.target.value });
                flashShow(`Alert ${sel.id} → ${e.target.value}`);
              }}
            >
              {TRIAGE_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <label className="f" style={{ margin: 0, marginLeft: 12 }}>Assignee</label>
            <input
              defaultValue={sel.assigned_to || ""}
              placeholder="e.g. sasha"
              style={{ width: 120 }}
              onBlur={async (e) => {
                if (e.target.value !== (sel.assigned_to || "")) {
                  await patchAlert(sel, { assigned_to: e.target.value || null });
                  flashShow(`Alert ${sel.id} reassigned`);
                }
              }}
            />
            <span className="right faint">PATCH /api/soc/alerts/{sel.id}</span>
          </div>
        </Modal>
      )}
    </>
  );
}

function AlertEvents({ alertId }: { alertId: number }) {
  const { data, loading, error } = useApi<{ events: EventRow[] }>(
    () => api.get<{ events: EventRow[] }>(`/api/soc/alerts/${alertId}`),
    [alertId],
  );
  if (loading) return <div className="empty">Loading events…</div>;
  if (error) return <div className="error-box">{error}</div>;
  if (!data || !data.events.length) return <div className="empty">No events recorded for this alert.</div>;
  return (
    <div className="mt">
      <div className="faint mb">Correlated events ({data.events.length})</div>
      <table className="tbl">
        <tbody>
          {data.events.slice(0, 10).map((e) => (
            <tr key={e.id}>
              <td className="dim mono">{fmtTs(e.ts)}</td>
              <td>{e.host}</td>
              <td>{e.action}</td>
              <td className="dim">{e.user || ""}</td>
              <td className="dim" style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.data ? JSON.stringify(e.data) : ""}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RuleForm({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [uid, setUid] = useState("");
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [specText, setSpecText] = useState(
    JSON.stringify(
      {
        detection: { fail: { action: "login_failed", outcome: "failure" } },
        condition: "fail",
        timeframe: 300,
        threshold: 10,
        entity: "user",
      },
      null,
      2,
    ),
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  return (
    <div className="mt">
      <button className="small" onClick={() => { setErr(null); setOpen(true); }}>+ New rule</button>
      {open && (
        <div className="panel mt" style={{ background: "var(--bg-panel-2)" }}>
          <div className="formrow">
            <div>
              <label className="f">uid</label>
              <input value={uid} onChange={(e) => setUid(e.target.value)} placeholder="cs-0007" style={{ width: 120 }} />
            </div>
            <div>
              <label className="f">name</label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Rule name" style={{ width: 220 }} />
            </div>
            <div>
              <label className="f">severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <label className="f">spec (Sigma-subset: detection / condition / timeframe / threshold / entity)</label>
          <textarea rows={8} value={specText} onChange={(e) => setSpecText(e.target.value)} />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt">
            <button
              className="primary"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/soc/rules", { uid, name, severity, spec: JSON.parse(specText) });
                  setOpen(false);
                  onCreated();
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Creating…" : "Create rule"}
            </button>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <span className="right faint">POST /api/soc/rules (rules.write)</span>
          </div>
        </div>
      )}
    </div>
  );
}
