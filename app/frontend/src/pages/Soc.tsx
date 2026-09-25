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
  // SEC-074: false = stored but INERT (detection never fires it).
  compiles: boolean;
  error: string | null;
  // SEC-103: fields this rule reads that no ingested event carries.
  unmatched_fields?: string[];
}
interface Paged<T> {
  items: T[];
  total: number;
}
interface Coverage {
  total_rules: number;
  active_rules: number;
  inert_rules: number;
  fired_rules: number;
  coverage_pct: number;
  gaps: { uid: string; name: string; severity: string }[];
  broken_rules: { uid: string; name: string; severity: string; status: string; error: string | null }[];
  // SEC-103: a rule can compile and still never match — it may watch a field no
  // event carries (a typo like `user_name` for `user`).
  misconfigured_rules: number;
  watching_unknown_fields: { uid: string; name: string; severity: string; status: string; unmatched_fields: string[]; alerts_total: number }[];
  rules: { uid: string; name: string; severity: string; status: string; alerts_total: number; last_alert_at: string | null; never_fired: boolean; compiles: boolean; error: string | null; unmatched_fields: string[] }[];
}
interface Scenario {
  uid: string;
  name: string;
  description: string;
  expected_rule: string;
  events: number;
}
interface SavedSearch {
  id: number;
  name: string;
  module: string;
  params: Record<string, unknown>;
  created_at: string;
}

// SEC-079: must match ALERT_STATUSES in routers/soc.py — "false_positive" is not
// a status the API accepts (400 bad_status), and the real "dismissed" value was
// missing, so a false positive could not be recorded from the UI at all.
const TRIAGE_STATUSES = ["new", "triaging", "confirmed", "dismissed", "closed"];

export default function Soc() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [sel, setSel] = useState<Alert | null>(null);
  const [note, setNote] = useState("");
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
    setNote("");
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
                    <td>
                      {r.compiles
                        ? (r.unmatched_fields?.length
                            ? (
                              <span className="st inert"
                                title={`watches field(s) no event carries: ${r.unmatched_fields.join(", ")}`}>
                                misconfigured
                              </span>
                            )
                            : <span className="st closed">live</span>)
                        : <span className="st inert" title={r.error || undefined}>inert</span>}
                    </td>
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

      <div className="grid cols-3 mt">
        <CoveragePanel />
        <PurpleTeamPanel onRan={() => { alerts.reload(); }} />
        <SavedSearchesPanel
          currentParams={{ q, status, severity }}
          onApply={(p) => { setQ(p.q || ""); setStatus(p.status || ""); setSeverity(p.severity || ""); setPage(1); }}
        />
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
            <label className="f" style={{ margin: 0 }}>Disposition note</label>
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="why — required when dismissing as a false positive"
              style={{ flex: 1, minWidth: 220 }}
            />
          </div>
          <div className="row" style={{ marginTop: 6 }}>
            <label className="f" style={{ margin: 0 }}>Triage status</label>
            <select
              defaultValue={sel.status}
              onChange={async (e) => {
                const body: Record<string, unknown> = { status: e.target.value };
                if (note.trim()) body.notes = note.trim();
                await patchAlert(sel, body);
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

function CoveragePanel() {
  const cov = useApi<Coverage>(() => api.get<Coverage>("/api/soc/rules/coverage"), []);
  return (
    <div className="panel">
      <h2>Detection coverage</h2>
      <LoadBlock loading={cov.loading} error={cov.error}>
        {cov.data && (
          <>
            <div className="grid cols-2 mb">
              <div className="stat"><div className="k">coverage</div><div className="v">{cov.data.coverage_pct}%</div><div className="s">active rules have fired</div></div>
              <div className="stat"><div className="k">fired / active</div><div className="v">{cov.data.fired_rules}/{cov.data.active_rules}</div><div className="s">of {cov.data.total_rules} total</div></div>
            </div>
            {cov.data.inert_rules > 0 && (
              <div className="inert-warn">
                <strong>{cov.data.inert_rules} inert rule(s)</strong> — these are stored
                as <code>active</code> but cannot compile, so detection never fires them
                (<code>scripts/lint_rules.py</code>):
                <ul style={{ margin: "6px 0 0 16px" }}>
                  {cov.data.broken_rules.map((b) => (
                    <li key={b.uid}>
                      <span className="mono">{b.uid}</span> — {b.error}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {cov.data.misconfigured_rules > 0 && (
              <div className="inert-warn">
                <strong>{cov.data.misconfigured_rules} rule(s) watch fields no event carries</strong> —
                they compile, so they look live, but the term can never be true
                (fix the field name or the emitter):
                <ul style={{ margin: "6px 0 0 16px" }}>
                  {cov.data.watching_unknown_fields.map((b) => (
                    <li key={b.uid}>
                      <span className="mono">{b.uid}</span> — {b.unmatched_fields.join(", ")}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {cov.data.gaps.length > 0 ? (
              <div className="faint mb">Coverage gaps (active, never fired): {cov.data.gaps.map((g) => g.uid).join(", ")}</div>
            ) : (
              <div className="faint mb">No coverage gaps — every active rule has fired.</div>
            )}
            <table className="tbl">
              <tbody>
                {cov.data.rules.map((r) => (
                  <tr key={r.uid}>
                    <td className="mono dim">{r.uid}</td>
                    <td>{r.name}</td>
                    <td className="dim">{r.alerts_total}</td>
                    <td>
                      {!r.compiles
                        ? <span className="st inert" title={r.error || undefined}>inert</span>
                        : r.never_fired
                          ? <span className="st open">gap</span>
                          : <span className="st closed">fired</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </LoadBlock>
    </div>
  );
}

function PurpleTeamPanel({ onRan }: { onRan: () => void }) {
  const sc = useApi<{ scenarios: Scenario[] }>(() => api.get<{ scenarios: Scenario[] }>("/api/soc/purple-team/scenarios"), []);
  const [flash, flashShow] = useFlash();
  const [busy, setBusy] = useState<string | null>(null);
  const [last, setLast] = useState<Record<string, boolean>>({});
  return (
    <div className="panel">
      <h2>Purple team</h2>
      <div className="faint mb">Recorded synthetic attacks run through the live detection path — expect the named rule to fire.</div>
      {flash}
      <LoadBlock loading={sc.loading} error={sc.error} empty={!sc.data?.scenarios?.length}>
        <table className="tbl">
          <tbody>
            {sc.data!.scenarios.map((s) => (
              <tr key={s.uid}>
                <td className="mono dim">{s.uid}</td>
                <td>{s.name}<div className="faint" style={{ fontSize: 11 }}>{s.events} events → {s.expected_rule}</div></td>
                <td>
                  {last[s.uid] !== undefined && (last[s.uid] ? <span className="st closed">pass</span> : <span className="st denied">fail</span>)}
                  <button className="small" disabled={busy === s.uid}
                    onClick={async () => {
                      setBusy(s.uid);
                      try {
                        const out = await api.post<{ passed: boolean; run_id: string }>(`/api/soc/purple-team/run`, { scenario: s.uid });
                        setLast((p) => ({ ...p, [s.uid]: out.passed }));
                        flashShow(`PT ${s.uid}: ${out.passed ? "PASS" : "FAIL"} (run ${out.run_id})`);
                        onRan();
                      } finally {
                        setBusy(null);
                      }
                    }}>
                    {busy === s.uid ? "Running…" : "Run"}
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

function SavedSearchesPanel({ currentParams, onApply }: {
  currentParams: Record<string, string>;
  onApply: (p: Record<string, string>) => void;
}) {
  const [name, setName] = useState("");
  const ss = useApi<{ items: SavedSearch[]; total: number }>(
    () => api.get<{ items: SavedSearch[]; total: number }>("/api/soc/saved-searches"), []);
  const [flash, flashShow] = useFlash();
  const [err, setErr] = useState<string | null>(null);
  return (
    <div className="panel">
      <h2>Saved searches</h2>
      {flash}
      <div className="row mb">
        <input placeholder="Name this filter…" value={name} onChange={(e) => setName(e.target.value)} style={{ width: 150 }} />
        <button className="small" disabled={!name.trim()}
          onClick={async () => {
            setErr(null);
            try {
              await api.post("/api/soc/saved-searches", { name: name.trim(), module: "alerts", params: currentParams });
              setName("");
              flashShow("Saved current alert filter");
              ss.reload();
            } catch (e) {
              setErr((e as Error).message);
            }
          }}>
          Save current
        </button>
      </div>
      {err && <div className="error-box">{err}</div>}
      <LoadBlock loading={ss.loading} error={ss.error} empty={!ss.data?.items?.length}>
        <table className="tbl">
          <tbody>
            {ss.data!.items.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td className="dim mono" style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {JSON.stringify(s.params)}
                </td>
                <td>
                  <button className="small" onClick={() => onApply(s.params as Record<string, string>)}>Apply</button>{" "}
                  <button className="small danger"
                    onClick={async () => {
                      await api.delete(`/api/soc/saved-searches/${s.id}`);
                      ss.reload();
                    }}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </LoadBlock>
    </div>
  );
}
