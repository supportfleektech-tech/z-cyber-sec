import { useState } from "react";
import { api } from "../api";
import { LoadBlock, Modal, PageHead, StBadge, useApi, useFlash } from "../components";

// SEC-115: the lab range registry. The write-up of *why* this page exists is in
// docs/17-lab-range.md: an exercise authorizes targets, and this is the half of
// that sentence which says which targets actually exist and whether they are up.

interface Target {
  id: number;
  name: string;
  kind: string;
  endpoint: string;
  image: string | null;
  exposure: string;
  status: string;
  purpose: string | null;
  notes: string | null;
}
interface Authorization {
  exercise_id: number;
  name: string;
  status: string;
  owner: string | null;
  ends_at: string | null;
}
interface CoverageEntry extends Target {
  authorized_by: Authorization[];
  in_scope: boolean;
}
interface Coverage {
  targets: CoverageEntry[];
  counts: { registered: number; running: number };
  authorized_but_not_running: { name: string; status: string; exercises: string[] }[];
  running_but_not_authorized: { name: string; endpoint: string }[];
  authorizations_with_no_target: { exercise_id: number; exercise: string; target: string }[];
  other_authorized_targets: { exercise_id: number; exercise: string; target: string }[];
  note: string;
  ok: boolean;
}

const KINDS = ["web", "api", "network", "host", "cloud"];
const EXPOSURES = ["critical", "high", "medium", "low"];
const STATUSES = ["registered", "running", "stopped", "retired"];

export default function Lab() {
  const [flash, flashShow] = useFlash();
  const [sel, setSel] = useState<CoverageEntry | null>(null);
  const coverage = useApi<Coverage>(() => api.get<Coverage>("/api/lab/coverage"), []);

  const setStatus = async (t: CoverageEntry, status: string) => {
    try {
      await api.patch(`/api/lab/targets/${t.id}`, { status });
      flashShow(`${t.name} → ${status}`);
      coverage.reload();
    } catch (e) {
      flashShow(e instanceof Error ? e.message : String(e), false);
    }
  };

  const data = coverage.data;
  const drift = data?.running_but_not_authorized?.length ?? 0;
  const dangling = data?.authorizations_with_no_target?.length ?? 0;
  const notRunning = data?.authorized_but_not_running?.length ?? 0;

  return (
    <>
      <PageHead
        title="Lab range"
        sub="Registered training targets and whether the authorizations point at something real"
        actions={<NewTarget onDone={() => coverage.reload()} />}
      />
      {flash}

      {data && !data.ok && (
        <div className="error-box mb">
          Range cross-check failed:{" "}
          {drift > 0 && <b>{drift} running target(s) nobody authorized. </b>}
          {dangling > 0 && <b>{dangling} authorization(s) name a target that is not registered. </b>}
          Fix those before running a session — the first is scope drift, the second is an
          authorization pointing at nothing.
        </div>
      )}
      {data && data.ok && (
        <div className="note-box mb">
          Range cross-check clean: every running target is covered by an authorized exercise and every
          range-shaped authorization names a registered target.
        </div>
      )}

      <div className="grid cols-4 mb">
        <div className="stat">
          <div className="k">Registered</div>
          <div className="v">{data?.counts.registered ?? "—"}</div>
          <div className="s">targets in the registry</div>
        </div>
        <div className="stat">
          <div className="k">Running</div>
          <div className="v">{data?.counts.running ?? "—"}</div>
          <div className="s">containers reported up</div>
        </div>
        <div className="stat">
          <div className="k">Authorized, not running</div>
          <div className="v">{notRunning}</div>
          <div className="s">session would fail</div>
        </div>
        <div className="stat">
          <div className="k">Running, not authorized</div>
          <div className="v">{drift}</div>
          <div className="s">scope drift</div>
        </div>
      </div>

      <div className="panel">
        <LoadBlock loading={coverage.loading} error={coverage.error} empty={!data?.targets?.length}>
          <table className="tbl">
            <thead>
              <tr>
                <th>Target</th><th>Kind</th><th>Endpoint</th><th>Exposure</th><th>Status</th>
                <th>In scope</th><th>Authorized by</th><th>Action</th>
              </tr>
            </thead>
            <tbody>
              {(data?.targets ?? []).map((t) => (
                <tr key={t.id} onClick={() => setSel(t)} style={{ cursor: "pointer" }}>
                  <td>{t.name}</td>
                  <td><StBadge value={t.kind} /></td>
                  <td className="dim">{t.endpoint}</td>
                  <td><StBadge value={t.exposure} /></td>
                  <td><StBadge value={t.status} /></td>
                  <td>{t.in_scope ? <StBadge value="in scope" /> : <span className="faint">no</span>}</td>
                  <td className="dim">{t.authorized_by.map((a) => a.name).join(", ") || "—"}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <select
                      value={t.status}
                      onChange={(e) => setStatus(t, e.target.value)}
                      aria-label={`status for ${t.name}`}
                    >
                      {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      {data && (data.authorized_but_not_running.length > 0 || data.other_authorized_targets.length > 0) && (
        <div className="panel mt">
          <h2>Cross-checks</h2>
          {data.authorized_but_not_running.length > 0 && (
            <>
              <div className="f faint">Authorized but not running (the exercise is live, the target is not):</div>
              <ul>
                {data.authorized_but_not_running.map((t) => (
                  <li key={t.name}><code>{t.name}</code> is <b>{t.status}</b> — {t.exercises.join(", ")}</li>
                ))}
              </ul>
            </>
          )}
          {data.other_authorized_targets.length > 0 && (
            <>
              <div className="f faint">Authorized targets that are not range hosts (informational — mailboxes, vendor hosts are legitimate):</div>
              <ul>
                {data.other_authorized_targets.map((t) => (
                  <li key={`${t.exercise_id}-${t.target}`}><code>{t.target}</code> — {t.exercise}</li>
                ))}
              </ul>
            </>
          )}
          <div className="faint f">{data.note}</div>
        </div>
      )}

      {sel && (
        <Modal title={sel.name} onClose={() => setSel(null)}>
          <div className="kv">
            <div className="k">Endpoint</div><div>{sel.endpoint}</div>
            <div className="k">Kind</div><div>{sel.kind}</div>
            <div className="k">Image / profile</div><div>{sel.image || "—"}</div>
            <div className="k">Exposure if reached</div><div><StBadge value={sel.exposure} /></div>
            <div className="k">Status</div><div><StBadge value={sel.status} /></div>
            <div className="k">In scope</div><div>{sel.in_scope ? "yes" : "no"}</div>
            <div className="k">Authorized by</div>
            <div>
              {sel.authorized_by.length === 0 ? "—" : sel.authorized_by.map((a) => (
                <div key={a.exercise_id}>
                  #{a.exercise_id} {a.name} <span className="faint">({a.status}{a.ends_at ? `, ends ${a.ends_at}` : ""})</span>
                </div>
              ))}
            </div>
            <div className="k">Purpose</div><div>{sel.purpose || "—"}</div>
            <div className="k">Notes</div><div>{sel.notes || "—"}</div>
          </div>
          <div className="note-box mt">
            Start the range with <code>docker compose -f infra/lab/docker-compose.yml up -d</code>
            {" "}(loopback-only, isolated network). The platform never starts or touches a target.
          </div>
        </Modal>
      )}
    </>
  );
}

function NewTarget({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", endpoint: "", kind: "web", exposure: "medium", purpose: "" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string, v: string) => setForm((f) => ({ ...f, [k]: v }));
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ Register target</button>
      {open && (
        <Modal title="Register a lab target" onClose={() => setOpen(false)}>
          <label className="f">Name (as exercises list it, e.g. lab-juice-01)</label>
          <input value={form.name} onChange={(e) => set("name", e.target.value)} autoFocus placeholder="lab-juice-01" />
          <div className="formrow mt">
            <div>
              <label className="f">Endpoint (host[:port])</label>
              <input value={form.endpoint} onChange={(e) => set("endpoint", e.target.value)} placeholder="lab-juice-01:3000" />
            </div>
            <div>
              <label className="f">Kind</label>
              <select value={form.kind} onChange={(e) => set("kind", e.target.value)}>
                {KINDS.map((k) => <option key={k}>{k}</option>)}
              </select>
            </div>
            <div>
              <label className="f">Exposure</label>
              <select value={form.exposure} onChange={(e) => set("exposure", e.target.value)}>
                {EXPOSURES.map((k) => <option key={k}>{k}</option>)}
              </select>
            </div>
          </div>
          <label className="f">Purpose</label>
          <input value={form.purpose} onChange={(e) => set("purpose", e.target.value)} placeholder="what skill this target exercises" />
          {err && <div className="error-box">{err}</div>}
          <div className="foot" style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !form.name || !form.endpoint}
              onClick={async () => {
                setBusy(true); setErr(null);
                try {
                  await api.post("/api/lab/targets", { ...form, purpose: form.purpose || undefined });
                  setOpen(false); onDone();
                } catch (e) {
                  setErr(e instanceof Error ? e.message : String(e));
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Registering…" : "Register"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
