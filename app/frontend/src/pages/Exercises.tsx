import { useState } from "react";
import { api, fmtTs } from "../api";
import { ConfirmButton, LoadBlock, Modal, PageHead, StBadge, useApi, useFlash } from "../components";

interface Exercise {
  id: number;
  name: string;
  scope: string;
  status: string;
  owner: string | null;
  starts_at: string | null;
  ends_at: string | null;
  targets: string[] | null;
}
interface ExerciseDetail extends Exercise {
  runs: { id: number; started_at: string; finished_at: string | null; result: string; detail: string | null }[];
}
interface Paged<T> {
  items: T[];
  total: number;
}

const FLOW: [string, string][] = [
  ["planned", "Mark authorized"],
  ["authorized", "Start (running)"],
  ["running", "Complete"],
];

export default function Exercises() {
  const [flash, flashShow] = useFlash();
  const [sel, setSel] = useState<Exercise | null>(null);
  const exercises = useApi<Paged<Exercise>>(() => api.get<Paged<Exercise>>("/api/exercises?page_size=50"), []);

  const nextAction = (s: string): [string, string] | null => FLOW.find(([from]) => from === s) || null;

  return (
    <>
      <PageHead
        title="Exercises"
        sub="Authorized Red Team / CTF exercises — authorization required before running; platform never initiates network action"
        actions={<NewExercise onDone={() => exercises.reload()} />}
      />
      {flash}
      <div className="note-box">
        Guardrail: an exercise cannot transition to <code>running</code> unless it is <code>authorized</code>
        (server-side 409). Targets are inventory only — no network action is ever initiated by the platform.
      </div>

      <div className="panel">
        <LoadBlock loading={exercises.loading} error={exercises.error} empty={!exercises.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Exercise</th><th>Scope</th><th>Status</th><th>Owner</th><th>Window</th><th>Targets</th><th>Action</th></tr>
            </thead>
            <tbody>
              {exercises.data!.items.map((e) => (
                <tr key={e.id} style={{ cursor: "pointer" }} onClick={() => setSel(e)}>
                  <td>{e.name}</td>
                  <td className="dim" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.scope}>
                    {e.scope}
                  </td>
                  <td><StBadge value={e.status} /></td>
                  <td className="dim">{e.owner || "—"}</td>
                  <td className="dim">{fmtTs(e.starts_at)} → {fmtTs(e.ends_at)}</td>
                  <td className="dim">{e.targets?.join(", ") || "—"}</td>
                  <td onClick={(ev) => ev.stopPropagation()}>
                    <StatusAdvance e={e} onDone={() => exercises.reload()} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      {sel && (
        <Modal title={`Exercise — ${sel.name}`} onClose={() => setSel(null)}>
          <ExerciseDetailModal e={sel} onClose={() => setSel(null)} onFlash={flashShow} />
        </Modal>
      )}
      <span className="faint">{nextAction("planned") ? "Flow: planned → authorized → running → completed" : ""}</span>
    </>
  );
}

function StatusAdvance({ e, onDone }: { e: Exercise; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const action = FLOW.find(([from]) => from === e.status);
  if (!action) return <span className="faint">—</span>;
  const [from, label] = action;
  const to = from === "planned" ? "authorized" : from === "authorized" ? "running" : "completed";
  const needsReason = to === "completed";
  return (
    <span className="row">
      <input
        value={reason}
        onChange={(ev) => setReason(ev.target.value)}
        placeholder={needsReason ? "reason required" : undefined}
        style={{ width: 130, display: needsReason ? "inline-block" : "none" }}
      />
      <ConfirmButton
        label={label}
        confirmLabel={`Move exercise "${e.name}" from ${from} to ${to}?`}
        impact={
          to === "running"
            ? "Runs an authorized synthetic scenario against lab inventory only. Every step is recorded in the run log."
            : to === "completed"
              ? `Exercise closes with result=completed. Reason: ${reason || "(none given)"}`
              : "Marks the exercise as authorized. Requires written scope (already on record)."
        }
        onConfirm={async () => {
          setBusy(true);
          try {
            await api.patch(`/api/exercises/${e.id}`, {
              status: to,
              reason: reason || undefined,
            });
            setReason("");
            onDone();
          } finally {
            setBusy(false);
          }
        }}
      />
    </span>
  );
}

function ExerciseDetailModal({ e, onClose, onFlash }: { e: Exercise; onClose: () => void; onFlash: (m: string, ok?: boolean) => void }) {
  const detail = useApi<ExerciseDetail>(() => api.get<ExerciseDetail>(`/api/exercises/${e.id}`), [e.id]);
  return (
    <LoadBlock loading={detail.loading} error={detail.error}>
      {detail.data && (
        <>
          <div className="kv mb">
            <div className="k">Status</div><div><StBadge value={detail.data.status} /></div>
            <div className="k">Scope (authorized)</div><div>{detail.data.scope}</div>
            <div className="k">Targets</div><div>{detail.data.targets?.join(", ") || "—"}</div>
            <div className="k">Window</div>
            <div className="mono">{fmtTs(detail.data.starts_at)} → {fmtTs(detail.data.ends_at)}</div>
          </div>
          <h2 style={{ fontSize: 13 }}>Run log</h2>
          <table className="tbl">
            <thead>
              <tr><th>Started</th><th>Finished</th><th>Result</th><th>Detail</th></tr>
            </thead>
            <tbody>
              {detail.data.runs.map((r) => (
                <tr key={r.id}>
                  <td className="dim mono">{fmtTs(r.started_at)}</td>
                  <td className="dim mono">{fmtTs(r.finished_at)}</td>
                  <td><StBadge value={r.result} /></td>
                  <td className="dim">{r.detail || "—"}</td>
                </tr>
              ))}
              {!detail.data.runs.length && <tr><td colSpan={4} className="empty">No runs yet.</td></tr>}
            </tbody>
          </table>
          <div className="row mt">
            <StatusAdvance e={detail.data} onDone={() => { detail.reload(); onFlash("Exercise updated"); }} />
          </div>
        </>
      )}
    </LoadBlock>
  );
}

function NewExercise({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [targets, setTargets] = useState("");
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ New exercise</button>
      {open && (
        <Modal title="New exercise" onClose={() => setOpen(false)}>
          <label className="f">Name</label>
          <input value={name} onChange={(ev) => setName(ev.target.value)} autoFocus placeholder="CTF lab weekend" />
          <label className="f">Written, authorized scope (min 20 chars)</label>
          <textarea rows={3} value={scope} onChange={(ev) => setScope(ev.target.value)}
                    placeholder="Authorized synthetic exercise limited to lab-ctf-target-01 only. No production systems." />
          <div className="formrow mt">
            <div>
              <label className="f">Targets (comma-separated)</label>
              <input value={targets} onChange={(ev) => setTargets(ev.target.value)} placeholder="lab-ctf-target-01" style={{ width: 220 }} />
            </div>
            <div>
              <label className="f">Owner</label>
              <input value={owner} onChange={(ev) => setOwner(ev.target.value)} style={{ width: 110 }} />
            </div>
          </div>
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !name}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/exercises", {
                    name,
                    scope,
                    targets: targets.split(",").map((s) => s.trim()).filter(Boolean),
                    owner: owner || undefined,
                  });
                  setOpen(false);
                  onDone();
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Creating…" : "Create (planned)"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
