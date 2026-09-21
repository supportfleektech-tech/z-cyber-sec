import { useRef, useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, StBadge, useApi, useFlash } from "../components";

interface Control {
  id: number;
  framework: string;
  code: string;
  title: string;
  category: string | null;
  owner: string | null;
  status: string;
  next_review: string | null;
}
interface Risk {
  id: number;
  title: string;
  description: string | null;
  likelihood: number;
  impact: number;
  score: number;
  status: string;
  owner: string | null;
  mitigations: string[] | null;
}
interface Paged<T> {
  items: T[];
  total: number;
}

const CONTROL_STATUSES = ["not_started", "in_progress", "met", "gap"];
const RISK_STATUSES = ["open", "mitigating", "accepted", "closed"];

export default function Grc() {
  const [flash, flashShow] = useFlash();
  const [status, setStatus] = useState("");
  const controls = useApi<Paged<Control>>(
    () => api.get<Paged<Control>>(`/api/grc/controls?status=${encodeURIComponent(status)}&page_size=100`),
    [status],
  );
  const risks = useApi<Paged<Risk>>(() => api.get<Paged<Risk>>("/api/grc/risks?page_size=100"), []);

  return (
    <>
      <PageHead
        title="GRC"
        sub="Controls with owners, review dates and evidence; risk register with likelihood × impact scoring"
        actions={
          <>
            <NewRisk onDone={() => risks.reload()} />
            <NewControl onDone={() => controls.reload()} />
          </>
        }
      />
      {flash}

      <div className="panel">
        <h2>Controls</h2>
        <div className="toolbar">
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option>
            {CONTROL_STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </div>
        <LoadBlock loading={controls.loading} error={controls.error} empty={!controls.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Code</th><th>Framework</th><th>Control</th><th>Owner</th><th>Status</th><th>Next review</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {controls.data!.items.map((c) => (
                <tr key={c.id}>
                  <td className="mono dim">{c.code}</td>
                  <td className="dim">{c.framework}</td>
                  <td>{c.title}</td>
                  <td className="dim">{c.owner || "—"}</td>
                  <td>
                    <select
                      defaultValue={c.status}
                      className="small"
                      onChange={async (e) => {
                        try {
                          await api.patch(`/api/grc/controls/${c.id}`, { status: e.target.value });
                          flashShow(`${c.code} → ${e.target.value}`);
                          controls.reload();
                        } catch (e) {
                          flashShow((e as Error).message, false);
                        }
                      }}
                    >
                      {CONTROL_STATUSES.map((s) => <option key={s}>{s}</option>)}
                    </select>
                  </td>
                  <td className="dim">{c.next_review || "—"}</td>
                  <td><ControlEvidence c={c} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      <div className="panel">
        <h2>Risk register</h2>
        <LoadBlock loading={risks.loading} error={risks.error} empty={!risks.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Risk</th><th>Score</th><th>L×I</th><th>Status</th><th>Owner</th><th>Mitigations</th></tr>
            </thead>
            <tbody>
              {risks.data!.items.map((r) => (
                <tr key={r.id}>
                  <td>{r.title}<div className="faint">{r.description || ""}</div></td>
                  <td>
                    <StBadge
                      value={
                        r.score >= 15 ? "critical" : r.score >= 8 ? "high" : r.score >= 4 ? "medium" : "low"
                      }
                    />{" "}
                    {r.score}
                  </td>
                  <td className="dim">{r.likelihood}×{r.impact}</td>
                  <td>
                    <select
                      defaultValue={r.status}
                      className="small"
                      onChange={async (e) => {
                        try {
                          await api.patch(`/api/grc/risks/${r.id}`, { status: e.target.value });
                          flashShow(`Risk → ${e.target.value}`);
                          risks.reload();
                        } catch (e) {
                          flashShow((e as Error).message, false);
                        }
                      }}
                    >
                      {RISK_STATUSES.map((s) => <option key={s}>{s}</option>)}
                    </select>
                  </td>
                  <td className="dim">{r.owner || "—"}</td>
                  <td className="dim">{r.mitigations?.join("; ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>
    </>
  );
}

function ControlEvidence({ c }: { c: Control }) {
  const ev = useApi<{ items: { id: number; name: string; sha256: string; created_at: string }[] }>(
    () => api.get(`/api/grc/controls/${c.id}/evidence`),
    [c.id],
  );
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="row">
      <input ref={fileRef} type="file" style={{ display: "none" }} />
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
            await api.post(`/api/grc/controls/${c.id}/evidence`, fd);
            ev.reload();
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Uploading…" : `Attach (${ev.data?.items.length || 0})`}
      </button>
      {ev.data?.items.slice(0, 3).map((e) => (
        <span key={e.id} className="faint" title={`${e.sha256}\n${fmtTs(e.created_at)}`}>{e.name}</span>
      ))}
    </div>
  );
}

function NewRisk({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [desc, setDesc] = useState("");
  const [likelihood, setLikelihood] = useState(3);
  const [impact, setImpact] = useState(3);
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button onClick={() => { setErr(null); setOpen(true); }}>+ New risk</button>
      {open && (
        <Modal title="New risk" onClose={() => setOpen(false)}>
          <label className="f">Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          <label className="f">Description</label>
          <textarea rows={2} value={desc} onChange={(e) => setDesc(e.target.value)} />
          <div className="formrow mt">
            <div>
              <label className="f">Likelihood (1-5)</label>
              <input type="number" min={1} max={5} value={likelihood} onChange={(e) => setLikelihood(Number(e.target.value))} style={{ width: 70 }} />
            </div>
            <div>
              <label className="f">Impact (1-5)</label>
              <input type="number" min={1} max={5} value={impact} onChange={(e) => setImpact(Number(e.target.value))} style={{ width: 70 }} />
            </div>
            <div>
              <label className="f">Owner</label>
              <input value={owner} onChange={(e) => setOwner(e.target.value)} style={{ width: 110 }} />
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
                  await api.post("/api/grc/risks", { title, description: desc || undefined, likelihood, impact, owner: owner || undefined });
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

function NewControl({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [framework, setFramework] = useState("NIST-800-53");
  const [code, setCode] = useState("");
  const [title, setTitle] = useState("");
  const [owner, setOwner] = useState("");
  const [nextReview, setNextReview] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ New control</button>
      {open && (
        <Modal title="New control" onClose={() => setOpen(false)}>
          <div className="formrow">
            <div>
              <label className="f">Framework</label>
              <input value={framework} onChange={(e) => setFramework(e.target.value)} style={{ width: 140 }} />
            </div>
            <div>
              <label className="f">Code</label>
              <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="AC-2" style={{ width: 90 }} />
            </div>
            <div>
              <label className="f">Owner</label>
              <input value={owner} onChange={(e) => setOwner(e.target.value)} style={{ width: 110 }} />
            </div>
            <div>
              <label className="f">Next review (YYYY-MM-DD)</label>
              <input value={nextReview} onChange={(e) => setNextReview(e.target.value)} style={{ width: 130 }} />
            </div>
          </div>
          <label className="f">Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !title || !code}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/grc/controls", {
                    framework,
                    code,
                    title,
                    owner: owner || undefined,
                    next_review: nextReview || undefined,
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
              {busy ? "Creating…" : "Create"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
