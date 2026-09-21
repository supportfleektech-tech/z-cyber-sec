import { useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, StBadge, useApi, useFlash } from "../components";

interface Agent {
  id: number;
  name: string;
  provider: string;
  role: string | null;
  status: string;
  tools: string[];
}
interface Task {
  id: number;
  agent_id: number;
  title: string;
  status: string;
  result: unknown;
  created_at: string;
  agent_name?: string;
}
interface Approval {
  id: number;
  task_id: number;
  action: string;
  status: string;
  requested_by: string;
  created_at: string;
  task_title?: string;
  agent_name?: string;
}
interface Paged<T> {
  items: T[];
  total: number;
}

export default function Agents() {
  const [flash, flashShow] = useFlash();
  const agents = useApi<Paged<Agent>>(() => api.get<Paged<Agent>>("/api/agents"), []);
  const tasks = useApi<Paged<Task>>(() => api.get<Paged<Task>>("/api/agents/tasks?page_size=30"), []);
  const approvals = useApi<Paged<Approval>>(() => api.get<Paged<Approval>>("/api/agents/approvals?status=pending"), []);
  const tools = useApi<{ tools: Record<string, { description: string; read_only: boolean; requires_approval: boolean }> }>(
    () => api.get("/api/agents/tools"),
    [],
  );
  const [selTask, setSelTask] = useState<Task | null>(null);

  return (
    <>
      <PageHead
        title="Agent Center"
        sub="Scoped tool allowlists · consequential actions require human approval · every call audited"
        actions={<NewTask agents={agents.data?.items || []} onDone={() => { tasks.reload(); approvals.reload(); }} />}
      />
      {flash}

      {approvals.data?.items.length ? (
        <div className="panel" style={{ borderColor: "#6e2a38" }}>
          <h2>Pending approvals ({approvals.data.items.length})</h2>
          <table className="tbl">
            <thead>
              <tr><th>Agent</th><th>Task</th><th>Action</th><th>Requested by</th><th>When</th><th>Decision</th></tr>
            </thead>
            <tbody>
              {approvals.data.items.map((a) => (
                <tr key={a.id}>
                  <td>{a.agent_name || `#${a.task_id}`}</td>
                  <td>{a.task_title || `task ${a.task_id}`}</td>
                  <td className="mono">{a.action}</td>
                  <td className="dim">{a.requested_by}</td>
                  <td className="dim">{fmtTs(a.created_at)}</td>
                  <td>
                    <DecideButton a={a} onDone={() => { approvals.reload(); tasks.reload(); }} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="ok-box">No pending approvals.</div>
      )}

      <div className="grid cols-2">
        <div className="panel">
          <h2>Task queue</h2>
          <LoadBlock loading={tasks.loading} error={tasks.error} empty={!tasks.data?.items?.length}>
            <table className="tbl">
              <thead>
                <tr><th>ID</th><th>Task</th><th>Agent</th><th>Status</th><th>Created</th></tr>
              </thead>
              <tbody>
                {tasks.data!.items.map((t) => (
                  <tr key={t.id} style={{ cursor: "pointer" }} onClick={() => setSelTask(t)}>
                    <td className="mono dim">{t.id}</td>
                    <td>{t.title}</td>
                    <td className="dim">{t.agent_name || "—"}</td>
                    <td><StBadge value={t.status} /></td>
                    <td className="dim">{fmtTs(t.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
        </div>

        <div className="panel">
          <h2>Agents & allowlists</h2>
          <LoadBlock loading={agents.loading} error={agents.error} empty={!agents.data?.items?.length}>
            {agents.data!.items.map((a) => (
              <div key={a.id} className="mb">
                <div className="row">
                  <b>{a.name}</b>
                  <StBadge value={a.status} />
                  <span className="faint">provider: {a.provider}</span>
                </div>
                <div className="faint mb" style={{ marginTop: 2 }}>
                  {a.tools.map((t) => (
                    <span key={t} className="badge st" style={{ marginRight: 4 }}>
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </LoadBlock>
          <div className="mt">
            <Evals agents={agents.data?.items || []} onDone={(m) => flashShow(m)} />
          </div>
        </div>
      </div>

      <div className="panel">
        <h2>Tool registry (governance)</h2>
        <LoadBlock loading={tools.loading} error={tools.error} empty={!tools.data}>
          <table className="tbl">
            <thead>
              <tr><th>Tool</th><th>Read-only</th><th>Requires approval</th><th>Description</th></tr>
            </thead>
            <tbody>
              {Object.entries(tools.data!.tools).map(([name, t]) => (
                <tr key={name}>
                  <td className="mono">{name}</td>
                  <td>{t.read_only ? "yes" : "no"}</td>
                  <td>{t.requires_approval ? <span className="st pending">approval</span> : "—"}</td>
                  <td className="dim">{t.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      {selTask && <TaskModal t={selTask} onClose={() => setSelTask(null)} />}
    </>
  );
}

function DecideButton({ a, onDone }: { a: Approval; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [decision, setDecision] = useState<"approve" | "reject">("approve");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="small" onClick={() => { setErr(null); setOpen(true); }}>Decide…</button>
      {open && (
        <Modal title={`Approve: ${a.action}`} onClose={() => setOpen(false)}>
          <div className="note-box">
            Consequential agent action <code>{a.action}</code> requested on task {a.task_id}. Approving executes it once, now,
            and is recorded in the audit log. Rejecting leaves no effect.
          </div>
          <div className="row mt">
            <select value={decision} onChange={(e) => setDecision(e.target.value as "approve" | "reject")}>
              <option value="approve">Approve</option>
              <option value="reject">Reject</option>
            </select>
            <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="comment (optional)" style={{ flex: 1 }} />
          </div>
          {err && <div className="error-box">{err}</div>}
          <div className="foot">
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className={decision === "approve" ? "primary" : "danger"}
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post(`/api/agents/approvals/${a.id}/decide`, { decision, comment: comment || undefined });
                  setOpen(false);
                  onDone();
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Working…" : decision === "approve" ? "Approve & execute" : "Reject"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function TaskModal({ t, onClose }: { t: Task; onClose: () => void }) {
  const detail = useApi<Task & { tool_calls: { tool: string; allowed: number; reason: string | null; result: unknown }[] }>(
    () => api.get(`/api/agents/tasks/${t.id}`),
    [t.id],
  );
  return (
    <Modal title={`Task #${t.id} — ${t.title}`} onClose={onClose}>
      <LoadBlock loading={detail.loading} error={detail.error}>
        {detail.data && (
          <>
            <div className="kv mb">
              <div className="k">Status</div><div><StBadge value={detail.data.status} /></div>
            </div>
            {detail.data.result && (
              <>
                <div className="faint mb">Result (truthful status)</div>
                <pre>{JSON.stringify(detail.data.result, null, 2)}</pre>
              </>
            )}
            <div className="faint mb">Tool calls (audited)</div>
            <table className="tbl">
              <tbody>
                {detail.data.tool_calls.map((c, i) => (
                  <tr key={i}>
                    <td className="mono">{c.tool}</td>
                    <td>{c.allowed ? <span className="st met">allowed</span> : <span className="st denied">denied</span>}</td>
                    <td className="dim">{c.reason || ""}</td>
                  </tr>
                ))}
                {!detail.data.tool_calls.length && <tr><td className="empty">No tool calls recorded.</td></tr>}
              </tbody>
            </table>
          </>
        )}
      </LoadBlock>
    </Modal>
  );
}

function NewTask({ agents, onDone }: { agents: Agent[]; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [agentId, setAgentId] = useState("");
  const [title, setTitle] = useState("");
  const [tool, setTool] = useState("summarize_alerts");
  const [argsText, setArgsText] = useState("{}");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const agent = agents.find((a) => a.id === Number(agentId));
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ New agent task</button>
      {open && (
        <Modal title="New agent task" onClose={() => setOpen(false)}>
          <div className="note-box">
            Requests may contain untrusted content — execution is always policy-checked against the agent's allowlist.
            Consequential tools queue for human approval instead of executing.
          </div>
          <div className="formrow mt">
            <div>
              <label className="f">Agent</label>
              <select
                value={agentId}
                onChange={(e) => {
                  setAgentId(e.target.value);
                  const a = agents.find((x) => x.id === Number(e.target.value));
                  if (a?.tools.length) setTool(a.tools[0]);
                }}
                style={{ width: 200 }}
              >
                <option value="">—</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>{a.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="f">Tool</label>
              <select value={tool} onChange={(e) => setTool(e.target.value)} style={{ width: 200 }}>
                {(agent?.tools || ["summarize_alerts"]).map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>
          <label className="f">Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus />
          <label className="f">Args (JSON)</label>
          <textarea rows={3} value={argsText} onChange={(e) => setArgsText(e.target.value)} />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !title || !agentId}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  const out = await api.post<Task>("/api/agents/tasks", {
                    agent_id: Number(agentId),
                    title,
                    request: { tool, args: JSON.parse(argsText || "{}") },
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
              {busy ? "Submitting…" : "Submit task"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function Evals({ agents, onDone }: { agents: Agent[]; onDone: (m: string) => void }) {
  const [agentId, setAgentId] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <div className="row">
      <select value={agentId} onChange={(e) => setAgentId(e.target.value)} style={{ width: 190 }}>
        <option value="">Eval agent…</option>
        {agents.map((a) => (
          <option key={a.id} value={a.id}>{a.name}</option>
        ))}
      </select>
      <button
        className="small"
        disabled={busy || !agentId}
        onClick={async () => {
          setBusy(true);
          try {
            const out = await api.post<{ passed: number; total: number }>(
              "/api/agents/evals/run",
              { agent_id: Number(agentId) },
            );
            onDone(`Governance evals: ${out.passed}/${out.total} passed`);
          } catch (e) {
            onDone(`Evals failed: ${(e as Error).message}`);
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? "Running…" : "Run governance evals"}
      </button>
    </div>
  );
}
