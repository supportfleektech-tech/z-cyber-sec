import { useState } from "react";
import { api, fmtTs } from "../api";
import { ConfirmButton, LoadBlock, PageHead, StBadge, useApi, useFlash } from "../components";

interface Playbook {
  id: number;
  name: string;
  description: string | null;
  trigger: string;
  status: string;
  steps: { tool: string; args: Record<string, unknown> }[];
}
interface Run {
  id: number;
  playbook_id: number;
  trigger: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  result: { plan?: { status?: string; reasons?: string[] }; executed?: boolean; errors?: string[]; [k: string]: unknown } | null;
}
interface Paged<T> {
  items: T[];
  total: number;
}

export default function Automation() {
  const [flash, flashShow] = useFlash();
  const playbooks = useApi<Paged<Playbook>>(() => api.get<Paged<Playbook>>("/api/automation"), []);
  const runs = useApi<Paged<Run>>(() => api.get<Paged<Run>>("/api/automation/runs?page_size=30"), []);

  return (
    <>
      <PageHead
        title="Automation"
        sub="Playbooks reuse the agent policy engine: read-only steps execute, consequential steps queue for approval"
      />
      {flash}

      <div className="panel">
        <h2>Playbooks</h2>
        <LoadBlock loading={playbooks.loading} error={playbooks.error} empty={!playbooks.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Playbook</th><th>Trigger</th><th>Status</th><th>Steps</th><th></th></tr>
            </thead>
            <tbody>
              {playbooks.data!.items.map((p) => (
                <tr key={p.id}>
                  <td>
                    {p.name}
                    <div className="faint">{p.description || ""}</div>
                  </td>
                  <td className="mono dim">{p.trigger}</td>
                  <td><StBadge value={p.status} /></td>
                  <td className="dim">
                    {p.steps.map((s, i) => (
                      <span key={i} className="badge st" style={{ marginRight: 4 }}>{s.tool}</span>
                    ))}
                  </td>
                  <td>
                    <span className="row">
                      <button
                        className="small"
                        onClick={async () => {
                          try {
                            const out = await api.post(`/api/automation/${p.id}/run`, { dry_run: true });
                            flashShow(
                              `Dry run ${p.name}: plan=${(out as { plan?: { status?: string } }).plan?.status ?? "?"} (nothing executed)`,
                            );
                            runs.reload();
                          } catch (e) {
                            flashShow((e as Error).message, false);
                          }
                        }}
                      >
                        Dry run
                      </button>
                      <ConfirmButton
                        label="Run"
                        confirmLabel={`Execute playbook "${p.name}"?`}
                        impact="Read-only steps execute immediately. Consequential steps pause for human approval instead of running."
                        onConfirm={async () => {
                          const out = await api.post(`/api/automation/${p.id}/run`, {});
                          const o = out as { status?: string };
                          flashShow(`Run ${p.name}: ${o.status || "started"}`);
                          runs.reload();
                        }}
                      />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      <div className="panel">
        <h2>Execution history</h2>
        <LoadBlock loading={runs.loading} error={runs.error} empty={!runs.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>ID</th><th>Playbook</th><th>Trigger</th><th>Status</th><th>Started</th><th>Result</th><th></th></tr>
            </thead>
            <tbody>
              {runs.data!.items.map((r) => (
                <tr key={r.id}>
                  <td className="mono dim">{r.id}</td>
                  <td className="dim">#{r.playbook_id}</td>
                  <td className="mono dim">{r.trigger}</td>
                  <td><StBadge value={r.status} /></td>
                  <td className="dim">{fmtTs(r.started_at)}</td>
                  <td className="dim" style={{ maxWidth: 380 }}>
                    {r.result
                      ? r.result.errors?.length
                        ? `errors: ${r.result.errors.slice(0, 2).join("; ")}`
                        : r.result.executed === false
                          ? "dry-run — nothing executed"
                          : r.result.awaiting_approval
                            ? "awaiting human approval"
                            : `plan: ${r.result.plan?.status || "ok"}`
                      : "—"}
                  </td>
                  <td>
                    {/* SEC-096: alert-triggered runs used to sit `pending` forever
                        with no way to act on them. auto_run playbooks run
                        themselves; the rest are suggestions an operator starts. */}
                    {r.status === "pending" && r.result == null ? (
                      <button
                        className="small"
                        onClick={async () => {
                          try {
                            const out = await api.post<{ status: string }>(`/api/automation/runs/${r.id}/execute`, {});
                            flashShow(`Run ${r.id} → ${out.status}`);
                            runs.reload();
                          } catch (e) {
                            flashShow((e as Error).message, false);
                          }
                        }}
                      >
                        Run
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>
    </>
  );
}
