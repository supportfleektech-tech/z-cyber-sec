import { useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, PageHead, StBadge, useApi, useFlash } from "../components";

/**
 * Tradecraft (SEC-075) — the The-Xploiter workspace.
 *
 * The page is built around the two questions a finding list cannot answer:
 * "is this actually exploitable?" and "can these issues be chained?". The
 * scope panel is deliberately the first thing on the page: every action here
 * is bounded by an authorized engagement, and the UI should never imply
 * otherwise.
 */

interface Persona {
  codename: string;
  role: string;
  summary: string;
  focus_areas: string[];
  design_principles: { principle: string; means: string }[];
  use_cases: string[];
  guardrails: string[];
  certification_mapping: { cert: string; focus: string }[];
}
interface ScopeSummary {
  authorized: {
    exercise_id: number; exercise: string; status: string; owner: string | null;
    target: string; usable: boolean;
    starts_at: string | null; ends_at: string | null; window_state: string;
  }[];
  ignored_entries: { exercise_id: number; exercise: string; target: string; note: string | null; window_state?: string }[];
  expired_engagements: [number, string, string][];
  deny_by_default: boolean;
  rule: string;
}
interface Review {
  id: number;
  vuln_id: number | null;
  target: string | null;
  verdict: string;
  trust_boundary: string | null;
  impact_before: string | null;
  impact_after: string | null;
  triage_ready: number;
  policy_note: string | null;
  rationale: string;
  created_at: string;
  reviewed_by: string;
}
interface Chain {
  id: number;
  title: string;
  entry_point: string;
  trust_boundary: string | null;
  steps: { order?: number; action: string; impact: string; target?: string }[];
  combined_impact: string;
  status: string;
  rationale: string | null;
  escalation_note: string | null;
  created_by: string;
  created_at: string;
}
interface Paged<T> { items: T[]; total: number }
interface DuplicateCluster {
  dedupe_key: string;
  count: number;
  reviews: { id: number; vuln_id: number | null; target: string | null; verdict: string; triage_ready: number; created_at: string }[];
}
interface Stats {
  reviews: number;
  reviews_triage_ready: number;
  by_verdict: Record<string, number>;
  chains: number;
  chains_validated: number;
  authorized_targets: number;
  rejected_as_theoretical: number;
}

const VERDICT_TONE: Record<string, string> = {
  exploitable: "closed",
  not_exploitable: "confirmed",
  needs_evidence: "open",
  theoretical: "denied",
};

export default function Tradecraft() {
  const [flash, flashShow] = useFlash();
  const persona = useApi<Persona>(() => api.get<Persona>("/api/tradecraft/persona"), []);
  const scope = useApi<ScopeSummary>(() => api.get<ScopeSummary>("/api/tradecraft/scope"), []);
  const stats = useApi<Stats>(() => api.get<Stats>("/api/tradecraft/stats"), []);
  const reviews = useApi<Paged<Review>>(() => api.get<Paged<Review>>("/api/tradecraft/reviews?limit=50"), []);
  const chains = useApi<Paged<Chain>>(() => api.get<Paged<Chain>>("/api/tradecraft/chains"), []);
  const dupes = useApi<{ clusters: DuplicateCluster[] }>(
    () => api.get<{ clusters: DuplicateCluster[] }>("/api/tradecraft/duplicates"), []);
  const [report, setReport] = useState<{ vuln_id: number; markdown: string; reportable: boolean } | null>(null);

  const reloadAll = () => { reviews.reload(); chains.reload(); stats.reload(); scope.reload(); };

  return (
    <>
      <PageHead
        title="Tradecraft — The-Xploiter"
        sub="Adversary reasoning on authorized engagements: exploitability validation, attack chains, triage-ready reports"
      />
      {flash}

      <div className="note-box">
        <strong>Scope guard:</strong> {scope.data?.rule ?? "loading…"} Over-broad entries
        (0.0.0.0/0, *, any) authorize nothing. Attempts against un-authorized targets are
        refused and written to the audit log as <code>tradecraft.out_of_scope</code>. The
        platform ships no exploit payloads and no scanning engine — this is the reasoning,
        validation and reporting layer.
      </div>

      <div className="grid cols-3 mb">
        <div className="stat"><div className="k">authorized targets</div>
          <div className="v">{stats.data?.authorized_targets ?? "—"}</div>
          <div className="s">in-force authorization windows</div></div>
        <div className="stat"><div className="k">reviews</div>
          <div className="v">{stats.data?.reviews ?? "—"}</div>
          <div className="s">{stats.data?.reviews_triage_ready ?? 0} triage-ready</div></div>
        <div className="stat"><div className="k">chains</div>
          <div className="v">{stats.data?.chains ?? "—"}</div>
          <div className="s">{stats.data?.chains_validated ?? 0} validated</div></div>
      </div>

      {stats.data && stats.data.rejected_as_theoretical > 0 && (
        <div className="faint mb">
          {stats.data.rejected_as_theoretical} theoretical finding(s) recorded as rejected —
          kept so they are not re-tested, never reportable.
        </div>
      )}

      <div className="grid cols-2">
        <div className="panel">
          <h2>Persona</h2>
          <LoadBlock loading={persona.loading} error={persona.error}>
            {persona.data && (
              <>
                <p className="dim">{persona.data.summary}</p>
                <h3 style={{ marginBottom: 4 }}>Focus areas</h3>
                <ul style={{ margin: "0 0 10px 16px" }}>
                  {persona.data.focus_areas.map((f) => <li key={f}>{f}</li>)}
                </ul>
                <h3 style={{ marginBottom: 4 }}>Design principles</h3>
                <table className="tbl">
                  <tbody>
                    {persona.data.design_principles.map((p) => (
                      <tr key={p.principle}>
                        <td style={{ whiteSpace: "nowrap" }}>{p.principle}</td>
                        <td className="dim">{p.means}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <h3 style={{ margin: "10px 0 4px" }}>Use cases</h3>
                <ul style={{ margin: "0 0 10px 16px" }}>
                  {persona.data.use_cases.map((u) => <li key={u}>{u}</li>)}
                </ul>
                <div className="faint">
                  Certifications: {persona.data.certification_mapping.map((c) => c.cert).join(" · ")}
                </div>
              </>
            )}
          </LoadBlock>
        </div>

        <div className="panel">
          <h2>Authorized scope</h2>
          <LoadBlock loading={scope.loading} error={scope.error} empty={!scope.data?.authorized?.length}>
            <table className="tbl">
              <thead><tr><th>Target</th><th>Engagement</th><th>Status</th><th>Authority</th><th>Owner</th></tr></thead>
              <tbody>
                {scope.data!.authorized.map((t) => (
                  <tr key={`${t.exercise_id}-${t.target}`}>
                    <td className="mono">{t.target}</td>
                    <td>{t.exercise}</td>
                    <td><StBadge value={t.status} /></td>
                    <td className="dim">
                      {t.window_state === "open" ? "open-ended"
                        : t.ends_at ? `until ${String(t.ends_at).slice(0, 10)}` : "—"}
                    </td>
                    <td className="dim">{t.owner || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
          {scope.data && scope.data.authorized.length === 0 && (
            <div className={scope.data.expired_engagements.length ? "inert-warn" : "faint"}>
              No engagement currently authorizes work.{" "}
              {scope.data.expired_engagements.length > 0 ? (
                <>
                  {scope.data.expired_engagements.map(([id, name, note]) => (
                    <div key={id} className="faint">
                      #{id} “{name}”: {note}
                    </div>
                  ))}
                  Extend the window on the Exercises page — an authorization that has lapsed is
                  not an authorization, so reviews and chains against it are refused.
                </>
              ) : (
                <>
                  Create an exercise and move it to <code>authorized</code> on the Exercises page
                  before recording tradecraft work.
                </>
              )}
            </div>
          )}
          {scope.data && scope.data.ignored_entries.length > 0 && (
            <div className="inert-warn" style={{ marginTop: 10 }}>
              {scope.data.ignored_entries.length} scope entr(y/ies) ignored as over-broad or invalid:{" "}
              {scope.data.ignored_entries.map((e) => e.target).join(", ")}
            </div>
          )}
        </div>
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <h2>Exploitability reviews</h2>
          <ReviewForm onDone={(msg) => { flashShow(msg); reloadAll(); }} />
          <LoadBlock loading={reviews.loading} error={reviews.error} empty={!reviews.data?.items?.length}>
            <table className="tbl">
              <thead>
                <tr><th>Finding</th><th>Target</th><th>Verdict</th><th>Impact</th><th>Reportable</th><th></th></tr>
              </thead>
              <tbody>
                {reviews.data!.items.map((r) => (
                  <tr key={r.id}>
                    <td className="mono dim">{r.vuln_id ? `#${r.vuln_id}` : "—"}</td>
                    <td className="mono">{r.target || "—"}</td>
                    <td><StBadge value={r.verdict} /></td>
                    <td className="dim">{r.impact_before || "—"} → {r.impact_after || "—"}</td>
                    <td>{r.triage_ready ? <span className="st closed">yes</span> : <span className="st open">no</span>}</td>
                    <td>{r.vuln_id && (
                      <button className="btn ghost sm" onClick={() =>
                        api.get<{ markdown: string; reportable: boolean; vuln_id: number }>(
                          `/api/tradecraft/findings/${r.vuln_id}/triage-report`)
                          .then((d) => setReport(d))
                          .catch((e) => flashShow(String(e.message || e)))}>report</button>
                    )}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
          <div className="faint" style={{ marginTop: 8 }}>
            {reviews.data?.items?.length
              ? `Verdicts: ${Object.entries(stats.data?.by_verdict || {}).map(([k, v]) => `${k} ${v}`).join(" · ")}`
              : ""}
          </div>
        </div>

        <div className="panel">
          <h2>Attack chains</h2>
          <LoadBlock loading={chains.loading} error={chains.error} empty={!chains.data?.items?.length}>
            <table className="tbl">
              <tbody>
                {chains.data!.items.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <div>{c.title}</div>
                      <div className="faint">entry: {c.entry_point}</div>
                      <ol style={{ margin: "4px 0 0 16px" }} className="faint">
                        {c.steps.map((s, i) => (
                          <li key={i}>{s.action} <span className="mono">[{s.impact}]</span></li>
                        ))}
                      </ol>
                      {c.escalation_note && (
                        <div className="faint" style={{ marginTop: 4 }}>why it compounds: {c.escalation_note}</div>
                      )}
                    </td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      <StBadge value={c.status} />
                      <div className="faint mono">{c.combined_impact}</div>
                    </td>
                    <td>
                      {c.status === "draft" && (
                        <button className="btn ghost sm" onClick={() =>
                          api.post(`/api/tradecraft/chains/${c.id}/status`,
                            { status: "validated", rationale: "Reproduced end to end on the authorized range." })
                            .then(() => { flashShow(`Chain #${c.id} validated`); reloadAll(); })
                            .catch((e) => flashShow(String(e.message || e)))}>validate</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
          <ChainForm onDone={(msg) => { flashShow(msg); reloadAll(); }} />
        </div>
      </div>

      <div className="panel">
        <h2>
          Engagement deliverable
          <button className="btn ghost sm" style={{ float: "right" }} onClick={() =>
            api.post<{ id: number }>("/api/reports", { kind: "tradecraft", filters: {} })
              .then((d) => { flashShow(`Report #${d.id} generated`); window.location.hash = `#/reports`; })
              .catch((e) => flashShow(String(e.message || e)))}>
            generate report
          </button>
        </h2>
        <div className="faint">
          Renders the engagement deliverable: findings that met the evidence standard, attack
          chains as paths, and the rejected/disproven verdicts (so the record shows what was
          ruled out, not only what was reported). Every generated file is hashed and audited.
        </div>
      </div>

      <div className="panel">
        <h2>Duplicate clusters</h2>
        <LoadBlock loading={dupes.loading} error={dupes.error}>
          {dupes.data && dupes.data.clusters.length === 0 ? (
            <div className="faint">
              No duplicate submissions — every recorded review has a distinct
              target/weakness fingerprint. Identical submissions cluster here instead of
              being reviewed twice (bug bounty signal-to-noise).
            </div>
          ) : (
            <table className="tbl">
              <thead><tr><th>Fingerprint</th><th>Submissions</th><th>Targets</th><th>Verdicts</th></tr></thead>
              <tbody>
                {dupes.data?.clusters.map((c) => (
                  <tr key={c.dedupe_key}>
                    <td className="mono dim">{c.dedupe_key}</td>
                    <td>{c.count}</td>
                    <td className="mono">{[...new Set(c.reviews.map((r) => r.target || "—"))].join(", ")}</td>
                    <td>{[...new Set(c.reviews.map((r) => r.verdict))].map((v) => (
                      <span key={v} className={`st ${VERDICT_TONE[v] || ""}`}>{v}</span>
                    ))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </LoadBlock>
      </div>

      {report && (
        <div className="panel">
          <h2>
            Triage report — finding #{report.vuln_id}{" "}
            {report.reportable ? <span className="st closed">ready</span> : <span className="st open">not submittable</span>}
            <button className="btn ghost sm" style={{ float: "right" }}
              onClick={() => { navigator.clipboard?.writeText(report.markdown); flashShow("Copied report markdown"); }}>
              copy
            </button>
          </h2>
          <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>{report.markdown}</pre>
        </div>
      )}
    </>
  );
}

function ReviewForm({ onDone }: { onDone: (msg: string) => void }) {
  const [open, setOpen] = useState(false);
  const [vulnId, setVulnId] = useState("");
  const [target, setTarget] = useState("");
  const [verdict, setVerdict] = useState("exploitable");
  const [boundary, setBoundary] = useState("user->admin");
  const [impactBefore, setImpactBefore] = useState("low");
  const [impactAfter, setImpactAfter] = useState("high");
  const [evidence, setEvidence] = useState("");
  const [repro, setRepro] = useState("");
  const [rationale, setRationale] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      await api.post("/api/tradecraft/reviews", {
        vuln_id: vulnId ? Number(vulnId) : null,
        target: target || null,
        verdict, trust_boundary: boundary,
        impact_before: impactBefore, impact_after: impactAfter,
        evidence: evidence.split("\n").map((s) => s.trim()).filter(Boolean),
        reproduction: repro || null,
        rationale,
      });
      setOpen(false);
      setEvidence(""); setRepro(""); setRationale("");
      onDone("Review recorded (audited)");
    } catch (e) {
      setErr(String((e as Error).message || e));
    } finally { setBusy(false); }
  };

  if (!open) {
    return <button className="btn" onClick={() => setOpen(true)} style={{ marginBottom: 8 }}>
      Record exploitability review
    </button>;
  }
  return (
    <div className="note-box" style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 6 }}>
        <input value={vulnId} onChange={(e) => setVulnId(e.target.value)} placeholder="finding id" style={{ width: 90 }} />
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="in-scope target (e.g. 10.42.0.10)" style={{ width: 240 }} />
        <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
          <option value="exploitable">exploitable</option>
          <option value="needs_evidence">needs_evidence</option>
          <option value="not_exploitable">not_exploitable</option>
          <option value="theoretical">theoretical</option>
        </select>
        <select value={boundary} onChange={(e) => setBoundary(e.target.value)}>
          {["unauthenticated->authenticated", "user->admin", "tenant->tenant", "edge->internal",
            "container->host", "workstation->domain", "cloud-identity->resource", "other"]
            .map((b) => <option key={b} value={b}>{b}</option>)}
        </select>
      </div>
      <div style={{ display: "flex", gap: 8, marginBottom: 6 }}>
        <select value={impactBefore} onChange={(e) => setImpactBefore(e.target.value)}>
          {["info", "low", "medium", "high", "critical"].map((i) => <option key={i} value={i}>before: {i}</option>)}
        </select>
        <select value={impactAfter} onChange={(e) => setImpactAfter(e.target.value)}>
          {["info", "low", "medium", "high", "critical"].map((i) => <option key={i} value={i}>after: {i}</option>)}
        </select>
      </div>
      <textarea value={evidence} onChange={(e) => setEvidence(e.target.value)} rows={2}
        placeholder="evidence — one artifact per line (observed output, request/response, artifact ref)"
        style={{ width: "100%", marginBottom: 6 }} />
      <textarea value={repro} onChange={(e) => setRepro(e.target.value)} rows={2}
        placeholder="reproduction steps another engineer can follow" style={{ width: "100%", marginBottom: 6 }} />
      <textarea value={rationale} onChange={(e) => setRationale(e.target.value)} rows={3}
        placeholder="WHY it works — the mechanism (required, min 20 chars). 'vulnerable' is not a rationale."
        style={{ width: "100%", marginBottom: 6 }} />
      {err && <div className="inert-warn">{err}</div>}
      <button className="btn" disabled={busy} onClick={submit}>{busy ? "saving…" : "Submit (audited)"}</button>{" "}
      <button className="btn ghost" onClick={() => setOpen(false)}>Cancel</button>
      <div className="faint" style={{ marginTop: 4 }}>
        An <code>exploitable</code> verdict requires evidence + reproduction + impact and an
        in-scope target; <code>theoretical</code> is recorded as rejected, never reportable.
      </div>
    </div>
  );
}

function ChainForm({ onDone }: { onDone: (msg: string) => void }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [entry, setEntry] = useState("");
  const [raw, setRaw] = useState('[\n  {"action": "abuse mass assignment to become local admin", "impact": "medium"},\n  {"action": "read cached credentials from the host", "impact": "high"}\n]');
  const [escalation, setEscalation] = useState("");
  const [rationale, setRationale] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true); setErr(null);
    try {
      const steps = JSON.parse(raw);
      const impacts = ["info", "low", "medium", "high", "critical"];
      const combined = steps.map((s: { impact: string }) => s.impact)
        .sort((a: string, b: string) => impacts.indexOf(b) - impacts.indexOf(a))[0] || "low";
      await api.post("/api/tradecraft/chains", {
        title, entry_point: entry, steps, combined_impact: combined,
        escalation_note: escalation || null, rationale,
      });
      setOpen(false); setTitle(""); setEntry(""); setRationale(""); setEscalation("");
      onDone("Chain recorded (audited)");
    } catch (e) {
      setErr(String((e as Error).message || e));
    } finally { setBusy(false); }
  };

  if (!open) {
    return <button className="btn ghost" onClick={() => setOpen(true)} style={{ marginTop: 8 }}>
      Record attack chain
    </button>;
  }
  return (
    <div className="note-box" style={{ marginTop: 10 }}>
      <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="chain title"
        style={{ width: "100%", marginBottom: 6 }} />
      <input value={entry} onChange={(e) => setEntry(e.target.value)}
        placeholder="entry point (e.g. authenticated low-priv account on lab-web-01)"
        style={{ width: "100%", marginBottom: 6 }} />
      <textarea value={raw} onChange={(e) => setRaw(e.target.value)} rows={5} style={{ width: "100%", marginBottom: 6 }} />
      <input value={escalation} onChange={(e) => setEscalation(e.target.value)}
        placeholder="why it compounds (required if impacts do not escalate)"
        style={{ width: "100%", marginBottom: 6 }} />
      <textarea value={rationale} onChange={(e) => setRationale(e.target.value)} rows={2}
        placeholder="rationale — why the chain works end to end" style={{ width: "100%", marginBottom: 6 }} />
      {err && <div className="inert-warn">{err}</div>}
      <button className="btn" disabled={busy} onClick={submit}>{busy ? "saving…" : "Submit (audited)"}</button>{" "}
      <button className="btn ghost" onClick={() => setOpen(false)}>Cancel</button>
      <div className="faint" style={{ marginTop: 4 }}>
        A chain needs ≥2 steps and must raise impact above its entry point — otherwise it is a
        finding list, not a chain.
      </div>
    </div>
  );
}
