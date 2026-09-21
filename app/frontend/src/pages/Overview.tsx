import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, fmtTs } from "../api";
import { LoadBlock, PageHead, Stat, StBadge, useApi } from "../components";

interface Stats {
  env: string;
  uptime_seconds: number;
  events_total: number;
  events_last_24h: number;
  alerts: Record<string, number>;
  cases: Record<string, number>;
  vulns: { total: number; open: number };
  indicators: number;
  posture_open: number;
  controls: Record<string, number>;
  open_approvals: number;
  active_agents: number;
  playbooks: number;
}
interface TrendPoint {
  day: string;
  severity: string;
  c: number;
}
type Services = Record<string, { status: string; [k: string]: unknown }>;
interface Integration {
  id: number;
  name: string;
  kind: string;
  status: string;
  last_run_at: string | null;
  last_status: string | null;
}
interface Task {
  id: number;
  title: string;
  status: string;
  agent_name?: string;
  created_at: string;
}

function hms(s: number) {
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m ${Math.floor(s % 60)}s`;
}

function TrendBars({ days, points }: { days: number; points: TrendPoint[] }) {
  const byDay = useMemo(() => {
    const m = new Map<string, Record<string, number>>();
    for (let i = days; i >= 1; i--) {
      const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      m.set(d, {});
    }
    for (const p of points) {
      const row = m.get(p.day);
      if (row) row[p.severity] = (row[p.severity] || 0) + p.c;
    }
    return [...m.entries()];
  }, [days, points]);
  const max = Math.max(1, ...byDay.map(([, s]) => Object.values(s).reduce((a, b) => a + b, 0)));
  return (
    <div className="bars">
      {byDay.map(([day, s]) => {
        const total = Object.values(s).reduce((a, b) => a + b, 0);
        const cls = s.critical ? "critical" : s.high ? "high" : s.medium ? "medium" : "info";
        return <div key={day} className={`b ${cls}`} style={{ height: `${Math.max(3, (total / max) * 100)}%` }} title={`${day}: ${total} alerts`} />;
      })}
    </div>
  );
}

export default function Overview() {
  const stats = useApi<Stats>(() => api.get<Stats>("/api/overview/stats"), []);
  const trend = useApi<{ days: number; points: TrendPoint[] }>(() => api.get("/api/overview/alert-trend?days=14"), []);
  const services = useApi<Services>(() => api.get<Services>("/api/overview/services"), []);
  const integrations = useApi<{ items: Integration[] }>(() => api.get<{ items: Integration[] }>("/api/overview/integrations"), []);
  const tasks = useApi<{ items: Task[] }>(() => api.get<{ items: Task[] }>("/api/agents/tasks?page_size=6"), []);
  const [fresh] = useState(() => new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC");

  const s = stats.data;
  const casesOpen = s ? Object.entries(s.cases).filter(([k]) => k !== "closed" && k !== "total").reduce((a, [, v]) => a + v, 0) : 0;

  return (
    <>
      <PageHead title="Overview" sub={`Data freshness: ${fresh} · all records are synthetic lab data`} />
      <LoadBlock loading={stats.loading} error={stats.error} empty={!s}>
        <div className="grid cols-4">
          <Stat k="Events" v={s!.events_total} s={`${s!.events_last_24h} in last 24h`} />
          <Stat k="Alerts" v={s!.alerts.total} s={`critical ${s!.alerts.critical ?? 0} · high ${s!.alerts.high ?? 0} · medium ${s!.alerts.medium ?? 0}`} tone={s!.alerts.critical ? "critical" : undefined} />
          <Stat k="Cases open" v={casesOpen} s={`${s!.cases.total} total`} />
          <Stat k="Vulns open" v={s!.vulns.open} s={`${s!.vulns.total} total`} />
          <Stat k="Active indicators" v={s!.indicators} s="threat intel store" />
          <Stat k="Posture open" v={s!.posture_open} s="cloud findings" />
          <Stat k="Controls met" v={s!.controls.met ?? 0} s={`gap ${s!.controls.gap ?? 0} · in progress ${s!.controls.in_progress ?? 0}`} />
          <Stat k="Pending approvals" v={s!.open_approvals} s="agent + playbook actions" tone={s!.open_approvals ? "critical" : undefined} />
        </div>
      </LoadBlock>

      <div className="grid cols-2">
        <div className="panel">
          <h2>Alert trend (14 days)</h2>
          <LoadBlock loading={trend.loading} error={trend.error} empty={!trend.data || !trend.data.points.length}>
            <TrendBars days={trend.data!.days} points={trend.data!.points} />
            <div className="faint mt">
              <span style={{ color: "var(--sev-critical)" }}>■</span> critical&nbsp;
              <span style={{ color: "var(--sev-high)" }}>■</span> high&nbsp;
              <span style={{ color: "var(--sev-medium)" }}>■</span> medium&nbsp;
              <span style={{ color: "var(--sev-info)" }}>■</span> low / info
            </div>
          </LoadBlock>
          <div className="mt">
            <Link to="/soc">View alert queue →</Link>
          </div>
        </div>

        <div className="panel">
          <h2>Service health</h2>
          <LoadBlock loading={services.loading} error={services.error} empty={!services.data}>
            <table className="tbl">
              <tbody>
                {Object.entries(services.data!).map(([name, svc]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td><StBadge value={svc.status} /></td>
                    <td className="dim">
                      {Object.entries(svc)
                        .filter(([k]) => k !== "status")
                        .map(([k, v]) => `${k}: ${v}`)
                        .join(" · ") || ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
        </div>
      </div>

      <div className="panel">
        <h2>Integrations (inbound adapters)</h2>
        <LoadBlock loading={integrations.loading} error={integrations.error} empty={!integrations.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Name</th><th>Kind</th><th>Status</th><th>Last run</th><th>Last result</th></tr>
            </thead>
            <tbody>
              {integrations.data!.items.map((i) => (
                <tr key={i.id}>
                  <td>{i.name}</td>
                  <td className="dim">{i.kind}</td>
                  <td><StBadge value={i.status} /></td>
                  <td className="dim">{fmtTs(i.last_run_at)}</td>
                  <td>{i.last_status ? <StBadge value={i.last_status} /> : <span className="dim">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      <div className="panel">
        <h2>Recent agent tasks</h2>
        <LoadBlock loading={tasks.loading} error={tasks.error} empty={!tasks.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>ID</th><th>Task</th><th>Agent</th><th>Status</th><th>Created</th></tr>
            </thead>
            <tbody>
              {tasks.data!.items.map((t) => (
                <tr key={t.id}>
                  <td className="mono">{t.id}</td>
                  <td>{t.title}</td>
                  <td className="dim">{t.agent_name || "—"}</td>
                  <td><StBadge value={t.status} /></td>
                  <td className="dim">{fmtTs(t.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt">
            <Link to="/agents">Agent center →</Link>
          </div>
        </LoadBlock>
      </div>

      {s && (
        <div className="faint">
          env {s.env} · uptime {hms(s.uptime_seconds)} · active agents {s.active_agents} · active playbooks {s.playbooks}
        </div>
      )}
    </>
  );
}
