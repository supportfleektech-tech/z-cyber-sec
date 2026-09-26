import { useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, StBadge, useApi, useFlash } from "../components";

interface Indicator {
  id: number;
  type: string;
  value: string;
  confidence: number | null;
  status: string;
  source_name: string | null;
  mitre_tactics: string[] | null;
  mitre_techniques: string[] | null;
  ttl_hours: number | null;
  expires_at: string | null;
}
interface Source {
  id: number;
  name: string;
  kind: string;
  trust: string | null;
}
interface CorrelateHit {
  event_id: number;
  event_ts: string;
  event_action: string;
  indicator_type: string;
  indicator_value: string;
  confidence: number | null;
}
interface Paged<T> {
  items: T[];
  total: number;
}

export default function Intel() {
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [flash, flashShow] = useFlash();

  const indicators = useApi<Paged<Indicator>>(
    () => api.get<Paged<Indicator>>(`/api/intel/indicators?type=${encodeURIComponent(type)}&q=${encodeURIComponent(q)}&page_size=100`),
    [type, q],
  );
  const sources = useApi<Paged<Source>>(() => api.get<Paged<Source>>("/api/intel/sources"), []);
  const correlate = useApi<{ hits: CorrelateHit[]; truncated: boolean; indicators_checked?: number; events_checked?: number }>(
    () => api.get("/api/intel/indicators/correlate?window_hours=168"),
    [],
  );

  return (
    <>
      <PageHead
        title="Threat Intel"
        sub="STIX 2.1-aligned indicators with confidence, expiry, and cross-correlation against ingested events"
        actions={
          <>
            <StixImport onDone={() => indicators.reload()} />
            <NewIndicator onDone={() => indicators.reload()} />
          </>
        }
      />
      {flash}
      <div className="toolbar">
        <input type="search" placeholder="Filter value…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={type} onChange={(e) => setType(e.target.value)}>
          <option value="">All types</option>
          {["ip", "domain", "url", "hash", "user", "email"].map((t) => <option key={t}>{t}</option>)}
        </select>
      </div>

      <div className="panel">
        <LoadBlock loading={indicators.loading} error={indicators.error} empty={!indicators.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Type</th><th>Value</th><th>Confidence</th><th>Status</th><th>Source</th><th>MITRE</th><th>Expires</th><th></th></tr>
            </thead>
            <tbody>
              {indicators.data!.items.map((i) => (
                <tr key={i.id}>
                  <td className="mono dim">{i.type}</td>
                  <td className="mono">{i.value}</td>
                  <td>{i.confidence ?? "—"}</td>
                  <td>
                    <select
                      defaultValue={i.status}
                      className="small"
                      onChange={async (e) => {
                        try {
                          // SEC-088: only the field being changed. Sending the
                          // whole row used to be the only way to keep it, and
                          // omitting a field silently NULLed it.
                          await api.patch(`/api/intel/indicators/${i.id}`, {
                            status: e.target.value,
                          });
                          flashShow(`Indicator ${i.value} → ${e.target.value}`);
                          indicators.reload();
                        } catch (e) {
                          flashShow((e as Error).message, false);
                        }
                      }}
                    >
                      {["active", "expired", "revoked"].map((s) => <option key={s}>{s}</option>)}
                    </select>
                  </td>
                  <td className="dim">{i.source_name || "—"}</td>
                  <td className="dim">{i.mitre_tactics?.length ? i.mitre_tactics.join(", ") : "—"}</td>
                  <td className="dim">{fmtTs(i.expires_at)}</td>
                  <td className="faint">#{i.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>

      <div className="grid cols-2">
        <div className="panel">
          <h2>Sources</h2>
          <LoadBlock loading={sources.loading} error={sources.error} empty={!sources.data?.items?.length}>
            <table className="tbl">
              <tbody>
                {sources.data!.items.map((s) => (
                  <tr key={s.id}>
                    <td>{s.name}</td>
                    <td className="dim">{s.kind}</td>
                    <td><StBadge value={s.trust} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
        </div>

        <div className="panel">
          <h2>Correlation — indicators observed in recent events</h2>
          <LoadBlock loading={correlate.loading} error={correlate.error} empty={!correlate.data?.hits?.length}>
            {correlate.data && correlate.data.indicators_checked !== undefined && (
              <div className="faint mb">
                {correlate.data.indicators_checked} indicator(s) × {correlate.data.events_checked} event(s)
                {correlate.data.truncated ? " (truncated at 500 hits)" : ""}
              </div>
            )}
            <table className="tbl">
              <thead>
                <tr><th>Indicator</th><th>Type</th><th>Conf.</th><th>Seen in event</th><th>When</th></tr>
              </thead>
              <tbody>
                {correlate.data!.hits.slice(0, 30).map((h, idx) => (
                  <tr key={idx}>
                    <td className="mono">{h.indicator_value}</td>
                    <td className="dim">{h.indicator_type}</td>
                    <td className="dim">{h.confidence ?? "—"}</td>
                    <td className="dim">#{h.event_id} · {h.event_action}</td>
                    <td className="mono dim">{fmtTs(h.event_ts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
        </div>
      </div>
    </>
  );
}

function NewIndicator({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [type, setType] = useState("ip");
  const [value, setValue] = useState("");
  const [confidence, setConfidence] = useState("70");
  const [mitre, setMitre] = useState("");
  const [ttl, setTtl] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button onClick={() => { setErr(null); setOpen(true); }}>+ New indicator</button>
      {open && (
        <Modal title="New indicator" onClose={() => setOpen(false)}>
          <div className="formrow">
            <div>
              <label className="f">Type</label>
              <select value={type} onChange={(e) => setType(e.target.value)}>
                {["ip", "domain", "url", "hash", "user", "email"].map((t) => <option key={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className="f">Confidence (0-100)</label>
              <input value={confidence} onChange={(e) => setConfidence(e.target.value)} style={{ width: 90 }} />
            </div>
            <div>
              <label className="f">MITRE tactics</label>
              <input value={mitre} onChange={(e) => setMitre(e.target.value)} placeholder="T1041, T1110" style={{ width: 120 }} />
            </div>
            <div>
              <label className="f">TTL (hours)</label>
              <input value={ttl} onChange={(e) => setTtl(e.target.value)} placeholder="no expiry" style={{ width: 100 }} />
            </div>
          </div>
          <label className="f">Value</label>
          <input value={value} onChange={(e) => setValue(e.target.value)} autoFocus placeholder="e.g. 198.51.100.23" />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !value}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/intel/indicators", {
                    type,
                    value,
                    confidence: Number(confidence) || undefined,
                    // SEC-089: the API wants a list; this used to send the raw
                    // string and every attempt to save tactics got a 422.
                    mitre_tactics: mitre.split(",").map((t) => t.trim()).filter(Boolean),
                    ttl_hours: Number(ttl) > 0 ? Number(ttl) : undefined,
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
              {busy ? "Adding…" : "Add"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

function StixImport({ onDone }: { onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button onClick={() => { setErr(null); setOpen(true); }}>Import STIX bundle</button>
      {open && (
        <Modal title="Import STIX 2.1 bundle (JSON)" onClose={() => setOpen(false)}>
          <label className="f">Bundle JSON</label>
          <textarea rows={10} value={text} onChange={(e) => setText(e.target.value)}
                    placeholder='{"type":"bundle","objects":[{"type":"indicator",...}]}' />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !text}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  const out = await api.post<{ created: number; updated: number }>("/api/intel/indicators/stix", {
                    bundle: JSON.parse(text),
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
              {busy ? "Importing…" : "Import"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
