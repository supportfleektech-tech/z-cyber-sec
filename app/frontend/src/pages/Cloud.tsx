import { useState } from "react";
import { api, fmtTs } from "../api";
import { LoadBlock, Modal, PageHead, SevBadge, StBadge, useApi, useFlash } from "../components";

interface CloudAsset {
  id: number;
  provider: string;
  account: string | null;
  region: string | null;
  type: string;
  name: string;
  status: string;
}
interface Posture {
  id: number;
  asset_id: number;
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  detail: string | null;
  checked_at: string;
  asset_name: string | null;
  provider: string | null;
}
interface Asset {
  id: number;
  name: string;
  kind: string;
  owner: string | null;
  status: string;
}
interface Paged<T> {
  items: T[];
  total: number;
}

const POSTURE_STATUSES = ["open", "remediating", "accepted", "resolved"];

export default function Cloud() {
  const [flash, flashShow] = useFlash();
  const assets = useApi<Paged<CloudAsset>>(() => api.get<Paged<CloudAsset>>("/api/cloud/assets"), []);
  const posture = useApi<Paged<Posture>>(() => api.get<Paged<Posture>>("/api/cloud/posture"), []);
  const inventory = useApi<Paged<Asset>>(() => api.get<Paged<Asset>>("/api/assets?page_size=100"), []);

  return (
    <>
      <PageHead
        title="Network / Cloud"
        sub="Cloud assets, posture findings, and the asset inventory"
        actions={<NewPosture assets={assets.data?.items || []} onDone={() => posture.reload()} />}
      />
      {flash}

      <div className="grid cols-2">
        <div className="panel">
          <h2>Cloud assets</h2>
          <LoadBlock loading={assets.loading} error={assets.error} empty={!assets.data?.items?.length}>
            <table className="tbl">
              <thead>
                <tr><th>Name</th><th>Provider</th><th>Type</th><th>Region</th><th>Account</th><th>Status</th></tr>
              </thead>
              <tbody>
                {assets.data!.items.map((a) => (
                  <tr key={a.id}>
                    <td>{a.name}</td>
                    <td className="dim">{a.provider}</td>
                    <td className="dim">{a.type}</td>
                    <td className="dim">{a.region || "—"}</td>
                    <td className="dim">{a.account || "—"}</td>
                    <td><StBadge value={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
        </div>

        <div className="panel">
          <h2>Posture findings</h2>
          <LoadBlock loading={posture.loading} error={posture.error} empty={!posture.data?.items?.length}>
            <table className="tbl">
              <thead>
                <tr><th>Finding</th><th>Rule</th><th>Asset</th><th>Severity</th><th>Status</th><th>Checked</th></tr>
              </thead>
              <tbody>
                {posture.data!.items.map((p) => (
                  <tr key={p.id}>
                    <td>{p.title}</td>
                    <td className="mono dim">{p.rule_id}</td>
                    <td className="dim">{p.asset_name || "—"}</td>
                    <td><SevBadge value={p.severity} /></td>
                    <td>
                      <select
                        defaultValue={p.status}
                        className="small"
                        onChange={async (e) => {
                          try {
                            // SEC-090: only the field being changed — the full
                            // body used to be echoed back, and omitting `detail`
                            // (as this payload did) wiped the finding's evidence.
                            await api.patch(`/api/cloud/posture/${p.id}`, {
                              status: e.target.value,
                            });
                            flashShow(`Posture ${p.rule_id} → ${e.target.value}`);
                            posture.reload();
                          } catch (e) {
                            flashShow((e as Error).message, false);
                          }
                        }}
                      >
                        {POSTURE_STATUSES.map((s) => <option key={s}>{s}</option>)}
                      </select>
                    </td>
                    <td className="dim">{fmtTs(p.checked_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </LoadBlock>
        </div>
      </div>

      <div className="panel">
        <h2>Asset inventory</h2>
        <LoadBlock loading={inventory.loading} error={inventory.error} empty={!inventory.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Name</th><th>Kind</th><th>Owner</th><th>Status</th></tr>
            </thead>
            <tbody>
              {inventory.data!.items.map((a) => (
                <tr key={a.id}>
                  <td>{a.name}</td>
                  <td className="dim">{a.kind}</td>
                  <td className="dim">{a.owner || "—"}</td>
                  <td><StBadge value={a.status} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
      </div>
    </>
  );
}

function NewPosture({ assets, onDone }: { assets: CloudAsset[]; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [assetId, setAssetId] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [detail, setDetail] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ Posture finding</button>
      {open && (
        <Modal title="New posture finding" onClose={() => setOpen(false)}>
          <div className="formrow">
            <div>
              <label className="f">Cloud asset</label>
              <select value={assetId} onChange={(e) => setAssetId(e.target.value)} style={{ width: 200 }}>
                <option value="">—</option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>{a.name} ({a.provider})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="f">Rule id</label>
              <input value={ruleId} onChange={(e) => setRuleId(e.target.value)} placeholder="public-bucket" style={{ width: 150 }} />
            </div>
            <div>
              <label className="f">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
                {["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <label className="f">Title</label>
          <input value={title} onChange={(e) => setTitle(e.target.value)} autoFocus placeholder="Public S3 bucket detected" />
          <label className="f">Detail (optional)</label>
          <textarea rows={2} value={detail} onChange={(e) => setDetail(e.target.value)} />
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || !title || !ruleId || !assetId}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/cloud/posture", {
                    asset_id: Number(assetId),
                    rule_id: ruleId,
                    title,
                    severity,
                    status: "open",
                    detail: detail || undefined,
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
