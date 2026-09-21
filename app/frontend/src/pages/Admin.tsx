import { useState } from "react";
import { api, fmtTs } from "../api";
import { ConfirmButton, LoadBlock, Modal, PageHead, Pager, StBadge, useApi, useFlash } from "../components";

interface UserRow {
  id: number;
  username: string;
  display_name: string | null;
  role: string;
  active: number;
  created_at: string;
}
interface AuditRow {
  seq: number;
  ts: string;
  actor_name: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  detail: string | null;
}
interface Flag {
  id: number;
  key: string;
  value: number;
  description: string | null;
  updated_at: string;
}
interface Integration {
  id: number;
  name: string;
  kind: string;
  status: string;
  last_run_at: string | null;
  last_status: string | null;
}
interface Paged<T> {
  items: T[];
  total: number;
}

const ROLES = ["admin", "ir_lead", "soc_analyst", "viewer", "agent_service"];

export default function Admin() {
  const [flash, flashShow] = useFlash();
  const [tab, setTab] = useState<"audit" | "users" | "integrations" | "flags" | "backup">("audit");
  return (
    <>
      <PageHead
        title="Admin"
        sub="Users & roles · audit chain integrity · integrations · feature flags · backup/restore"
      />
      {flash}
      <div className="toolbar">
        {(["audit", "users", "integrations", "flags", "backup"] as const).map((t) => (
          <button key={t} className={tab === t ? "primary small" : "small"} onClick={() => setTab(t)}>
            {t}
          </button>
        ))}
      </div>
      {tab === "audit" && <AuditTab onFlash={flashShow} />}
      {tab === "users" && <UsersTab onFlash={flashShow} />}
      {tab === "integrations" && <IntegrationsTab onFlash={flashShow} />}
      {tab === "flags" && <FlagsTab onFlash={flashShow} />}
      {tab === "backup" && <BackupTab onFlash={flashShow} />}
    </>
  );
}

function AuditTab({ onFlash }: { onFlash: (m: string, ok?: boolean) => void }) {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [page, setPage] = useState(1);
  const audit = useApi<Paged<AuditRow>>(
    () =>
      api.get<Paged<AuditRow>>(
        `/api/admin/audit?action=${encodeURIComponent(action)}&actor=${encodeURIComponent(actor)}&page=${page}&page_size=100`,
      ),
    [action, actor, page],
  );
  const verify = useApi<{ ok: boolean; rows: number; first_bad_seq: number | null }>(
    () => api.get("/api/admin/audit/verify"),
    [],
  );
  return (
    <>
      <div className="panel">
        <div className="row">
          <h2 style={{ margin: 0 }}>Hash-chained audit log</h2>
          <span className="right">
            {verify.loading && <span className="faint">verifying…</span>}
            {verify.data &&
              (verify.data.ok ? (
                <span className="ok-box" style={{ display: "inline-block" }}>
                  chain OK · {verify.data.rows} rows
                </span>
              ) : (
                <span className="error-box" style={{ display: "inline-block" }}>
                  TAMPER DETECTED at seq {verify.data.first_bad_seq}
                </span>
              ))}
          </span>
        </div>
        <div className="toolbar mt">
          <input type="search" placeholder="action prefix (e.g. auth.)" value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }} style={{ width: 200 }} />
          <input type="search" placeholder="actor" value={actor} onChange={(e) => { setActor(e.target.value); setPage(1); }} style={{ width: 150 }} />
          <button className="small" onClick={verify.reload}>Re-verify chain</button>
        </div>
        <LoadBlock loading={audit.loading} error={audit.error} empty={!audit.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>seq</th><th>ts</th><th>actor</th><th>action</th><th>target</th><th>detail</th></tr>
            </thead>
            <tbody>
              {audit.data!.items.map((r) => (
                <tr key={r.seq}>
                  <td className="mono dim">{r.seq}</td>
                  <td className="mono dim">{fmtTs(r.ts)}</td>
                  <td>{r.actor_name}</td>
                  <td className="mono">{r.action}</td>
                  <td className="dim">{r.target_type ? `${r.target_type}:${r.target_id || ""}` : "—"}</td>
                  <td className="dim" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={r.detail || ""}>
                    {r.detail || ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={page} page_size={100} total={audit.data!.total} onPage={setPage} />
        </LoadBlock>
      </div>
      <span className="faint" onClick={() => onFlash("Audit verification result shown above")} style={{ display: "none" }}>
        {""}
      </span>
    </>
  );
}

function UsersTab({ onFlash }: { onFlash: (m: string, ok?: boolean) => void }) {
  const users = useApi<Paged<UserRow>>(() => api.get<Paged<UserRow>>("/api/auth/users"), []);
  const [open, setOpen] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <div className="panel">
        <h2>Users (app-managed auth — PBKDF2-SHA256 390k, hashed tokens only)</h2>
        <LoadBlock loading={users.loading} error={users.error} empty={!users.data?.items?.length}>
          <table className="tbl">
            <thead>
              <tr><th>Username</th><th>Display name</th><th>Role</th><th>Active</th><th>Created</th></tr>
            </thead>
            <tbody>
              {users.data!.items.map((u) => (
                <tr key={u.id}>
                  <td className="mono">{u.username}</td>
                  <td>{u.display_name || "—"}</td>
                  <td>
                    <select
                      className="small"
                      defaultValue={u.role}
                      onChange={async (e) => {
                        try {
                          await api.patch(`/api/auth/users/${u.id}`, { role: e.target.value });
                          onFlash(`${u.username} role → ${e.target.value}`);
                          users.reload();
                        } catch (e) {
                          onFlash((e as Error).message, false);
                        }
                      }}
                    >
                      {ROLES.map((r) => <option key={r}>{r}</option>)}
                    </select>
                  </td>
                  <td>
                    <ConfirmButton
                      label={u.active ? "Deactivate" : "Activate"}
                      confirmLabel={`${u.active ? "Deactivate" : "Activate"} ${u.username}?`}
                      impact={u.active ? "User cannot log in until re-activated. Sessions expire by TTL." : "User can log in again."}
                      danger={!!u.active}
                      onConfirm={async () => {
                        await api.patch(`/api/auth/users/${u.id}`, { active: !u.active });
                        onFlash(`${u.username} ${u.active ? "deactivated" : "activated"}`);
                        users.reload();
                      }}
                    />
                  </td>
                  <td className="dim">{fmtTs(u.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </LoadBlock>
        <div className="mt">
          <button className="primary" onClick={() => { setErr(null); setOpen(true); }}>+ New user</button>
        </div>
      </div>

      {open && (
        <Modal title="New user" onClose={() => setOpen(false)}>
          <label className="f">Username (lowercase, a-z 0-9 . _ -)</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          <label className="f">Password (min 8 chars — shown once, never stored in plain)</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <label className="f">Role</label>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((r) => <option key={r}>{r}</option>)}
          </select>
          {err && <div className="error-box">{err}</div>}
          <div className="row mt" style={{ justifyContent: "flex-end" }}>
            <button onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="primary"
              disabled={busy || username.length < 2 || password.length < 8}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api.post("/api/auth/users", { username, password, role });
                  setOpen(false);
                  users.reload();
                  onFlash(`User ${username} created`);
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

function IntegrationsTab({ onFlash }: { onFlash: (m: string, ok?: boolean) => void }) {
  const list = useApi<{ items: Integration[]; total: number }>(() => api.get("/api/admin/integrations"), []);
  return (
    <div className="panel">
      <h2>Inbound integrations (no secrets in config — server-side secret scan)</h2>
      <LoadBlock loading={list.loading} error={list.error} empty={!list.data?.items?.length}>
        <table className="tbl">
          <thead>
            <tr><th>Name</th><th>Kind</th><th>Status</th><th>Last run</th><th>Last result</th><th></th></tr>
          </thead>
          <tbody>
            {list.data!.items.map((i) => (
              <tr key={i.id}>
                <td>{i.name}</td>
                <td className="dim">{i.kind}</td>
                <td><StBadge value={i.status} /></td>
                <td className="dim">{fmtTs(i.last_run_at)}</td>
                <td>{i.last_status ? <StBadge value={i.last_status} /> : "—"}</td>
                <td>
                  <button
                    className="small"
                    onClick={async () => {
                      try {
                        await api.post(`/api/admin/integrations/${i.id}/health`, {});
                        onFlash(`Health recorded for ${i.name}`);
                        list.reload();
                      } catch (e) {
                        onFlash((e as Error).message, false);
                      }
                    }}
                  >
                    Record health
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </LoadBlock>
      <div className="note-box mt">
        New integrations are registered with config that must not contain secrets; values matching secret patterns
        are rejected server-side. Ingest is via <code>POST /api/soc/events</code> (idempotency keys supported).
      </div>
    </div>
  );
}

function FlagsTab({ onFlash }: { onFlash: (m: string, ok?: boolean) => void }) {
  const flags = useApi<Paged<Flag>>(() => api.get<Paged<Flag>>("/api/admin/flags"), []);
  return (
    <div className="panel">
      <h2>Feature flags & settings</h2>
      <LoadBlock loading={flags.loading} error={flags.error} empty={!flags.data?.items?.length}>
        <table className="tbl">
          <tbody>
            {flags.data!.items.map((f) => (
              <tr key={f.id}>
                <td className="mono">{f.key}</td>
                <td>
                  <span className={`st ${f.value ? "met" : "aborted"}`}>{f.value ? "on" : "off"}</span>
                </td>
                <td className="dim">{f.description || ""}</td>
                <td className="dim">{fmtTs(f.updated_at)}</td>
                <td>
                  <button
                    className="small"
                    onClick={async () => {
                      try {
                        await api.post("/api/admin/flags", { key: f.key, value: !f.value, description: f.description || undefined });
                        onFlash(`Flag ${f.key} → ${f.value ? "off" : "on"}`);
                        flags.reload();
                      } catch (e) {
                        onFlash((e as Error).message, false);
                      }
                    }}
                  >
                    Toggle
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

function BackupTab({ onFlash }: { onFlash: (m: string, ok?: boolean) => void }) {
  const [path, setPath] = useState("");
  const [lastBackup, setLastBackup] = useState<{ path: string; sha256: string } | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="panel">
      <h2>Backup & restore (SQLite hot backup, sha256-pinned)</h2>
      <div className="row">
        <button
          className="primary"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            try {
              const out = await api.post<{ path: string; sha256: string }>("/api/admin/backup");
              setLastBackup(out);
              onFlash(`Backup written: ${out.path}`);
            } catch (e) {
              onFlash((e as Error).message, false);
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy ? "Backing up…" : "Take backup"}
        </button>
        <span className="faint">writes to data/backups with sha256 checksum</span>
      </div>
      {lastBackup && (
        <div className="note-box mt">
          <div>path: <code>{lastBackup.path}</code></div>
          <div>sha256: <code>{lastBackup.sha256}</code></div>
        </div>
      )}
      <div className="mt">
        <label className="f">Restore from backup file path</label>
        <div className="row">
          <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/…/data/backups/cybersec-….db" style={{ width: 380 }} />
          <ConfirmButton
            label="Restore"
            confirmLabel="Restore the database from this backup file? Current data will be replaced."
            impact="Irreversible for the live database (a fresh backup should be taken first). The API refuses paths outside data/backups and requires the literal confirm token."
            danger
            onConfirm={async () => {
              const out = await api.post("/api/admin/backup/restore", { path, confirm: "RESTORE" });
              onFlash(`Restored: ${(out as { path?: string }).path || path}`);
            }}
          />
        </div>
      </div>
    </div>
  );
}
