import { ReactNode, useCallback, useEffect, useRef, useState } from "react";

/** Async data hook with reload; surfaces loading/error/empty states. */
export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    fnRef
      .current()
      .then((d) => alive && setData(d))
      .catch((e: Error) => alive && setError(e.message || String(e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { data, loading, error, reload, setData };
}

export function LoadBlock({ loading, error, children, empty }: { loading: boolean; error: string | null; children: ReactNode; empty?: boolean }) {
  if (loading) return <div className="empty">Loading…</div>;
  if (error) return <div className="error-box">⚠ {error}</div>;
  if (empty) return <div className="empty">No records.</div>;
  return <>{children}</>;
}

export function PageHead({ title, sub, actions }: { title: string; sub?: string; actions?: ReactNode }) {
  return (
    <div className="pagehead">
      <div>
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

export function SevBadge({ value }: { value: string | null | undefined }) {
  const s = String(value || "info").toLowerCase();
  return <span className={`sev ${s}`}>{s}</span>;
}

export function StBadge({ value }: { value: string | null | undefined }) {
  const s = String(value || "").toLowerCase();
  return <span className={`st ${s}`}>{s || "—"}</span>;
}

export function Stat({ k, v, s, tone }: { k: string; v: ReactNode; s?: string; tone?: string }) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className="v" style={tone ? { color: `var(--sev-${tone})` } : undefined}>
        {v}
      </div>
      {s && <div className="s">{s}</div>}
    </div>
  );
}

export function Pager({ page, page_size, total, onPage }: { page: number; page_size: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / page_size));
  return (
    <div className="pager">
      <button className="small" disabled={page <= 1} onClick={() => onPage(page - 1)}>
        ← Prev
      </button>
      <span>
        page {page} / {pages} · {total} total
      </span>
      <button className="small" disabled={page >= pages} onClick={() => onPage(page + 1)}>
        Next →
      </button>
    </div>
  );
}

export function Modal({ title, children, onClose }: { title: string; children: ReactNode; onClose: () => void }) {
  return (
    <div className="modal-back" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>{title}</h3>
        {children}
      </div>
    </div>
  );
}

/** Destructive-action gate: confirm with impact summary (UX rule). */
export function ConfirmButton({
  label,
  confirmLabel,
  impact,
  onConfirm,
  danger,
}: {
  label: string;
  confirmLabel: string;
  impact: string;
  onConfirm: () => Promise<void> | void;
  danger?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <>
      <button className={danger ? "danger small" : "small"} onClick={() => { setErr(null); setOpen(true); }}>
        {label}
      </button>
      {open && (
        <Modal title="Confirm action" onClose={() => !busy && setOpen(false)}>
          <p>{confirmLabel}</p>
          <div className="note-box">{impact}</div>
          {err && <div className="error-box">{err}</div>}
          <div className="foot">
            <button disabled={busy} onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button
              className={danger ? "danger" : "primary"}
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await onConfirm();
                  setOpen(false);
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Working…" : "Confirm"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}

/** Simple message flash for mutation results. */
export function useFlash(): [ReactNode, (msg: string, ok?: boolean) => void] {
  const [msg, setMsg] = useState<string | null>(null);
  const [ok, setOk] = useState(true);
  const show = useCallback((m: string, o = true) => {
    setMsg(m);
    setOk(o);
    window.setTimeout(() => setMsg(null), 4000);
  }, []);
  return [msg ? <div className={ok ? "ok-box" : "error-box"}>{msg}</div> : null, show];
}
