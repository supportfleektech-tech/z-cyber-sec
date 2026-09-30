/**
 * Minimal same-origin API client.
 * - Credentials ride the httpOnly session cookie.
 * - SEC-124: in lab/preview mode the login response also carries the session token, kept
 *   in sessionStorage and sent as `Authorization: Bearer`. A preview is a cross-site
 *   context, where the browser drops the SameSite cookie and the session would not
 *   survive; the bearer token is the same opaque token backing the same server-side
 *   session (RBAC, expiry and revocation identical). Production returns no token here.
 * - 401 -> bounce to the login page (hash router).
 * - Error bodies carry {detail: {code, message}} from the backend.
 */
export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const TOKEN_KEY = "cybersec_session";

/** The bearer token for preview/embedded contexts (SEC-124); no-op in production. */
export const session = {
  token: () => {
    try { return window.sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
  },
  keep: (token: string | undefined) => {
    try {
      if (token) window.sessionStorage.setItem(TOKEN_KEY, token);
    } catch { /* storage blocked; the cookie is the only transport */ }
  },
  clear: () => {
    try { window.sessionStorage.removeItem(TOKEN_KEY); } catch { /* nothing to clear */ }
  },
};

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined && !(body instanceof FormData)) headers["Content-Type"] = "application/json";
  const token = session.token();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
  });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    session.clear();
    window.location.hash = "#/login";
    throw new ApiError(401, "unauthenticated", "Session expired");
  }
  if (!res.ok) {
    let code = "error";
    let message = res.statusText;
    try {
      const j = await res.json();
      const d = j?.detail;
      if (typeof d === "string") message = d;
      else if (d && typeof d === "object") {
        code = d.code || code;
        message = d.message || JSON.stringify(d);
      } else if (Array.isArray(j?.detail)) {
        message = j.detail.map((x: { msg?: string }) => x.msg).filter(Boolean).join("; ") || message;
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, code, message);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") || "";
  return (ct.includes("application/json") ? res.json() : res.text()) as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  delete: <T>(path: string) => request<T>("DELETE", path),
};

export const fmtTs = (ts: string | null | undefined): string => {
  if (!ts) return "—";
  return ts.replace("T", " ").replace("Z", " UTC");
};

export const sevClass = (s: string | null | undefined) => `sev ${String(s || "info").toLowerCase()}`;
