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

// SEC-124c: a browser can refuse every place we might keep the token — `localStorage` and
// `sessionStorage` throw in a sandboxed frame, and cookies are dropped when the app is a
// third party. The memory fallback is the one that always works, so a login survives
// navigation within the page even when storage is denied (a reload then costs one login).
let memoryToken: string | null = null;

/** The bearer token for preview/embedded contexts (SEC-124); no-op in production. */
export const session = {
  token: () => {
    if (memoryToken) return memoryToken;
    for (const store of [() => window.localStorage, () => window.sessionStorage]) {
      try {
        const found = store().getItem(TOKEN_KEY);
        if (found) return found;
      } catch { /* blocked; try the next one */ }
    }
    return null;
  },
  keep: (token: string | undefined) => {
    if (!token) return;
    memoryToken = token;
    for (const store of [() => window.localStorage, () => window.sessionStorage]) {
      try { store().setItem(TOKEN_KEY, token); } catch { /* blocked; memory holds it */ }
    }
  },
  clear: () => {
    memoryToken = null;
    for (const store of [() => window.localStorage, () => window.sessionStorage]) {
      try { store().removeItem(TOKEN_KEY); } catch { /* nothing to clear */ }
    }
  },
  /** True when the token only exists in memory — i.e. storage was refused. */
  volatileOnly: () => {
    if (!memoryToken) return false;
    try { return window.sessionStorage.getItem(TOKEN_KEY) !== memoryToken; } catch { return true; }
  },
};

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined && !(body instanceof FormData)) headers["Content-Type"] = "application/json";
  const token = session.token();
  if (token) {
    // Two carriers again (SEC-124d): `Authorization` is what every server expects, and
    // `X-Session-Token` is the one intermediaries treat as opaque payload. Whichever
    // survives the proxy path carries the session.
    headers["Authorization"] = `Bearer ${token}`;
    headers["X-Session-Token"] = token;
  }
  // A marker, never a credential: lets the server's transport log distinguish "the page
  // sent nothing" from "the page sent it and something in between dropped it".
  headers["X-Auth-Source"] = token ? "attached" : "none";
  const res = await fetch(path, {
    method,
    // SEC-124c: "include" behaves exactly like "same-origin" for same-origin requests and
    // additionally carries (and accepts) the session cookie when the app is embedded
    // cross-origin — the case a preview creates. `same-origin` there would silently drop
    // the Set-Cookie from a successful login.
    credentials: "include",
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
  const text = await res.text();
  if (!text) return undefined as T;
  // SEC-124d: parse as JSON when it *is* JSON, not merely when the header says so — an
  // intermediary is free to rewrite Content-Type, and treating a JSON body as text cost
  // the session token (login 200, every later call 401).
  const looksJson = ct.includes("json") || /^[[{]/.test(text.trim());
  if (looksJson) {
    try {
      return JSON.parse(text) as T;
    } catch {
      /* not actually JSON; fall through to text */
    }
  }
  return text as T;
}

/**
 * Login (SEC-124d). Reads the token from the response *header* as well as the body: the
 * two are independent carriers, and a body a proxy rewrote should not cost the session.
 * When neither is present the page reports what it saw to the server (lab-like only) so
 * the cause is visible in the log rather than guessed at.
 */
export async function login(username: string, password: string): Promise<{ token: string | null }> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const text = await res.text();
  let body: Record<string, unknown> | null = null;
  try {
    body = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    body = null;
  }
  if (!res.ok) {
    const detail = (body?.detail ?? null) as { code?: string; message?: string } | null;
    throw new ApiError(res.status, detail?.code || "error",
                       detail?.message || res.statusText || `HTTP ${res.status}`);
  }
  const header = res.headers.get("X-Session-Token");
  const token = (body?.session_token as string | undefined) ?? header ?? null;
  session.keep(token ?? undefined);
  if (!token) {
    // Shape only — never the body's contents, the password, or any token.
    void report("login-response-without-token", {
      content_type: res.headers.get("content-type") || null,
      body_was_json: body !== null,
      body_type: body === null ? typeof text : "object",
      keys: body ? Object.keys(body).slice(0, 12) : [],
      header_present: header !== null,
      storage: storageAvailability(),
    });
  }
  return { token };
}

/** What this browser allows, for the diagnostic report (SEC-124d). */
export function storageAvailability() {
  const probe = (get: () => Storage) => {
    try {
      const store = get();
      const k = "__probe__";
      store.setItem(k, "1");
      store.removeItem(k);
      return true;
    } catch {
      return false;
    }
  };
  return {
    local: probe(() => window.localStorage),
    session: probe(() => window.sessionStorage),
    cookie: (() => {
      try {
        return navigator.cookieEnabled && document.cookie !== undefined;
      } catch {
        return false;
      }
    })(),
    third_party_blocked: (() => {
      try {
        return !window.top || window.top !== window.self;
      } catch {
        return true;               // cross-origin ancestor: we are inside someone's frame
      }
    })(),
  };
}

export async function diagnose(stage: string, detail: Record<string, unknown>) {
  await report(stage, detail);
}

async function report(stage: string, detail: Record<string, unknown>) {
  try {
    await fetch("/api/auth/client-report", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ stage, detail }),
    });
  } catch {
    /* a diagnostic must never be the thing that breaks */
  }
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
