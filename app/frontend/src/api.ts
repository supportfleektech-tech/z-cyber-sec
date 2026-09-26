/**
 * Minimal same-origin API client.
 * - Credentials ride the httpOnly session cookie (SameSite=Strict).
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

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body !== undefined && !(body instanceof FormData) ? { "Content-Type": "application/json" } : undefined,
    body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
  });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
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
