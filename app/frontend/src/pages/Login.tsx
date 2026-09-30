import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, session } from "../api";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const navigate = useNavigate();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.post<{ session_token?: string }>("/api/auth/login", { username, password });
      // Preview/embedded contexts receive a token (SEC-124); production sends none and
      // the httpOnly cookie is the only transport.
      session.keep(res?.session_token);
      // Prove the session survived before navigating: a browser that refuses cookies
      // *and* storage would otherwise bounce straight back here from /overview with no
      // explanation (SEC-124c).
      try {
        await api.get("/api/auth/me");
      } catch {
        setBlocked(true);
        return;
      }
      if (session.volatileOnly()) setBlocked(true);
      navigate("/overview");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1>🛡 CYBER-SEC</h1>
        <div className="sub">Security operations console — local lab (synthetic data)</div>
        {error && <div className="error-box">{error}</div>}
        {blocked && (
          <div className="error-box">
            <b>Signed in, but this browser kept no session.</b>
            <div className="mt">
              The page is embedded, and this browser blocks cookies and storage for
              embedded pages. Open the console in its own tab — the session then works
              normally.
            </div>
            <div className="mt">
              <button
                type="button"
                className="primary"
                onClick={() => window.open(window.location.href, "_blank", "noopener")}
              >
                Open in a new tab
              </button>
            </div>
          </div>
        )}
        <label className="f" htmlFor="u">Username</label>
        <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
        <label className="f" htmlFor="p">Password</label>
        <input id="p" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        <div className="mt">
          <button className="primary" style={{ width: "100%" }} disabled={busy || !username || !password}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </div>
        <div className="faint mt">
          Demo users (dev seed only): admin · iris (ir_lead) · sasha (soc_analyst) · viewer · agent-svc (agent_service)
        </div>
      </form>
    </div>
  );
}
