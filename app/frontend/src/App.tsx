import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api } from "./api";
import { useApi } from "./components";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Soc from "./pages/Soc";
import Incidents from "./pages/Incidents";
import Intel from "./pages/Intel";
import Vulns from "./pages/Vulns";
import Appsec from "./pages/Appsec";
import Cloud from "./pages/Cloud";
import Grc from "./pages/Grc";
import Exercises from "./pages/Exercises";
import Agents from "./pages/Agents";
import Automation from "./pages/Automation";
import Reports from "./pages/Reports";
import Admin from "./pages/Admin";

interface Me {
  user_id: number;
  username: string;
  display_name?: string;
  role: string;
}
interface Health {
  ok: boolean;
  env: string;
  version: string;
}

const NAV: { group: string; items: [string, string][] }[] = [
  { group: "Command", items: [["/overview", "Overview"], ["/reports", "Reports"]] },
  {
    group: "SOC",
    items: [
      ["/soc", "Alerts & Detection"],
      ["/incidents", "Incidents"],
      ["/intel", "Threat Intel"],
    ],
  },
  {
    group: "Assets",
    items: [
      ["/vulns", "Vulnerabilities"],
      ["/appsec", "AppSec"],
      ["/cloud", "Network / Cloud"],
    ],
  },
  {
    group: "Assurance",
    items: [
      ["/grc", "GRC"],
      ["/exercises", "Exercises"],
    ],
  },
  {
    group: "Autonomy",
    items: [
      ["/agents", "Agent Center"],
      ["/automation", "Automation"],
    ],
  },
  { group: "Platform", items: [["/admin", "Admin"]] },
];

function TopBar() {
  const { data: me } = useApi<Me>(() => api.get<Me>("/api/auth/me"), []);
  const { data: health } = useApi<Health>(() => api.get<Health>("/api/healthz"), []);
  const navigate = useNavigate();
  return (
    <div className="topbar">
      <span className="brand">🛡 CYBER-SEC</span>
      {health && (
        <span className={`env-badge ${health.env === "PROD" ? "prod" : ""}`}>{health.env}</span>
      )}
      <span className="demo-pill">SYNTHETIC DATA</span>
      <div className="spacer" />
      {me && (
        <span className="user">
          {me.display_name || me.username} · <code>{me.role}</code>
        </span>
      )}
      {me && (
        <button
          className="small"
          onClick={async () => {
            try {
              await api.post("/api/auth/logout");
            } finally {
              navigate("/login");
            }
          }}
        >
          Log out
        </button>
      )}
    </div>
  );
}

function Shell() {
  const [authed, setAuthed] = useState<boolean | null>(null);
  useEffect(() => {
    api
      .get<Me>("/api/auth/me")
      .then(() => setAuthed(true))
      .catch(() => setAuthed(false));
  }, []);
  if (authed === null) return <div className="empty" style={{ paddingTop: 80 }}>Loading…</div>;
  if (!authed) return <Navigate to="/login" replace />;
  return (
    <div className="shell">
      <TopBar />
      <nav className="sidenav">
        {NAV.map((g) => (
          <div key={g.group}>
            <div className="group">{g.group}</div>
            {g.items.map(([to, label]) => (
              <NavLink key={to} to={to} className={({ isActive }) => (isActive ? "active" : "")}>
                {label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<Overview />} />
          <Route path="/soc" element={<Soc />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/intel" element={<Intel />} />
          <Route path="/vulns" element={<Vulns />} />
          <Route path="/appsec" element={<Appsec />} />
          <Route path="/cloud" element={<Cloud />} />
          <Route path="/grc" element={<Grc />} />
          <Route path="/exercises" element={<Exercises />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/automation" element={<Automation />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/*" element={<Shell />} />
    </Routes>
  );
}
