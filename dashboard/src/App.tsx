import { useEffect, useState } from "react";
import { api, RunDetail, RunSummary, TestModuleInfo } from "./api";

const CAPABILITY_LABEL: Record<string, string> = {
  implemented: "Implemented",
  evaluation_only: "Evaluation-only",
  stub_not_implemented: "Not implemented (stub)",
};

export function App() {
  const [modules, setModules] = useState<TestModuleInfo[]>([]);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [target, setTarget] = useState("backend:8000");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [selectedRun, setSelectedRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refreshRuns = () => api.listRuns().then(setRuns).catch((e) => setError(String(e)));

  useEffect(() => {
    api.listModules().then(setModules).catch((e) => setError(String(e)));
    refreshRuns();
  }, []);

  const runModule = async (moduleId: string) => {
    setError(null);
    try {
      await api.runModule(moduleId, target);
      await refreshRuns();
    } catch (e) {
      setError(String(e));
    }
  };

  const authorize = async () => {
    setError(null);
    try {
      await api.authorizeScope(target.split(":")[0], authorizedBy || "dashboard-operator");
    } catch (e) {
      setError(String(e));
    }
  };

  const openRun = async (id: string) => {
    try {
      setSelectedRun(await api.getRun(id));
    } catch (e) {
      setError(String(e));
    }
  };

  const byLayer = modules.reduce<Record<string, TestModuleInfo[]>>((acc, m) => {
    (acc[m.layer] ||= []).push(m);
    return acc;
  }, {});

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 1100, margin: "0 auto", padding: 24 }}>
      <h1>IdentityShield</h1>
      <p style={{ color: "#555" }}>
        Local-first KYC security assessment framework. Targets the bundled simulator only, by design.
      </p>

      <section style={{ display: "flex", gap: 12, alignItems: "center", margin: "16px 0", flexWrap: "wrap" }}>
        <label>
          Target:&nbsp;
          <input value={target} onChange={(e) => setTarget(e.target.value)} style={{ width: 220 }} />
        </label>
        <label>
          Authorized by:&nbsp;
          <input
            value={authorizedBy}
            onChange={(e) => setAuthorizedBy(e.target.value)}
            placeholder="your name/role"
          />
        </label>
        <button onClick={authorize}>Authorize this target (POST /scope)</button>
      </section>

      {error && (
        <div style={{ background: "#fee", border: "1px solid #c00", padding: 8, marginBottom: 16 }}>
          {error}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        <div>
          <h2>Test modules</h2>
          {Object.entries(byLayer).map(([layer, mods]) => (
            <div key={layer} style={{ marginBottom: 16 }}>
              <h3>{layer}</h3>
              {mods.map((m) => (
                <div key={m.id} style={{ border: "1px solid #ddd", borderRadius: 6, padding: 10, marginBottom: 8 }}>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <strong>{m.title}</strong>
                    <span
                      style={{
                        fontSize: 12,
                        padding: "2px 6px",
                        borderRadius: 4,
                        background: m.capability === "implemented" ? "#dfd" : "#eee",
                      }}
                    >
                      {CAPABILITY_LABEL[m.capability]}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, color: "#666", margin: "4px 0" }}>{m.description}</div>
                  {m.limitation && (
                    <div style={{ fontSize: 12, color: "#a00" }}>Limitation: {m.limitation}</div>
                  )}
                  <button onClick={() => runModule(m.id)}>Run</button>
                </div>
              ))}
            </div>
          ))}
        </div>

        <div>
          <h2>Recent runs</h2>
          <button onClick={refreshRuns}>Refresh</button>
          <table style={{ width: "100%", fontSize: 13, marginTop: 8 }}>
            <thead>
              <tr>
                <th align="left">Module</th>
                <th align="left">Status</th>
                <th align="left">Findings</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id} style={{ cursor: "pointer" }} onClick={() => openRun(r.id)}>
                  <td>{r.module_id}</td>
                  <td>{r.status}</td>
                  <td>{r.finding_count}</td>
                </tr>
              ))}
            </tbody>
          </table>

          {selectedRun && (
            <div style={{ border: "1px solid #ddd", borderRadius: 6, padding: 10, marginTop: 12 }}>
              <h3>{selectedRun.module_id}</h3>
              <div>Status: {selectedRun.status}</div>
              <div>Summary: {selectedRun.summary}</div>
              {selectedRun.findings.map((f, i) => (
                <div key={i} style={{ borderTop: "1px solid #eee", marginTop: 8, paddingTop: 8 }}>
                  <strong>
                    [{f.severity}] {f.title}
                  </strong>
                  <div>{f.description}</div>
                  {f.remediation && <div style={{ color: "#070" }}>Fix: {f.remediation}</div>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
