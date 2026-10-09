const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL || "http://localhost:8000";

export interface TestModuleInfo {
  id: string;
  layer: string;
  title: string;
  description: string;
  capability: "implemented" | "stub_not_implemented" | "evaluation_only";
  limitation: string | null;
}

export interface RunSummary {
  id: string;
  layer: string;
  module_id: string;
  target: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  summary: string | null;
  finding_count: number;
}

export interface RunDetail extends RunSummary {
  raw_output: string | null;
  findings: {
    title: string;
    description: string;
    severity: string;
    cwe: string | null;
    remediation: string | null;
    risk_score: number;
  }[];
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return res.json();
}

export const api = {
  listModules: () => fetch(`${API_BASE}/tests/modules`).then((r) => json<TestModuleInfo[]>(r)),
  listRuns: () => fetch(`${API_BASE}/results/runs`).then((r) => json<RunSummary[]>(r)),
  getRun: (id: string) => fetch(`${API_BASE}/results/runs/${id}`).then((r) => json<RunDetail>(r)),
  runModule: (module_id: string, target: string) =>
    fetch(`${API_BASE}/tests/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ module_id, target }),
    }).then((r) => json<{ run_id: string; status: string; summary: string; finding_count: number }>(r)),
  authorizeScope: (target: string, authorized_by: string) =>
    fetch(`${API_BASE}/scope`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, authorized_by }),
    }).then((r) => json<{ status: string; target: string }>(r)),
};
