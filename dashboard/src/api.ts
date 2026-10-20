// Not a secret: where the backend lives. No API key is ever read from the
// build environment; the operator enters one at runtime (see signIn).
const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

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

// --- runtime sign-in --------------------------------------------------------
//
// The operator types an API key; it is sent once to POST /auth/session and
// exchanged for a short-lived signed token. Only the token is kept (in this
// tab's sessionStorage, cleared on sign-out, on any 401 and when the tab
// closes). The API key itself is never stored anywhere.

export interface Session {
  token: string;
  expiresAt: string; // ISO 8601
  identity: string;
  roles: string[];
}

const STORAGE_KEY = "identityshield.session";

export class UnauthorizedError extends Error {}

let current: Session | null = loadSession();
const listeners = new Set<(s: Session | null) => void>();

function loadSession(): Session | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw) as Session;
    if (!s.token || !(Date.parse(s.expiresAt) > Date.now())) {
      sessionStorage.removeItem(STORAGE_KEY);
      return null;
    }
    return s;
  } catch {
    return null;
  }
}

function setSession(s: Session | null) {
  current = s;
  try {
    if (s) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s));
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // sessionStorage unavailable: keep the token in memory only.
  }
  listeners.forEach((l) => l(s));
}

export const getSession = (): Session | null => {
  if (current && !(Date.parse(current.expiresAt) > Date.now())) setSession(null);
  return current;
};

export const onSessionChange = (l: (s: Session | null) => void): (() => void) => {
  listeners.add(l);
  return () => listeners.delete(l);
};

export async function signIn(apiKey: string): Promise<Session> {
  const res = await fetch(`${API_BASE}/auth/session`, {
    method: "POST",
    headers: { "X-API-Key": apiKey },
  });
  if (res.status === 401) throw new UnauthorizedError("Invalid API key.");
  if (res.status === 429) {
    const wait = res.headers.get("Retry-After");
    throw new Error(`Too many failed sign-in attempts. Try again${wait ? ` in ${wait} s` : " later"}.`);
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  const body = await res.json();
  const s: Session = {
    token: body.token,
    expiresAt: body.expires_at,
    identity: body.identity,
    roles: body.roles,
  };
  setSession(s);
  return s;
}

// Revoke the token on the server (POST /auth/logout), then forget it
// locally. Local sign-out happens even if the server call fails.
export async function signOut(): Promise<void> {
  const s = current;
  if (s) {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${s.token}` },
      });
    } catch {
      // Server unreachable: the token still expires on its own.
    }
  }
  setSession(null);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const s = getSession();
  if (!s) throw new UnauthorizedError("Not signed in.");
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${s.token}`);
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (res.status === 401) {
    // Expired, revoked or rotated: drop it and make the UI ask again.
    setSession(null);
    throw new UnauthorizedError("Session expired or revoked. Please sign in again.");
  }
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return res.json();
}

const postJson = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  listModules: () => request<TestModuleInfo[]>("/tests/modules"),
  listRuns: () => request<RunSummary[]>("/results/runs"),
  getRun: (id: string) => request<RunDetail>(`/results/runs/${encodeURIComponent(id)}`),
  runModule: (module_id: string, target: string) =>
    request<{ run_id: string; status: string; summary: string; finding_count: number }>(
      "/tests/run",
      postJson({ module_id, target }),
    ),
  authorizeScope: (target: string, authorized_by: string) =>
    request<{ status: string; target: string }>("/scope", postJson({ target, authorized_by })),
};
