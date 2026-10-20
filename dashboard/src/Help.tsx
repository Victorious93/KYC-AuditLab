// In-app Help: a summary of docs/MANUAL.md (the full manual lives in the repo).
// Static content only: no API calls, no secrets.

const box = { border: "1px solid #ddd", borderRadius: 6, padding: 12, marginBottom: 12 } as const;

export function Help({ onBack }: { onBack: () => void }) {
  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 900, margin: "0 auto", padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1>Help</h1>
        <button onClick={onBack}>Back to dashboard</button>
      </div>
      <p style={{ color: "#555" }}>
        A short version of the manual. The full manual is <code>docs/MANUAL.md</code> in the KYC-AuditLab repository.
      </p>

      <section style={box}>
        <h2>What IdentityShield is</h2>
        <p>
          A local-first lab that tests a KYC / identity-verification flow across seven layers: document, biometric,
          liveness, Android client, API, workflow and fraud monitoring. Out of the box it targets only its own bundled,
          synthetic simulator. It runs on a host (your computer). The Android companion app is an external node that the
          backend drives over adb.
        </p>
      </section>

      <section style={box}>
        <h2>Signing in</h2>
        <ol>
          <li>Paste an API key and click Sign in. The key is sent once to <code>POST /auth/session</code> and then discarded.</li>
          <li>The dashboard keeps only the short-lived session token, in this tab's <code>sessionStorage</code>.</li>
          <li>Sign out (top right) revokes the token on the server. An expired or revoked token sends you back here.</li>
          <li>Too many failed sign-ins from one IP get <code>429</code>. Wait for the <code>Retry-After</code> time.</li>
          <li>You need both roles: <code>admin</code> for scope and <code>operator</code> for tests and results.</li>
        </ol>
      </section>

      <section style={box}>
        <h2>Running a test</h2>
        <ol>
          <li>Set <strong>Target</strong> to the simulator's host:port (for local dev, <code>localhost:8000</code>).</li>
          <li>Click <strong>Authorize this target</strong>. Scope is default-deny: nothing runs without a scope entry, and the host must also be on the server allowlist.</li>
          <li>Click <strong>Run</strong> on a module. The result appears under <strong>Recent runs</strong>. Click a row to see findings and fixes.</li>
          <li>The simulator is deliberately vulnerable by default. Start the backend with <code>IDENTITYSHIELD_SIM_VULNERABLE=0</code> to test the hardened version.</li>
        </ol>
      </section>

      <section style={box}>
        <h2>Android (Layer 4)</h2>
        <p>
          Build the companion (<code>./gradlew assembleDebug</code>) and attach an emulator or test device (<code>adb devices</code>).
          Then authorize the target app's package name and run a Layer 4 module. The backend installs the APK and runs it with{" "}
          <code>am instrument</code>. The companion has no INTERNET permission and holds no key. With no device attached, Layer 4 runs are
          reported as <em>skipped</em>, never as passed.
        </p>
      </section>

      <section style={box}>
        <h2>Remote control</h2>
        <p>
          Remote control of the companion is <strong>not implemented and is off</strong>. External controllers use the HTTP API with
          their own key (see <code>docs/CONTROLLER_INTEGRATION.md</code>).
        </p>
      </section>

      <section style={box}>
        <h2>Privacy</h2>
        <p>
          Everything stays on this machine. The API and dashboard bind to loopback, and the bundled data is synthetic. Never enter real
          identities or point this at a real KYC provider.
        </p>
      </section>
    </div>
  );
}
