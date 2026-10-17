import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

// Anything prefixed VITE_ is public: Vite can inline it into the JavaScript
// bundle that every visitor downloads. Refuse to start or build if a
// secret-looking VITE_ variable is set, so an API key can't be baked in by
// accident. The dashboard asks the operator for a key at runtime instead.
const SECRET_LIKE = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)/i;

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const offending = Object.keys(env).filter((name) => SECRET_LIKE.test(name));
  if (offending.length) {
    throw new Error(
      `Refusing to run with secret-looking public env var(s): ${offending.join(", ")}. ` +
        "VITE_* values are inlined into the browser bundle. Remove them; the dashboard " +
        "prompts for an API key at runtime.",
    );
  }
  return {
    plugins: [react()],
    server: { port: 5173 },
  };
});
