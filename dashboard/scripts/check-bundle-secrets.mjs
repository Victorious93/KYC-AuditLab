#!/usr/bin/env node
// Fails (exit 1) if a built dashboard bundle contains anything key-like.
// Usage: node scripts/check-bundle-secrets.mjs [dir=dist]
//
// Extra literal values to look for can be passed via BUNDLE_CANARIES
// (comma-separated), e.g. the dev key used on this machine.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const dir = process.argv[2] || "dist";

const PATTERNS = [
  // The old baked-key mechanism, and any similar public env var.
  [/VITE_[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)/, "VITE_* secret variable name"],
  // An X-API-Key header with a hard-coded string value ("X-API-Key":"abc...").
  [/X-API-Key["']?\s*[:,]\s*["'`][^"'`]{4,}["'`]/i, "hard-coded X-API-Key value"],
  [/Bearer\s+iss1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, "hard-coded session token"],
  [/\biss1\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/, "session token"],
  // identity:roles:secret entries as used by IDENTITYSHIELD_(DEV_)API_KEYS.
  [/[\w.-]+:(admin|operator)(\+(admin|operator))?:[^\s"'`,]{6,}/, "API key config entry"],
  // sha256 hex digests (hashed key config).
  [/(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/, "64-char hex digest"],
  // Placeholder/dev keys from the docs and .env.example.
  [/change-me-dev-key|\bdevkey\b/, "documented dev key"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key"],
];

const canaries = (process.env.BUNDLE_CANARIES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function* walk(d) {
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

let files;
try {
  files = [...walk(dir)];
} catch (e) {
  console.error(`check-bundle-secrets: cannot read ${dir}: ${e.message}`);
  process.exit(2);
}
if (!files.length) {
  console.error(`check-bundle-secrets: ${dir} is empty (did the build run?)`);
  process.exit(2);
}

const hits = [];
for (const f of files) {
  const text = readFileSync(f, "utf8");
  for (const [re, what] of PATTERNS) {
    const m = text.match(re);
    if (m) hits.push(`${relative(".", f)}: ${what}: ${m[0].slice(0, 12)}...`);
  }
  for (const c of canaries) {
    if (text.includes(c)) hits.push(`${relative(".", f)}: canary value from BUNDLE_CANARIES`);
  }
}

if (hits.length) {
  console.error("check-bundle-secrets: key-like content found in the bundle:");
  for (const h of hits) console.error("  " + h);
  process.exit(1);
}
console.log(`check-bundle-secrets: OK (${files.length} files in ${dir}, ${PATTERNS.length} patterns, ${canaries.length} canaries)`);
