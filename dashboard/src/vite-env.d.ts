/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Public, non-secret build setting. There is deliberately no API key
  // variable: the operator signs in at runtime (see src/api.ts).
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
