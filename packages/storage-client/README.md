# Storage Client

The package contains the existing WebSocket client and a generated REST owner client under `src/generated`. `ResourcesResidencyApi`, `StorageOwnerConfiguration`, and `ResidencyMode` expose authorized whole-filesystem Full/Passthrough controls. They do not grant access or establish content/cleanup readiness.

Regenerate from the actual composed Storage OpenAPI listener:

```sh
OPENAPI_SPEC_URL=https://localhost:PORT/storage/openapi.json pnpm run openapi
```

Use the verified listener's literal URL and its normally approved CA trust. Do not bypass certificate validation. A saved, unmodified document fetched from that listener can also be supplied as the input path for reproducible offline generation.

The existing shared generator checks both Residency operations before atomically replacing only `src/generated`; failure preserves prior generated and handwritten sources. `openapitools.json` pins the generator. Never edit generated TypeScript by hand. Build with `pnpm build`; run focused client tests with `pnpm exec vitest run src/residency.test.ts src/index.test.ts`.
