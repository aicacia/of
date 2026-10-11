import { fileURLToPath } from "node:url";
import { sveltekit } from "@sveltejs/kit/vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [sveltekit()],
  resolve: {
    alias: {
      "@aicacia/oidc-client": fileURLToPath(
        new URL("../../packages/oidc-client/src/index.ts", import.meta.url),
      ),
      "@aicacia/idp-client": fileURLToPath(
        new URL("../../packages/idp-client/src/index.ts", import.meta.url),
      ),
      "@aicacia/management-client": fileURLToPath(
        new URL(
          "../../packages/management-client/src/index.ts",
          import.meta.url,
        ),
      ),
      "@aicacia/svelte-headless": fileURLToPath(
        new URL(
          "../../packages/svelte-headless/src/lib/state/storage.svelte.ts",
          import.meta.url,
        ),
      ),
    },
  },
  test: {
    include: [
      "src/lib/common/state/setupClient.test.ts",
      "src/routes/(auth)/layout.test.ts",
      "src/routes/setup/installation/page.test.ts",
    ],
  },
});
