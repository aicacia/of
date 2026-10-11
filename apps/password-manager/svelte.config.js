import { fileURLToPath } from "node:url";

import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** @type {import('@sveltejs/kit').Config} */
const config = {
    // Consult https://svelte.dev/docs/kit/integrations
    // for more information about preprocessors
    preprocess: vitePreprocess(),
    kit: {
        alias: {
            "@aicacia/storage-client": fileURLToPath(
                new URL(
                    "../../packages/storage-client/src/index.ts",
                    import.meta.url,
                ),
            ),
        },
        // adapter-auto only supports some environments, see https://svelte.dev/docs/kit/adapter-auto for a list.
        // If your environment is not supported, or you settled on a specific environment, switch out the adapter.
        // See https://svelte.dev/docs/kit/adapters for more information about adapters.
        adapter: adapter({
            fallback: "index.html",
        }),
        paths: {
            base: process.env.VITE_BASE_PATH,
            relative: false,
        },
    },
};

export default config;
