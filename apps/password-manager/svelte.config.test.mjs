import assert from "node:assert/strict";
import { realpathSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { sveltekit } from "@sveltejs/kit/vite";
import { resolveConfig } from "vite";

import config from "./svelte.config.js";

const source = fileURLToPath(
    new URL("../../packages/storage-client/src/index.ts", import.meta.url),
);

test("production SvelteKit config maps Storage to the current handwritten entry", () => {
    assert.equal(config.kit.alias?.["@aicacia/storage-client"], source);
});

test("SvelteKit propagates the production Storage alias into Vite runtime resolution", async (t) => {
    const cwd = process.cwd();
    t.after(() => process.chdir(cwd));
    process.chdir(fileURLToPath(new URL(".", import.meta.url)));

    const resolved = await resolveConfig(
        { configFile: false, plugins: [sveltekit()] },
        "serve",
    );
    const alias = resolved.resolve.alias.find(
        (entry) => entry.find === "@aicacia/storage-client",
    );
    assert.equal(alias?.replacement, source);
    assert.equal(realpathSync(alias.replacement), realpathSync(source));
});
