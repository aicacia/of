import { createRequire } from "node:module";
import { type Environment, populateGlobal } from "vitest/runtime";

export default {
    name: "residency-dom",
    viteEnvironment: "client",
    setup(global) {
        const { JSDOM } = createRequire(import.meta.url)(
            process.env.RESIDENCY_JSDOM_MODULE || "jsdom",
        );
        const dom = new JSDOM("<!doctype html><html><body></body></html>", {
            url: "https://app.test",
            pretendToBeVisual: true,
        });
        const { keys, originals } = populateGlobal(global, dom.window, {
            bindFunctions: true,
        });
        return {
            teardown() {
                dom.window.close();
                keys.forEach((key) => {
                    delete global[key];
                });
                originals.forEach((value, key) => {
                    global[key] = value;
                });
            },
        };
    },
} satisfies Environment;
