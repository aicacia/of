import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import auth from "./vitest.auth.config.ts";

export default defineConfig({
    ...auth,
    resolve: { ...auth.resolve, conditions: ["browser"] },
    test: {
        include: ["src/lib/common/components/residency.interaction.test.ts"],
        environment: fileURLToPath(
            new URL(
                "./src/lib/common/components/residency.environment.ts",
                import.meta.url,
            ),
        ),
    },
});
