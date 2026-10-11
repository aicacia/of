import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const base = process.argv[2];
assert.ok(base, "Pass the live unified fixture URL");
assert.ok(
    process.env.npm_execpath,
    "Set npm_execpath to the existing pnpm executable",
);

function digest(directory) {
    const hash = createHash("sha256");
    function visit(relative) {
        for (const entry of readdirSync(path.join(directory, relative), {
            withFileTypes: true,
        }).sort((a, b) => a.name.localeCompare(b.name))) {
            const name = path.join(relative, entry.name);
            if (entry.isDirectory()) visit(name);
            else
                hash.update(name).update(
                    readFileSync(path.join(directory, name)),
                );
        }
    }
    visit("");
    return hash.digest("hex");
}

for (const [service, count] of [
    ["idp", 50],
    ["management", 24],
    ["storage", 14],
]) {
    const url = `${base}/${service}/openapi.json`;
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 200, url);
    const document = await response.json();
    assert.equal(
        document.servers[0].url,
        `https://${service}.example/${service}`,
    );
    const operations = Object.values(document.paths).flatMap((item) =>
        Object.values(item).filter((operation) => operation?.operationId),
    );
    assert.equal(
        operations.length,
        count,
        `${service} complete operation inventory`,
    );
    for (const route of Object.keys(document.paths)) {
        assert.ok(
            !route.startsWith(`/${service}/`),
            `${service} prefix must be supplied by server only: ${route}`,
        );
        assert.ok(!route.includes("/internal/"));
    }
    if (service === "idp") {
        assert.ok(
            operations.some(
                (operation) =>
                    operation.operationId === "transfer_device" ||
                    operation.operationId === "transferDevice",
            ),
        );
        assert.ok(
            !Object.keys(document.paths).some((route) =>
                route.includes("/setup/bootstrap"),
            ),
        );
        assert.ok(
            !Object.keys(document.components.schemas).some((name) =>
                name.startsWith("SetupBootstrap"),
            ),
        );
    }
    console.log(
        `VERIFIED ${url}: ${count} operations; server=${document.servers[0].url}`,
    );
    const cwd = path.join(root, "packages", `${service}-client`);
    const source = path.join(
        cwd,
        "src",
        ...(service === "storage" ? ["generated"] : []),
    );
    const invoke = (spec) =>
        spawnSync(
            process.execPath,
            [path.join(root, "scripts/generate-openapi-client.mjs"), service],
            {
                cwd,
                env: { ...process.env, OPENAPI_SPEC_URL: spec },
                encoding: "utf8",
                timeout: 120000,
                maxBuffer: 16 * 1024 * 1024,
            },
        );
    const result = invoke(url);
    process.stdout.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, `${service} actual generation`);
    const before = digest(source);
    // Reserve, then close a fresh loopback port: the real generator must fail to connect.
    const listener = createServer();
    await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
    const port = listener.address().port;
    await new Promise((resolve, reject) =>
        listener.close((error) => (error ? reject(error) : resolve())),
    );
    const unreachable = `http://127.0.0.1:${port}/${service}/openapi.json`;
    const failed = invoke(unreachable);
    assert.equal(failed.error, undefined);
    assert.notEqual(failed.status, 0, `${service} unreachable input must fail`);
    assert.match(failed.stderr, /OpenAPI generation failed/);
    assert.match(
        `${failed.stdout}${failed.stderr}`,
        /ConnectException|Connection refused/,
    );
    assert.equal(
        digest(source),
        before,
        `${service} failed generation preserves every source byte`,
    );
    assert.ok(
        !readdirSync(cwd).some((name) => name.startsWith(".src-backup-")),
    );
    assert.ok(
        !readdirSync(path.dirname(cwd)).some((name) =>
            name.startsWith(".openapi-generation-"),
        ),
    );
    console.log(
        `PASS ${service} generation; unreachable=${unreachable}; source SHA256 preserved=${before}; staging cleaned`,
    );
}
