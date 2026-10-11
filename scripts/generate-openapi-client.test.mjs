import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
    chmodSync,
    mkdirSync,
    mkdtempSync,
    readdirSync,
    readFileSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

const generator = path.resolve(
    import.meta.dirname,
    "generate-openapi-client.mjs",
);
// Fixture inventory: current Rust OpenAPI routers, grouped as the generated APIs.
const contracts = {
    idp: {
        DefaultApi:
            "approveForUser authorizeJson authorizeQuery createApplication deleteApplication deleteRegister deleteUser device deviceAuth deviceVerify enrollDevice getApplication getRegister getUser health isAllowedForUser jwks listApplications listClientKeys listConsents listDevices lookupDeviceIdentity openapiJson openidConfiguration pairingAcceptance putRegister register resetPassword revoke revokeClientKeys revokeConsent revokeDevice revokeSelf rotateClientKey sessionsLogout setPairingAcceptance token transferDevice trustedDevices updateApplication updateDevice updateUser userinfo version",
        SuperRoutesDevicesApi:
            "listApprovedDeviceEndpoints lookupDeviceEndpoint",
        SuperRoutesOauth2IntrospectApi: "introspect",
        SuperRoutesReplicaSignersApi:
            "enrollReplicaSigner revokeReplicaSigner rotateReplicaSigner",
    },
    management: {
        DefaultApi:
            "assignPermissionToRole assignRoleToUser createPermission createRole deleteDeviceResourceSelection deleteDeviceSelection deletePermission deleteRole evaluatePermission getDeviceRestriction health listPermissions listRolePermissions listRoles listUserRoles listUserRolesAcrossApplications openapiJson putDeviceRestriction putDeviceSelection revokePermissionFromRole revokeRoleFromUser version",
        SuperRoutesReplicationApi: "replicationAdmission selectedResources",
    },
    storage: {
        DefaultApi: "health openapiJson upgradeSocket version",
        ResourcesApi:
            "createDatabase createFileSystem deleteDatabase deleteFileSystem getDatabase getFileSystem listDatabases listFileSystems",
        ResourcesResidencyApi: "getFileSystemResidency putFileSystemResidency",
    },
};

function fixture(service, run) {
    const workspace = mkdtempSync(path.join(tmpdir(), `${service}-generator-`));
    const directory = path.join(workspace, `${service}-client`);
    const source = service === "storage" ? "src/generated" : "src";
    try {
        mkdirSync(path.join(directory, source, "apis"), { recursive: true });
        writeFileSync(
            path.join(workspace, "biome.json"),
            readFileSync(path.resolve(import.meta.dirname, "../biome.json")),
        );
        writeFileSync(
            path.join(directory, source, "apis/previous.ts"),
            "previous REST client\n",
        );
        writeFileSync(
            path.join(directory, source, "index.ts"),
            "previous index\n",
        );
        if (service === "storage") {
            writeFileSync(
                path.join(directory, "src/index.ts"),
                "existing WebSocket client\n",
            );
        }
        writeFileSync(
            path.join(directory, "biome.json"),
            readFileSync(
                path.resolve(
                    import.meta.dirname,
                    `../packages/${service}-client/biome.json`,
                ),
            ),
        );
        const cli = path.join(directory, "pnpm");
        writeFileSync(
            cli,
            `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const source = ${JSON.stringify(source)};
if (args[1] === 'biome') {
  const out = args.at(-1);
  if (!path.basename(path.dirname(out)).startsWith('.openapi-generation-')) process.exit(90);
  if (fs.readFileSync(path.join(process.cwd(), source, 'apis/previous.ts'), 'utf8') !== 'previous REST client\\n') process.exit(91);
  if (fs.readFileSync(path.join(path.dirname(out), 'biome.json'), 'utf8') !== fs.readFileSync(path.join(process.cwd(), 'biome.json'), 'utf8')) process.exit(92);
  if (process.env.FAKE_MODE === 'format-failure') process.exit(23);
  if (process.env.GENERATOR_TEST_BIOME) {
    const result = require('node:child_process').spawnSync(process.env.GENERATOR_TEST_BIOME, args.slice(2), {stdio: 'inherit'});
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
  fs.writeFileSync(path.join(out, 'formatted.ts'), 'export {};\\n');
  process.exit(0);
}
const out = args[args.indexOf('-o') + 1];
fs.mkdirSync(path.join(out, 'apis'), {recursive: true});
fs.mkdirSync(path.join(out, 'models'), {recursive: true});
for (const file of ['index.ts', 'runtime.ts', 'models/index.ts']) {
  fs.writeFileSync(path.join(out, file), 'export {};\\n');
}
const contract = ${JSON.stringify(contracts[service])};
for (const [group, operations] of Object.entries(contract)) {
  if (group === process.env.FAKE_MISSING_GROUP) continue;
  const methods = operations.split(' ').filter(op => op !== process.env.FAKE_MISSING_OPERATION).map(op => '  async ' + op + '() {}').join('\\n');
  fs.writeFileSync(path.join(out, 'apis', group + '.ts'), 'export class ' + group + ' {\\n' + methods + '\\n}\\n');
}
fs.writeFileSync(path.join(out, 'apis/index.ts'), Object.keys(contract).map(group => 'export * from "./' + group + '.js";').join('\\n'));
if (process.env.FAKE_MODE === 'invalid-typescript') fs.writeFileSync(path.join(out, 'runtime.ts'), 'export const = ;');
if (process.env.FAKE_MISSING_FILE) fs.rmSync(path.join(out, process.env.FAKE_MISSING_FILE));
if (process.env.FAKE_EMPTY_FILE) fs.writeFileSync(path.join(out, process.env.FAKE_EMPTY_FILE), '');
if (process.env.FAKE_MODE === 'generation-failure') process.exit(17);
`,
        );
        chmodSync(cli, 0o755);
        const invoke = (extra = {}, selectedService = service) =>
            spawnSync(process.execPath, [generator, selectedService], {
                cwd: directory,
                env: {
                    ...process.env,
                    npm_execpath: cli,
                    OPENAPI_SPEC_URL:
                        "http://127.0.0.1:1/unreachable/openapi.json",
                    FAKE_MODE: "",
                    FAKE_MISSING_GROUP: "",
                    FAKE_MISSING_OPERATION: "",
                    FAKE_MISSING_FILE: "",
                    FAKE_EMPTY_FILE: "",
                    ...extra,
                },
                encoding: "utf8",
                timeout: 10000,
            });
        const preserved = () => {
            assert.equal(
                readFileSync(
                    path.join(directory, source, "apis/previous.ts"),
                    "utf8",
                ),
                "previous REST client\n",
            );
            assert.equal(
                readFileSync(path.join(directory, source, "index.ts"), "utf8"),
                "previous index\n",
            );
            assert.deepEqual(readdirSync(path.join(directory, source)).sort(), [
                "apis",
                "index.ts",
            ]);
        };
        run({ directory, source, invoke, preserved });
        assert.deepEqual(
            readdirSync(workspace).sort(),
            ["biome.json", `${service}-client`].sort(),
        );
        if (service === "storage") {
            assert.equal(
                readFileSync(path.join(directory, "src/index.ts"), "utf8"),
                "existing WebSocket client\n",
            );
            assert.deepEqual(readdirSync(path.join(directory, "src")).sort(), [
                "generated",
                "index.ts",
            ]);
        }
        assert.deepEqual(readdirSync(directory).sort(), [
            "biome.json",
            "pnpm",
            "src",
        ]);
    } finally {
        rmSync(workspace, { recursive: true, force: true });
    }
}

test("Unknown services cannot bypass the completeness contract through object properties", () => {
    fixture("idp", ({ invoke, preserved }) => {
        const result = invoke({}, "constructor");
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /Choose the idp, management or storage/);
        preserved();
    });
});

for (const [service, contract] of Object.entries(contracts)) {
    test(`${service} fixture inventory matches current Rust OpenAPI registrations`, () => {
        const router = readFileSync(
            path.resolve(
                import.meta.dirname,
                `../crates/${service}-server/src/router/openapi_router.rs`,
            ),
            "utf8",
        );
        const operations = [
            ...router.matchAll(/\.routes\(routes!\((\w+)\)\)/g),
        ].map((match) => match[1]);
        if (service === "storage") {
            const paths = router.match(/paths\(([\s\S]*?)\),/)[1];
            operations.push(
                ...paths
                    .split(",")
                    .map((route) => route.trim().split("::").at(-1)),
            );
        }
        const camelCase = (operation) =>
            operation.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
        assert.deepEqual(
            Object.values(contract)
                .flatMap((operations) => operations.split(" "))
                .sort(),
            [...new Set(operations.map(camelCase))].sort(),
        );
    });
    test(`${service} rejects invalid staged TypeScript with the existing Biome binary`, {
        skip: !process.env.GENERATOR_TEST_BIOME,
    }, () => {
        fixture(service, ({ invoke, preserved }) => {
            const result = invoke({ FAKE_MODE: "invalid-typescript" });
            assert.notEqual(result.status, 0);
            assert.match(result.stderr, /OpenAPI formatting failed/);
            assert.match(result.stderr, /runtime\.ts:\d+:\d+ parse/);
            preserved();
        });
    });
    for (const [name, env, message] of [
        ["missing URL", { OPENAPI_SPEC_URL: "" }, /Set OPENAPI_SPEC_URL/],
        [
            "missing pnpm path",
            { npm_execpath: "" },
            /Run this generator through pnpm/,
        ],
        [
            "generator launch failure",
            { npm_execpath: "/nonexistent-openapi-test-pnpm" },
            /ENOENT/,
        ],
        [
            "failed generation after partial output",
            { FAKE_MODE: "generation-failure" },
            /OpenAPI generation failed with exit code 17/,
        ],
    ]) {
        test(`${service} preserves sources on ${name}`, () => {
            fixture(service, ({ invoke, preserved }) => {
                const result = invoke(env);
                assert.notEqual(result.status, 0);
                assert.match(result.stderr, message);
                preserved();
            });
        });
    }
    for (const file of [
        "index.ts",
        "runtime.ts",
        "apis/index.ts",
        "models/index.ts",
    ]) {
        for (const mode of ["FAKE_MISSING_FILE", "FAKE_EMPTY_FILE"]) {
            test(`${service} rejects ${mode} ${file}`, () => {
                fixture(service, ({ invoke, preserved }) => {
                    const result = invoke({ [mode]: file });
                    assert.notEqual(result.status, 0);
                    assert.match(
                        result.stderr,
                        /missing or empty required generated file/,
                    );
                    preserved();
                });
            });
        }
    }
    test(`${service} preserves sources when staged formatting fails`, () => {
        fixture(service, ({ invoke, preserved }) => {
            const result = invoke({ FAKE_MODE: "format-failure" });
            assert.notEqual(result.status, 0);
            assert.match(
                result.stderr,
                /OpenAPI formatting failed with exit code 23/,
            );
            preserved();
        });
    });
    test(`${service} publishes complete formatted output and removes obsolete sources`, () => {
        fixture(service, ({ directory, source, invoke }) => {
            const result = invoke();
            assert.equal(result.status, 0, result.stderr);
            assert.equal(
                readFileSync(
                    path.join(directory, source, "formatted.ts"),
                    "utf8",
                ),
                "export {};\n",
            );
            assert.deepEqual(
                readdirSync(path.join(directory, source, "apis")).sort(),
                [
                    ...Object.keys(contract).map((group) => `${group}.ts`),
                    "index.ts",
                ].sort(),
            );
        });
    });
    for (const [group, operations] of Object.entries(contract)) {
        test(`${service} rejects missing API group ${group}`, () => {
            fixture(service, ({ invoke, preserved }) => {
                const result = invoke({ FAKE_MISSING_GROUP: group });
                assert.notEqual(result.status, 0);
                assert.match(
                    result.stderr,
                    new RegExp(`missing required API group ${group}`),
                );
                preserved();
            });
        });
        for (const operation of operations.split(" ")) {
            test(`${service} rejects missing operation ${operation} in ${group}`, () => {
                fixture(service, ({ invoke, preserved }) => {
                    const result = invoke({
                        FAKE_MISSING_OPERATION: operation,
                    });
                    assert.notEqual(result.status, 0);
                    assert.match(
                        result.stderr,
                        new RegExp(
                            `missing required operation ${operation}\\b`,
                        ),
                    );
                    preserved();
                });
            });
        }
    }
}

test("IdP rejects the stale contract missing transferDevice without replacing sources", () => {
    fixture("idp", ({ invoke, preserved }) => {
        const result = invoke({ FAKE_MISSING_OPERATION: "transferDevice" });
        assert.notEqual(result.status, 0);
        assert.match(
            result.stderr,
            /missing required operation transferDevice/,
        );
        preserved();
    });
});
