import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
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

test("Storage generation rejects an incomplete contract without replacing either source tree", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "storage-generator-"));
  try {
    mkdirSync(path.join(directory, "src/generated/apis"), { recursive: true });
    writeFileSync(
      path.join(directory, "src/index.ts"),
      "existing WebSocket client\n",
    );
    writeFileSync(
      path.join(directory, "src/generated/apis/DefaultApi.ts"),
      "previous REST client\n",
    );
    const cli = path.join(directory, "pnpm");
    writeFileSync(
      cli,
      `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const out = process.argv[process.argv.indexOf('-o') + 1];
fs.mkdirSync(path.join(out, 'apis'), {recursive: true});
fs.writeFileSync(path.join(out, 'apis/ResourcesResidencyApi.ts'), 'async getFileSystemResidency() {}' + (process.env.FAKE_COMPLETE ? ' async putFileSystemResidency() {}' : ''));
`,
    );
    chmodSync(cli, 0o755);
    const result = spawnSync(process.execPath, [generator, "storage"], {
      cwd: directory,
      env: {
        ...process.env,
        npm_execpath: cli,
        OPENAPI_SPEC_URL: "http://127.0.0.1:1/storage/openapi.json",
      },
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /missing required operation putFileSystemResidency/,
    );
    assert.equal(
      readFileSync(path.join(directory, "src/index.ts"), "utf8"),
      "existing WebSocket client\n",
    );
    assert.equal(
      readFileSync(
        path.join(directory, "src/generated/apis/DefaultApi.ts"),
        "utf8",
      ),
      "previous REST client\n",
    );
    assert.deepEqual(readdirSync(directory).sort(), ["pnpm", "src"]);
    const complete = spawnSync(process.execPath, [generator, "storage"], {
      cwd: directory,
      env: {
        ...process.env,
        npm_execpath: cli,
        OPENAPI_SPEC_URL: "http://127.0.0.1:1/storage/openapi.json",
        FAKE_COMPLETE: "1",
      },
      encoding: "utf8",
    });
    assert.equal(complete.status, 0, complete.stderr);
    assert.equal(
      readFileSync(path.join(directory, "src/index.ts"), "utf8"),
      "existing WebSocket client\n",
    );
    assert.deepEqual(readdirSync(path.join(directory, "src/generated/apis")), [
      "ResourcesResidencyApi.ts",
    ]);
    assert.deepEqual(readdirSync(directory).sort(), ["pnpm", "src"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
