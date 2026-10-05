import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, mkdtemp, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const service = process.argv[2];
const expectedOperations = {
  idp: ["listApplications", "listClientKeys", "listConsents"],
  management: ["listRoles", "createRole", "evaluatePermission"],
}[service];
const specUrl = process.env.OPENAPI_SPEC_URL;
const pnpmPath = process.env.npm_execpath;

if (!expectedOperations) {
  throw new Error("Choose the idp or management client generator");
}
if (!specUrl) {
  throw new Error(
    "Set OPENAPI_SPEC_URL to the live service OpenAPI document URL",
  );
}
if (!pnpmPath) {
  throw new Error(
    "Run this generator through pnpm so its local OpenAPI generator is available",
  );
}

const packageDir = process.cwd();
const sourceDir = path.join(packageDir, "src");
const temporaryDir = await mkdtemp(
  path.join(packageDir, ".openapi-generation-"),
);
const generatedDir = path.join(temporaryDir, "src");
const backupDir = path.join(packageDir, `.src-backup-${randomUUID()}`);

try {
  const result = spawnSync(
    process.execPath,
    [
      pnpmPath,
      "exec",
      "openapi-generator-cli",
      "generate",
      "-i",
      specUrl,
      "-g",
      "typescript-fetch",
      "-o",
      generatedDir,
      "--type-mappings=DateTime=Date",
      "--global-property=apiDocs=false,modelDocs=false",
      "--additional-properties=supportsES6=true,typescriptThreePlus=true,withInterfaces=true,useSingleRequestParameter=true,importFileExtension=.js",
    ],
    { cwd: packageDir, stdio: "inherit" },
  );

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(
      `OpenAPI generation failed with exit code ${result.status}`,
    );
  }

  const generatedApi = await readFile(
    path.join(generatedDir, "apis/DefaultApi.ts"),
    "utf8",
  );
  for (const operation of expectedOperations) {
    if (!generatedApi.includes(`async ${operation}(`)) {
      throw new Error(
        `The ${service} OpenAPI document is missing required operation ${operation}`,
      );
    }
  }

  let movedExistingSource = false;
  try {
    await access(sourceDir);
    await rename(sourceDir, backupDir);
    movedExistingSource = true;
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }

  try {
    await rename(generatedDir, sourceDir);
  } catch (error) {
    if (movedExistingSource) {
      await rename(backupDir, sourceDir);
    }
    throw error;
  }

  if (movedExistingSource) {
    await rm(backupDir, { recursive: true, force: true });
  }
} finally {
  await rm(temporaryDir, { recursive: true, force: true });
}
