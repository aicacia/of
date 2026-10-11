import { isHttpError } from "@sveltejs/kit";
import { render } from "svelte/server";
import { beforeEach, expect, it, vi } from "vitest";

const host = vi.hoisted(() => ({
  native: true,
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => host.native,
  invoke: host.invoke,
}));

vi.mock("$app/navigation", () => ({ goto: vi.fn() }));
vi.mock("$app/paths", () => ({ resolve: (path: string) => path }));
vi.mock("$lib/common/state/oidc.svelte", () => ({ getOidcClient: vi.fn() }));

const { load } = await import("./+page");
const { default: Installation } = await import("./+page.svelte");

it.each([
  [
    "ready",
    "/signin",
    "Local completion does not sign you in or grant permissions.",
  ],
  ["device", "/setup/device", "Continue Device setup"],
])(
  "shows %s completion navigation without recreating the Installation",
  (stage, href, message) => {
    const { body } = render(Installation, { props: { data: { stage } } });
    expect(body).toContain(`href="${href}"`);
    expect(body).toContain(message);
    expect(body).not.toContain("<form");
    expect(body).not.toContain("Create local Node");
    expect(body).not.toContain("Request approval and join");
    expect(body).toContain("Type RESET to confirm");
    expect(body).toMatch(
      /<button[^>]*disabled[^>]*>Reset \/ retry pending reset<\/button>/,
    );
    expect(host.invoke).not.toHaveBeenCalled();
  },
);

it("shows only the desktop restriction on the web", () => {
  host.native = false;
  const { body } = render(Installation, {
    props: { data: { stage: "desktop-only" } },
  });
  expect(body).toContain("Installation is available only in the desktop app.");
  expect(body).not.toContain("Reset this local Node");
  expect(body).not.toContain("<form");
});

it.each([null, undefined, "unknown", "desktop-only", { stage: "ready" }])(
  "denies invalid local setup evidence %j rather than redirecting to completion",
  async (stage) => {
    host.invoke.mockResolvedValue(stage);
    const failure = await load().catch((cause: unknown) => cause);
    expect(isHttpError(failure)).toBe(true);
    expect(failure).toMatchObject({ status: 503 });
  },
);

it.each(["installation", "unavailable"])(
  "preserves the existing %s setup state",
  async (stage) => {
    host.invoke.mockResolvedValue(stage);
    await expect(load()).resolves.toEqual({ stage });
    expect(host.invoke.mock.calls).toEqual([["get_setup_stage"]]);
  },
);

it("denies native setup controls on the web without reading local evidence", async () => {
  host.native = false;
  await expect(load()).resolves.toEqual({ stage: "desktop-only" });
  expect(host.invoke).not.toHaveBeenCalled();
});

it("does not turn a local evidence failure into readiness or a redirect", async () => {
  const failure = new Error("Local secure storage unavailable");
  host.invoke.mockRejectedValue(failure);
  await expect(load()).rejects.toBe(failure);
});

beforeEach(() => {
  host.native = true;
  host.invoke.mockReset();
});

it("keeps a locally ready Node's Installation reset page reachable without signing in", async () => {
  host.invoke.mockResolvedValue("ready");
  await expect(load()).resolves.toEqual({ stage: "ready" });
  expect(host.invoke.mock.calls).toEqual([["get_setup_stage"]]);
});

it("keeps Device completion reachable from the Installation reset page", async () => {
  host.invoke.mockResolvedValue("device");
  await expect(load()).resolves.toEqual({ stage: "device" });
  expect(host.invoke.mock.calls).toEqual([["get_setup_stage"]]);
});
