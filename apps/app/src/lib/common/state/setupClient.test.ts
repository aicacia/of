import { afterEach, beforeEach, expect, it, vi } from "vitest";

const host = vi.hoisted(() => ({
  authority: null as string | null,
  native: true,
  invoke: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => host.native,
  invoke: host.invoke,
}));
vi.mock("./idpClient.svelte", () => ({
  getIdpApiUrl: () => host.authority,
}));
vi.mock("$env/dynamic/public", () => ({
  env: { PUBLIC_URL: "https://app.test" },
}));

const entries = new Map<string, string>();
const storage: Storage = {
  get length() {
    return entries.size;
  },
  key: (index) => [...entries.keys()][index] ?? null,
  getItem: (key) => entries.get(key) ?? null,
  setItem: (key, value) => {
    entries.set(key, value);
  },
  removeItem: (key) => {
    entries.delete(key);
  },
  clear: () => entries.clear(),
};
const fetchApi = vi.fn();

beforeEach(() => {
  vi.resetModules();
  host.authority = null;
  host.native = true;
  host.invoke.mockReset();
  fetchApi.mockReset();
  entries.clear();
  vi.stubGlobal("window", {
    localStorage: storage,
    location: new URL("https://app.test"),
  });
  vi.stubGlobal("fetch", fetchApi);
});
afterEach(() => vi.unstubAllGlobals());

it("resets an incomplete native Node with no OIDC authority or live services", async () => {
  storage.setItem("oidc.token:https://old-node.test:response", "old session");
  storage.setItem(
    "oidc.pkce:https://old-node.test:state:pending",
    "old verifier",
  );
  storage.setItem("idp-api-url", "null");
  const { getOidcClient } = await import("./oidc.svelte");
  expect(() => getOidcClient()).toThrow("Invalid authority URL");
  const { resetDevice } = await import("./setupClient.svelte");
  host.invoke.mockImplementation(async (command) => {
    expect(command).toBe("reset_device");
    expect([...entries.keys()]).toEqual(["idp-api-url"]);
  });

  await expect(resetDevice()).resolves.toBeUndefined();
  expect(host.invoke.mock.calls).toEqual([["reset_device"]]);
  expect(fetchApi).not.toHaveBeenCalled();
});

it("clears the existing native memory session and PKCE state and invalidates desktop client identity", async () => {
  host.authority = "https://node.test/idp";
  host.invoke.mockResolvedValueOnce("old-client");
  const { ensureOidcClientId, getOidcClient } = await import("./oidc.svelte");
  expect(await ensureOidcClientId()).toBe("old-client");
  expect(await ensureOidcClientId()).toBe("old-client");
  const client = getOidcClient();
  client.setToken({ access_token: "session", refresh_token: "refresh" });
  fetchApi.mockResolvedValue(
    Response.json({
      authorization_endpoint: "https://node.test/idp/oauth2/authorize",
    }),
  );
  await client.getAuthorizationUrl({ state: "pending" });
  expect(client.getStoredTokenResponse()?.access_token).toBe("session");
  storage.setItem("oidc.token:https://old-node.test:response", "old session");
  storage.setItem("oidc.pkce:https://node.test/idp:last", "old verifier");
  storage.setItem("unrelated", "keep");
  host.authority = null;
  fetchApi.mockClear();
  host.invoke.mockImplementation(async (command) => {
    if (command === "get_desktop_client_id") return "new-client";
    expect(command).toBe("reset_device");
    expect(client.getStoredTokenResponse()).toBeNull();
    expect([...entries]).toEqual([["unrelated", "keep"]]);
  });

  const { resetDevice } = await import("./setupClient.svelte");
  await resetDevice();
  await expect(
    client.handleSigninCallback(
      new URL("https://app.test/callback?code=old-code&state=pending"),
    ),
  ).rejects.toMatchObject({ code: "INVALID_STATE" });
  expect(await ensureOidcClientId()).toBe("new-client");
  expect(host.invoke.mock.calls).toEqual([
    ["get_desktop_client_id"],
    ["reset_device"],
    ["get_desktop_client_id"],
  ]);
  expect(fetchApi).not.toHaveBeenCalled();
});

it("propagates a real native reset failure and permits an explicit retry", async () => {
  const failure = new Error(
    "Local secret deletion failed; reset remains pending",
  );
  host.invoke.mockRejectedValueOnce(failure).mockResolvedValueOnce(undefined);
  const { resetDevice } = await import("./setupClient.svelte");
  await expect(resetDevice()).rejects.toBe(failure);
  await expect(resetDevice()).resolves.toBeUndefined();
  expect(host.invoke.mock.calls).toEqual([["reset_device"], ["reset_device"]]);
  expect(fetchApi).not.toHaveBeenCalled();
});

it.each(["installation", "device", "ready", "unavailable"])(
  "obtains durable native setup stage %s independently of HTTP listener availability",
  async (stage) => {
    host.invoke.mockResolvedValue(stage);
    const { getSetupStage } = await import("./setupClient.svelte");
    expect(await getSetupStage()).toBe(stage);
    expect(host.invoke.mock.calls).toEqual([["get_setup_stage"]]);
    expect(fetchApi).not.toHaveBeenCalled();
  },
);

it("does not manufacture readiness when native setup evidence is unavailable", async () => {
  const failure = new Error("setup manifest is invalid");
  host.invoke.mockRejectedValue(failure);
  const { getSetupStage } = await import("./setupClient.svelte");
  await expect(getSetupStage()).rejects.toBe(failure);
  expect(fetchApi).not.toHaveBeenCalled();
});

it("does not swallow native persistent session clearing failures", async () => {
  const failure = new Error("Session storage unavailable");
  vi.stubGlobal("window", {
    get localStorage() {
      throw failure;
    },
  });
  const { resetDevice } = await import("./setupClient.svelte");
  await expect(resetDevice()).rejects.toBe(failure);
  expect(host.invoke).not.toHaveBeenCalled();
});

it.each([false, true])(
  "preserves authority-scoped web token clearing with an existing client: %s",
  async (existing) => {
    host.native = false;
    host.authority = "https://node.test/idp/";
    storage.setItem("oidc.token:https://node.test/idp:response", "session");
    storage.setItem("oidc.token:https://other.test:response", "other session");
    storage.setItem(
      "oidc.pkce:https://node.test/idp:state:pending",
      "verifier",
    );
    const { clearOidcSession, getOidcClient } = await import("./oidc.svelte");
    const client = existing ? getOidcClient() : undefined;
    clearOidcSession();
    expect(
      storage.getItem("oidc.token:https://node.test/idp:response"),
    ).toBeNull();
    expect(client?.getStoredTokenResponse() ?? null).toBeNull();
    expect([...entries]).toEqual([
      ["oidc.token:https://other.test:response", "other session"],
      ["oidc.pkce:https://node.test/idp:state:pending", "verifier"],
    ]);
    expect(host.invoke).not.toHaveBeenCalled();
    expect(fetchApi).not.toHaveBeenCalled();
  },
);
