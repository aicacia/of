import { afterEach, beforeEach, expect, it, vi } from "vitest";

const host = vi.hoisted(() => ({
    invoke: vi.fn(),
    desktop: true,
    token: "current-user",
}));
vi.mock("@tauri-apps/api/core", () => ({
    invoke: host.invoke,
    isTauri: () => host.desktop,
}));
vi.mock("./oidc.svelte", () => ({
    getOidcClient: () => ({
        getStoredTokenResponse: () => ({ access_token: host.token }),
    }),
}));
vi.mock("./afterSigninRedirect.svelte", () => ({
    afterSigninRedirect: { setURL: vi.fn() },
}));
vi.mock("$app/navigation", () => ({ goto: vi.fn() }));
vi.mock("$app/paths", () => ({ resolve: (path: string) => path }));
vi.mock("$app/state", () => ({ page: { url: new URL("https://app.test") } }));
vi.mock("$env/dynamic/public", () => ({ env: {} }));
const fetchApi = vi.fn();

beforeEach(() => {
    vi.resetModules();
    host.desktop = true;
    host.token = "current-user";
    host.invoke.mockReset().mockResolvedValue("https://localhost:4100");
    fetchApi.mockReset().mockImplementation(async (url: string) => {
        if (url.endsWith("/health")) return new Response(null);
        if (url.endsWith("/oauth2/token"))
            return Response.json({
                access_token: "owner-token",
                token_type: "Bearer",
            });
        if (url.endsWith("/applications")) return Response.json([]);
        if (url.endsWith("/userinfo"))
            return Response.json({ sub: "current-user" });
        if (url.endsWith("/version"))
            return Response.json({ name: "management-server" });
        if (url.endsWith("/restriction"))
            return Response.json({ admin_allowed: true });
        throw new Error(`Unexpected URL: ${url}`);
    });
    vi.stubGlobal("fetch", fetchApi);
});
afterEach(() => vi.unstubAllGlobals());

it("joins owner transport prefixes once and exchanges the distinct Management audience", async () => {
    const idp = await import("./idpClient.svelte");
    const management = await import("./managementClient.svelte");
    const { idpAdministration } = await import("./idpAdministration");
    expect(await idp.ensureTauriIdpApiUrl()).toBe("https://localhost:4100/idp");
    await management.ensureTauriManagementApiUrl();
    expect(management.getManagementApiUrl()).toBe(
        "https://localhost:4100/management",
    );
    await idp.idpApi.userinfo();
    await idpAdministration.listApplications({ offset: 0, limit: 10 });
    await management.managementApi.getDeviceRestriction({
        deviceId: "01900000-0000-7000-8000-000000000001",
    });

    const calls = fetchApi.mock.calls.filter(
        ([url]) => !url.endsWith("/health"),
    );
    expect(calls.map(([url]) => url)).toEqual([
        "https://localhost:4100/idp/oauth2/token",
        "https://localhost:4100/idp/userinfo",
        "https://localhost:4100/idp/oauth2/token",
        "https://localhost:4100/idp/applications",
        "https://localhost:4100/idp/oauth2/token",
        "https://localhost:4100/management/devices/01900000-0000-7000-8000-000000000001/restriction",
    ]);
    expect(
        calls
            .filter(([url]) => url.endsWith("/oauth2/token"))
            .map(([, init]) => {
                const body = init.body as URLSearchParams;
                return [
                    body.get("resource"),
                    body.get("grant_type"),
                    body.get("subject_token"),
                ];
            }),
    ).toEqual([
        [
            "https://localhost:4100/idp",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "current-user",
        ],
        [
            "https://localhost:4100/idp",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "current-user",
        ],
        [
            "idp-management",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "current-user",
        ],
    ]);
    expect(
        calls
            .filter(([url]) => !url.endsWith("/oauth2/token"))
            .map(([, init]) => init.headers.Authorization),
    ).toEqual([
        "Bearer owner-token",
        "Bearer owner-token",
        "Bearer owner-token",
    ]);
});

it("exchanges the current actor independently on each Management operation", async () => {
    const management = await import("./managementClient.svelte");
    await management.ensureTauriManagementApiUrl();
    await management.managementApi.getDeviceRestriction({
        deviceId: "01900000-0000-7000-8000-000000000001",
    });
    host.token = "another-current-user";
    await management.managementApi.getDeviceRestriction({
        deviceId: "01900000-0000-7000-8000-000000000001",
    });
    expect(
        fetchApi.mock.calls
            .filter(([url]) => url.endsWith("/oauth2/token"))
            .map(([, init]) => {
                const body = init.body as URLSearchParams;
                return [body.get("resource"), body.get("subject_token")];
            }),
    ).toEqual([
        ["idp-management", "current-user"],
        ["idp-management", "another-current-user"],
    ]);
});

it("rejects a transport URL as a Management audience without sending a token", async () => {
    const { ownerAccessToken } = await import("./idpClient.svelte");
    await expect(
        ownerAccessToken("https://localhost:4100/management"),
    ).rejects.toThrow("A current IdP or Management owner audience is required");
    expect(fetchApi.mock.calls.map(([url]) => url)).toEqual([
        "https://localhost:4100/idp/health",
    ]);
});

it("keeps configured web owner prefixes without adding desktop service paths", async () => {
    host.desktop = false;
    const idp = await import("./idpClient.svelte");
    const management = await import("./managementClient.svelte");
    idp.setIdpApiUrl("https://node.test/idp");
    management.setManagementApiUrl("https://node.test/management");
    expect(await idp.ensureTauriIdpApiUrl()).toBe("https://node.test/idp");
    await management.ensureTauriManagementApiUrl();
    expect(management.getManagementApiUrl()).toBe(
        "https://node.test/management",
    );
    expect(
        await management.validateManagementApiUrl(
            "https://node.test/management",
        ),
    ).toBe(true);
    expect(fetchApi.mock.calls.map(([url]) => url)).toEqual([
        "https://node.test/management/version",
    ]);
    expect(host.invoke).not.toHaveBeenCalled();
});
