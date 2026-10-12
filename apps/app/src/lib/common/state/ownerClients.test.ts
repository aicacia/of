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
vi.mock("@aicacia/svelte-headless", () => ({
    createStorage: (_key: string, item: unknown) => ({ item }),
}));
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

const deviceId = "01900000-0000-7000-8000-000000000001";
const applicationId = "01900000-0000-7000-8000-000000000002";
const filesystemId = "01900000-0000-7000-8000-000000000003";

async function localResidency(accessToken = "filesystem-user-token") {
    const { ResourcesResidencyApi, StorageOwnerConfiguration } = await import(
        "@aicacia/storage-client"
    );
    const { ensureLocalhostBaseUrl } = await import(
        "./localhostBaseUrl.svelte"
    );
    return new ResourcesResidencyApi(
        new StorageOwnerConfiguration({
            basePath: `${await ensureLocalhostBaseUrl()}/storage`,
            accessToken,
            fetchApi: fetch,
        }),
    );
}

it.each(["full", "passthrough"] as const)(
    "keeps %s pending until acknowledgement, then requires an independent mode read",
    async (mode) => {
        const api = await localResidency();
        const reply = Promise.withResolvers<Response>();
        fetchApi.mockImplementationOnce(() => reply.promise);
        const acknowledged = vi.fn();
        const pending = api
            .putFileSystemResidency(
                { filesystemId, resourceResidency: { mode } },
                { redirect: "error" },
            )
            .then(acknowledged);
        await vi.waitFor(() => expect(fetchApi).toHaveBeenCalledTimes(2));
        expect(acknowledged).not.toHaveBeenCalled();
        expect(fetchApi.mock.calls[1]).toEqual([
            `https://localhost:4100/storage/filesystems/${filesystemId}/residency`,
            expect.objectContaining({
                method: "PUT",
                redirect: "error",
                headers: expect.objectContaining({
                    Authorization: "Bearer filesystem-user-token",
                }),
                body: JSON.stringify({ mode }),
            }),
        ]);
        reply.resolve(new Response(null, { status: 204 }));
        await pending;
        expect(acknowledged.mock.calls).toEqual([[undefined]]);
        expect(fetchApi).toHaveBeenCalledTimes(2);

        fetchApi.mockResolvedValueOnce(Response.json({ mode }));
        await expect(
            api.getFileSystemResidency({ filesystemId }, { redirect: "error" }),
        ).resolves.toEqual({ mode });
        expect(fetchApi.mock.calls[2][1]).toMatchObject({
            method: "GET",
            redirect: "error",
        });
    },
);

it.each(["full", "passthrough"] as const)(
    "rejects cleanup-fenced %s without acknowledgement or automatic retry",
    async (mode) => {
        const api = await localResidency();
        fetchApi.mockResolvedValueOnce(
            Response.json({ error: "cleanup_pending" }, { status: 409 }),
        );
        await expect(
            api.putFileSystemResidency(
                { filesystemId, resourceResidency: { mode } },
                { redirect: "error" },
            ),
        ).rejects.toMatchObject({ response: { status: 409 } });
        expect(fetchApi).toHaveBeenCalledTimes(2);
        expect(host.invoke.mock.calls).toEqual([
            ["get_localhost_server_base_url"],
        ]);
    },
);

it("does not turn deselection or Full acknowledgement into transferred-resource selection readiness", async () => {
    const { SelectionKind } = await import("@aicacia/management-client");
    const management = await import("./managementClient.svelte");
    await management.ensureTauriManagementApiUrl();
    const residency = await localResidency();
    const ownerFetch = fetchApi.getMockImplementation();
    const selectionReply = Promise.withResolvers<Response>();
    let selectionAttempts = 0;
    fetchApi.mockImplementation((url: string, init: RequestInit) => {
        if (url.endsWith("/residency"))
            return Promise.resolve(new Response(null, { status: 204 }));
        if (
            url.endsWith(
                `/selection/${applicationId}/filesystem/${filesystemId}`,
            )
        )
            return Promise.resolve(new Response(null, { status: 204 }));
        if (url.endsWith("/selection")) {
            selectionAttempts += 1;
            return selectionAttempts === 1
                ? selectionReply.promise
                : Promise.resolve(new Response(null, { status: 204 }));
        }
        return ownerFetch?.(url, init);
    });
    await expect(
        management.managementApi.deleteDeviceResourceSelection({
            deviceId,
            applicationId,
            kind: SelectionKind.Filesystem,
            resourceId: filesystemId,
        }),
    ).resolves.toBeUndefined();
    await expect(
        residency.putFileSystemResidency(
            { filesystemId, resourceResidency: { mode: "full" } },
            { redirect: "error" },
        ),
    ).resolves.toBeUndefined();

    const selectionRequest = {
        applicationId,
        id: filesystemId,
        kind: SelectionKind.Filesystem,
        storageAccessToken: "transferred-resource-token",
    };
    const acknowledged = vi.fn();
    const pending = management.managementApi
        .putDeviceSelection({ deviceId, selectionRequest })
        .then(acknowledged);
    const rejection = expect(pending).rejects.toMatchObject({
        response: { status: 409 },
    });
    await vi.waitFor(() => expect(selectionAttempts).toBe(1));
    expect(acknowledged).not.toHaveBeenCalled();
    selectionReply.resolve(
        Response.json({ error: "cleanup_pending" }, { status: 409 }),
    );
    await rejection;
    expect(acknowledged).not.toHaveBeenCalled();
    expect(selectionAttempts).toBe(1);

    host.token = "current-transferred-owner";
    await expect(
        management.managementApi.putDeviceSelection({
            deviceId,
            selectionRequest: {
                ...selectionRequest,
                storageAccessToken: "fresh-transferred-resource-token",
            },
        }),
    ).resolves.toBeUndefined();
    const selectionCalls = fetchApi.mock.calls.filter(([url]) =>
        url.endsWith("/selection"),
    );
    expect(selectionCalls.map(([url]) => url)).toEqual([
        `https://localhost:4100/management/devices/${deviceId}/selection`,
        `https://localhost:4100/management/devices/${deviceId}/selection`,
    ]);
    expect(selectionCalls.map(([, init]) => JSON.parse(init.body))).toEqual([
        {
            applicationId,
            id: filesystemId,
            kind: "filesystem",
            storageAccessToken: "transferred-resource-token",
        },
        {
            applicationId,
            id: filesystemId,
            kind: "filesystem",
            storageAccessToken: "fresh-transferred-resource-token",
        },
    ]);
    expect(selectionCalls[1][1].headers.Authorization).toBe(
        "Bearer owner-token",
    );
    const exchanges = fetchApi.mock.calls.filter(([url]) =>
        url.endsWith("/oauth2/token"),
    );
    expect(exchanges.map(([, init]) => init.body.get("subject_token"))).toEqual(
        ["current-user", "current-user", "current-transferred-owner"],
    );
    expect(exchanges.map(([, init]) => init.body.get("resource"))).toEqual([
        "idp-management",
        "idp-management",
        "idp-management",
    ]);
});

it.each([true, false])(
    "renders Residency scope without claiming observed mode or readiness (desktop=%s)",
    async (desktop) => {
        host.desktop = desktop;
        const { render } = await import("svelte/server");
        const { default: ResourceResidency } = await import(
            "../components/ResourceResidency.svelte"
        );
        const { body } = render(ResourceResidency, { props: { filesystemId } });
        expect(body).toContain(
            "Full permits local content operations but does not prove all content is available.",
        );
        expect(body).toContain("requires an authorized reachable Full peer");
        expect(body).toContain("Cleanup fences remain enforced by Storage.");
        expect(body).not.toContain("Current owner-reported local mode:");
        expect(body).not.toContain("Storage acknowledged local");
        expect(body).toMatch(
            /<button[^>]*disabled[^>]*>Apply local Residency<\/button>/,
        );
        if (!desktop) {
            expect(body).toMatch(/<fieldset[^>]*disabled/);
            expect(body).toContain("Unavailable outside the native desktop");
        }
        expect(fetchApi).not.toHaveBeenCalled();
        expect(host.invoke).not.toHaveBeenCalled();
    },
);

it("renders Device policy as owner-authorized mutations, not a ready resource directory", async () => {
    const { render } = await import("svelte/server");
    const { default: DevicePolicy } = await import(
        "../components/DevicePolicy.svelte"
    );
    const { body } = render(DevicePolicy, { props: { devices: [] } });
    expect(body).toContain("signing in or joining does not grant access.");
    expect(body).toContain(
        "Mutation acknowledgements above are not presented as a current selection list.",
    );
    expect(body).toContain(
        "Full/Passthrough Residency controls apply to whole filesystems, not databases.",
    );
    expect(body).toMatch(
        /<button[^>]*disabled[^>]*>Select authorized resource<\/button>/,
    );
    expect(body).not.toContain("Management acknowledged selection");
    expect(fetchApi).not.toHaveBeenCalled();
});
