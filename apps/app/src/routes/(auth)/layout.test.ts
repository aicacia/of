import { isHttpError, isRedirect } from "@sveltejs/kit";
import { render } from "svelte/server";
import { beforeEach, expect, it, vi } from "vitest";

const host = vi.hoisted(() => ({
    token: { access_token: "session", iss: "https://installation.test" } as
        | { access_token: string; iss?: string }
        | undefined,
    clear: vi.fn(),
    returnTo: vi.fn(),
    goto: vi.fn(),
    native: true,
    installation: { issuer: "https://installation.test" },
}));
vi.mock("@tauri-apps/api/core", () => ({
    isTauri: () => host.native,
    invoke: async () => host.installation,
}));
vi.mock("$app/navigation", () => ({ goto: host.goto }));
vi.mock("$app/paths", () => ({ resolve: (path: string) => path }));
vi.mock("$app/state", () => ({
    page: {
        url: new URL("https://app.test/devices?view=local"),
        status: 503,
        error: {
            message:
                "Authentication service unavailable. Your session has been preserved. Retry when the service is reachable.",
        },
    },
}));
vi.mock("$env/dynamic/public", () => ({
    env: { PUBLIC_LIDP_BASE_URL: "https://node.test/idp" },
}));
vi.mock("$lib/common/state/afterSigninRedirect.svelte", () => ({
    afterSigninRedirect: { setURL: host.returnTo },
}));
vi.mock("$lib/common/state/oidc.svelte", () => ({
    ensureOidcClientId: async () => "client",
    getOidcClient: () => ({
        getStoredTokenResponse: () => host.token,
        clearStoredTokenResponse: () => {
            host.clear();
            host.token = undefined;
        },
    }),
}));
vi.mock("$lib/common/state/managementClient.svelte", () => ({
    ensureTauriManagementApiUrl: async () => {},
}));
vi.mock("$lib/common/state/localhostBaseUrl.svelte", () => ({
    loadLocalhostBaseUrl: async () => "https://node.test",
    ensureLocalhostBaseUrl: async () => "https://node.test",
}));

// Host/session storage is substituted; the IdP state, token exchange and userinfo client are real.
const fetchApi = vi.fn();
vi.stubGlobal("fetch", fetchApi);
const { load } = await import("./+layout");
const event = {
    parent: async () => ({}),
    url: new URL("https://app.test/devices?view=local"),
} as Parameters<typeof load>[0];

beforeEach(() => {
    vi.clearAllMocks();
    fetchApi.mockReset();
    host.native = true;
    host.token = { access_token: "session", iss: "https://installation.test" };
});
function respond(failure: () => Promise<Response>, endpoint = "userinfo") {
    fetchApi.mockImplementation(async (url: string) => {
        if (url.endsWith(`/${endpoint}`)) return failure();
        if (url.endsWith("/oauth2/token"))
            return Response.json({
                access_token: "owner-token",
                token_type: "Bearer",
            });
        if (url.endsWith("/userinfo"))
            return Response.json({ sub: "local-user", name: "Local User" });
        return Response.json({
            token_endpoint: "https://node.test/idp/oauth2/token",
        });
    });
}

it("preserves the session during local owner unavailability and verifies it on retry", async () => {
    respond(async () => new Response(null, { status: 503 }));
    const failure = await load(event).catch((cause: unknown) => cause);
    expect(isHttpError(failure, 503)).toBe(true);
    expect(failure).toMatchObject({
        body: { message: expect.stringContaining("Retry") },
    });
    expect(host.token?.access_token).toBe("session");
    expect(host.clear).not.toHaveBeenCalled();
    expect(host.returnTo).not.toHaveBeenCalled();
    expect(host.goto).not.toHaveBeenCalled();
    expect(fetchApi).toHaveBeenCalledWith(
        "https://node.test/idp/userinfo",
        expect.objectContaining({
            headers: { Authorization: "Bearer owner-token" },
        }),
    );
    respond(async () =>
        Response.json({ sub: "local-user", name: "Local User" }),
    );
    await expect(load(event)).resolves.toMatchObject({
        userInfo: { sub: "local-user", name: "Local User" },
    });
    expect(host.clear).not.toHaveBeenCalled();
});

it.each(["userinfo", "oauth2/token"])(
    "preserves the session on %s network and server failures",
    async (endpoint) => {
        for (const status of [500, 502, 503, 504]) {
            respond(async () => new Response(null, { status }), endpoint);
            expect(
                isHttpError(
                    await load(event).catch((cause: unknown) => cause),
                    503,
                ),
            ).toBe(true);
        }
        respond(async () => {
            throw new TypeError("Failed to fetch");
        }, endpoint);
        expect(
            isHttpError(
                await load(event).catch((cause: unknown) => cause),
                503,
            ),
        ).toBe(true);
        expect(host.token?.access_token).toBe("session");
        expect(host.clear).not.toHaveBeenCalled();
        expect(host.goto).not.toHaveBeenCalled();
    },
);

it.each(["userinfo", "oauth2/token"])(
    "clears and denies the session after a real %s 401",
    async (endpoint) => {
        respond(async () => new Response(null, { status: 401 }), endpoint);
        const failure = await load(event).catch((cause: unknown) => cause);
        expect(isRedirect(failure)).toBe(true);
        expect(failure).toMatchObject({ status: 302, location: "/signin" });
        expect(host.token).toBeUndefined();
        expect(host.clear).toHaveBeenCalledOnce();
        expect(host.returnTo).toHaveBeenCalledWith(event.url);
    },
);

it("does not treat an explicit invalid_grant as temporary owner unavailability", async () => {
    respond(
        async () => Response.json({ error: "invalid_grant" }, { status: 400 }),
        "oauth2/token",
    );
    expect(isRedirect(await load(event).catch((cause: unknown) => cause))).toBe(
        true,
    );
    expect(host.token).toBeUndefined();
});

it.each([{}, null, { sub: "" }, { sub: 42 }])(
    "denies unverifiable successful userinfo %j without deleting the session",
    async (body) => {
        respond(async () => Response.json(body));
        expect(
            isHttpError(
                await load(event).catch((cause: unknown) => cause),
                502,
            ),
        ).toBe(true);
        expect(host.clear).not.toHaveBeenCalled();
    },
);

it.each(["userinfo", "oauth2/token"])(
    "denies explicit %s 403 rejection",
    async (endpoint) => {
        respond(async () => new Response(null, { status: 403 }), endpoint);
        expect(
            isRedirect(await load(event).catch((cause: unknown) => cause)),
        ).toBe(true);
        expect(host.token).toBeUndefined();
    },
);

it.each(["userinfo", "oauth2/token"])(
    "preserves credentials but denies unclassified %s responses",
    async (endpoint) => {
        for (const response of [
            new Response("not JSON", { status: 400 }),
            Response.json({ error: "invalid_request" }, { status: 400 }),
            new Response(null, { status: 404 }),
            new Response(null, { status: 429 }),
            Response.json({ error: "invalid_grant" }, { status: 500 }),
        ]) {
            respond(async () => response, endpoint);
            expect(
                isHttpError(
                    await load(event).catch((cause: unknown) => cause),
                    response.status >= 500 ? 503 : 502,
                ),
            ).toBe(true);
            expect(host.token?.access_token).toBe("session");
            expect(host.clear).not.toHaveBeenCalled();
        }
    },
);

it("denies malformed userinfo without clearing the session", async () => {
    respond(async () => new Response("not JSON", { status: 200 }));
    expect(
        isHttpError(await load(event).catch((cause: unknown) => cause), 502),
    ).toBe(true);
    expect(host.clear).not.toHaveBeenCalled();
});

it("rechecks authorization after an outage instead of trusting the preserved session", async () => {
    respond(async () => new Response(null, { status: 503 }));
    expect(
        isHttpError(await load(event).catch((cause: unknown) => cause), 503),
    ).toBe(true);
    respond(async () => new Response(null, { status: 401 }));
    expect(isRedirect(await load(event).catch((cause: unknown) => cause))).toBe(
        true,
    );
    expect(host.token).toBeUndefined();
});

it("retains the missing-bearer and other-Installation denial guards", async () => {
    for (const token of [
        undefined,
        { access_token: "session", iss: "https://other.test" },
    ]) {
        host.token = token;
        expect(
            isRedirect(await load(event).catch((cause: unknown) => cause)),
        ).toBe(true);
        expect(host.token).toBeUndefined();
    }
    expect(fetchApi).not.toHaveBeenCalled();
});

it("also preserves web sessions during owner unavailability", async () => {
    host.native = false;
    host.token = { access_token: "web-session" };
    respond(async () => new Response(null, { status: 503 }));
    expect(
        isHttpError(await load(event).catch((cause: unknown) => cause), 503),
    ).toBe(true);
    expect(host.token?.access_token).toBe("web-session");
    expect(host.clear).not.toHaveBeenCalled();
});

it("presents actionable retry outside the failed auth layout without authenticated content", async () => {
    const { default: ErrorPage } = await import("../+error.svelte");
    const { body } = render(ErrorPage);
    expect(body).toContain("Your session has been preserved");
    expect(body).toContain('role="alert"');
    expect(body).toMatch(/<button[^>]*>\s*Retry\s*<\/button>/);
    expect(body).not.toContain("Management");
    expect(body).not.toContain("Sign in");
});
