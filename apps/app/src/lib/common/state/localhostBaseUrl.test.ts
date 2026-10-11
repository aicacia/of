import { afterEach, beforeEach, expect, it, vi } from "vitest";

const native = vi.hoisted(() => ({ invoke: vi.fn(), desktop: true }));
vi.mock("@tauri-apps/api/core", () => ({
    invoke: native.invoke,
    isTauri: () => native.desktop,
}));
const fetchApi = vi.fn();

beforeEach(() => {
    vi.resetModules();
    vi.useFakeTimers();
    native.desktop = true;
    native.invoke.mockReset().mockResolvedValue("https://localhost:4100");
    fetchApi.mockReset();
    vi.stubGlobal("fetch", fetchApi);
});
afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
});

it("keeps an empty Installation discoverable without claiming durable readiness", async () => {
    fetchApi
        .mockResolvedValueOnce(new Response(null, { status: 404 }))
        .mockResolvedValueOnce(Response.json({ stage: "installation" }));
    const { loadLocalhostBaseUrl, getLocalhostBaseUrlCached } = await import(
        "./localhostBaseUrl.svelte"
    );
    expect(await loadLocalhostBaseUrl()).toBe("https://localhost:4100");
    expect(getLocalhostBaseUrlCached()).toBe("https://localhost:4100");
    expect(fetchApi.mock.calls.map(([url]) => url)).toEqual([
        "https://localhost:4100/idp/health",
        "https://localhost:4100/lidp/setup/status",
    ]);
    expect(native.invoke.mock.calls).toEqual([
        ["get_localhost_server_base_url"],
    ]);
});

it("discovers an active IdP listener once for concurrent callers without querying setup readiness", async () => {
    fetchApi.mockResolvedValue(new Response(null));
    const { loadLocalhostBaseUrl, ensureLocalhostBaseUrl } = await import(
        "./localhostBaseUrl.svelte"
    );
    expect(
        await Promise.all([loadLocalhostBaseUrl(), ensureLocalhostBaseUrl()]),
    ).toEqual(["https://localhost:4100", "https://localhost:4100"]);
    expect(fetchApi.mock.calls.map(([url]) => url)).toEqual([
        "https://localhost:4100/idp/health",
    ]);
    expect(native.invoke.mock.calls).toEqual([
        ["get_localhost_server_base_url"],
    ]);
});

it("does not probe native listeners in the web app", async () => {
    native.desktop = false;
    const { loadLocalhostBaseUrl, ensureLocalhostBaseUrl } = await import(
        "./localhostBaseUrl.svelte"
    );
    expect(await loadLocalhostBaseUrl()).toBeNull();
    await expect(ensureLocalhostBaseUrl()).rejects.toThrow(
        "Localhost server URL is not available yet",
    );
    expect(native.invoke).not.toHaveBeenCalled();
    expect(fetchApi).not.toHaveBeenCalled();
});

it.each([{ stage: "ready" }, { stage: "device" }, {}, null])(
    "rejects non-discovery setup status %j",
    async (status) => {
        fetchApi.mockImplementation(async (url: string) =>
            url.endsWith("/health")
                ? new Response(null, { status: 404 })
                : Response.json(status),
        );
        const { loadLocalhostBaseUrl, getLocalhostBaseUrlCached } =
            await import("./localhostBaseUrl.svelte");
        const loading = loadLocalhostBaseUrl();
        await vi.runAllTimersAsync();
        expect(await loading).toBeNull();
        expect(getLocalhostBaseUrlCached()).toBeNull();
    },
);
