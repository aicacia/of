import { flushSync, mount, unmount } from "svelte";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import DevicePolicy from "./DevicePolicy.svelte";
import ResourceResidency from "./ResourceResidency.svelte";

const owner = vi.hoisted(() => ({ select: vi.fn(), deselect: vi.fn() }));
vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true }));
vi.mock("$lib/common/state/localhostBaseUrl.svelte", () => ({
    ensureLocalhostBaseUrl: async () => "https://localhost:4100",
}));
vi.mock("$lib/common/state/managementClient.svelte", () => ({
    managementApi: {
        putDeviceSelection: owner.select,
        deleteDeviceResourceSelection: owner.deselect,
    },
}));

const filesystemId = "01900000-0000-7000-8000-000000000003";
let component: ReturnType<typeof mount>;
let target: HTMLDivElement;
const fetchApi = vi.fn();

beforeEach(() => {
    target = document.createElement("div");
    document.body.append(target);
    fetchApi.mockReset();
    owner.select.mockReset();
    owner.deselect.mockReset().mockResolvedValue(undefined);
    vi.stubGlobal("fetch", fetchApi);
    vi.stubGlobal(
        "confirm",
        vi.fn(() => true),
    );
});
afterEach(async () => {
    if (component) await unmount(component);
    target.remove();
    vi.unstubAllGlobals();
});

function field(label: string) {
    const element = [...target.querySelectorAll("label")]
        .find((element) => element.textContent?.includes(label))
        ?.querySelector<HTMLInputElement | HTMLSelectElement>("input, select");
    if (!element) throw new Error(`Missing field: ${label}`);
    return element;
}
function enter(label: string, value: string) {
    const element = field(label);
    element.value = value;
    element.dispatchEvent(
        new Event(element.tagName === "SELECT" ? "change" : "input", {
            bubbles: true,
        }),
    );
    flushSync();
}
function button(text: string) {
    const element = [...target.querySelectorAll("button")].find(
        (element) => element.textContent === text,
    );
    if (!element) throw new Error(`Missing button: ${text}`);
    return element;
}

it.each(["full", "passthrough"])(
    "drives %s Apply through pending, cleanup error and acknowledgement",
    async (mode) => {
        component = mount(ResourceResidency, {
            target,
            props: { filesystemId },
        });
        flushSync();
        enter("Requested mode", mode);
        enter(
            "Storage-filesystem User access token",
            "current-filesystem-token",
        );
        const reply = Promise.withResolvers<Response>();
        fetchApi.mockReturnValueOnce(reply.promise);
        button("Apply local Residency").click();
        flushSync();
        await vi.waitFor(() => expect(fetchApi).toHaveBeenCalledTimes(1));
        expect(target.querySelector("fieldset")?.disabled).toBe(true);
        expect(target.querySelector('[role="status"]')).toBeNull();
        button("Apply local Residency").click();
        expect(fetchApi).toHaveBeenCalledTimes(1);

        reply.resolve(
            Response.json({ error: "cleanup_pending" }, { status: 409 }),
        );
        await vi.waitFor(() =>
            expect(
                target.querySelector('[role="alert"]')?.textContent,
            ).toContain("No success is claimed"),
        );
        expect(target.textContent).toContain(
            "Resource denial does not reset this Node's completed setup.",
        );
        expect(target.querySelector("fieldset")?.disabled).toBe(false);
        expect(field("Storage-filesystem User access token").value).toBe("");
        expect(button("Apply local Residency").disabled).toBe(true);
        expect(target.querySelector('[role="status"]')).toBeNull();

        enter("Storage-filesystem User access token", "fresh-filesystem-token");
        fetchApi.mockResolvedValueOnce(new Response(null, { status: 204 }));
        button("Apply local Residency").click();
        await vi.waitFor(() =>
            expect(
                target.querySelector('[role="status"]')?.textContent,
            ).toContain(`Storage acknowledged local ${mode}`),
        );
        expect(target.textContent).toContain(
            "no content or cleanup readiness is inferred.",
        );
        expect(target.textContent).not.toContain(
            "Current owner-reported local mode:",
        );
        expect(target.querySelector('[role="alert"]')).toBeNull();
        expect(field("Storage-filesystem User access token").value).toBe("");
        expect(button("Apply local Residency").disabled).toBe(true);
        expect(fetchApi).toHaveBeenCalledTimes(2);
    },
);

it("keeps transferred-resource selection pending/denied despite deselection and Full acknowledgements", async () => {
    const deviceId = "01900000-0000-7000-8000-000000000001";
    const applicationId = "01900000-0000-7000-8000-000000000002";
    component = mount(DevicePolicy, {
        target,
        props: {
            devices: [
                {
                    id: deviceId,
                    name: "Approved Device",
                    address: "local",
                    publicKey: "public-test-key",
                    state: "approved",
                    createdAt: 0,
                    updatedAt: 0,
                },
            ],
        },
    });
    flushSync();
    expect(button("Select authorized resource").disabled).toBe(true);
    enter("Device", deviceId);
    enter("Application UUID", applicationId);
    enter("Resource UUID", filesystemId);
    enter("Resource kind", "filesystem");
    button("Deselect exact resource").click();
    await vi.waitFor(() =>
        expect(target.textContent).toContain(
            "Management acknowledged deselection",
        ),
    );
    expect(owner.deselect).toHaveBeenCalledWith({
        deviceId,
        applicationId,
        kind: "filesystem",
        resourceId: filesystemId,
    });

    enter("Storage-filesystem User access token", "filesystem-token");
    fetchApi.mockResolvedValueOnce(new Response(null, { status: 204 }));
    button("Apply local Residency").click();
    await vi.waitFor(() =>
        expect(target.textContent).toContain("Storage acknowledged local full"),
    );
    expect(owner.select).not.toHaveBeenCalled();

    button("Select authorized resource").click();
    await vi.waitFor(() =>
        expect(target.querySelector('[role="alert"]')?.textContent).toContain(
            "independently authorized, resource-scoped Storage token is required",
        ),
    );
    expect(owner.select).not.toHaveBeenCalled();
    expect(target.textContent).not.toContain(
        "Management acknowledged selection",
    );

    enter("Resource-scoped Storage access token", "transferred-resource-token");
    const reply = Promise.withResolvers<void>();
    owner.select.mockReturnValueOnce(reply.promise);
    button("Select authorized resource").click();
    flushSync();
    expect(owner.select).toHaveBeenCalledTimes(1);
    expect(button("Select authorized resource").disabled).toBe(true);
    expect(button("Deselect exact resource").disabled).toBe(true);
    expect(field("Device").disabled).toBe(true);
    expect(field("Resource UUID").disabled).toBe(true);
    expect(target.querySelector('[role="alert"]')).toBeNull();
    expect(target.textContent).not.toContain(
        "Management acknowledged selection",
    );
    button("Select authorized resource").click();
    expect(owner.select).toHaveBeenCalledTimes(1);

    reply.reject(
        new Error("cleanup_pending: transferred resource remains fenced"),
    );
    await vi.waitFor(() =>
        expect(target.querySelector('[role="alert"]')?.textContent).toContain(
            "cleanup_pending",
        ),
    );
    expect(target.textContent).not.toContain(
        "Management acknowledged selection",
    );
    expect(field("Resource-scoped Storage access token").value).toBe("");
    expect(button("Select authorized resource").disabled).toBe(false);
    expect(owner.select).toHaveBeenCalledTimes(1);

    enter("Resource-scoped Storage access token", "fresh-resource-token");
    owner.select.mockResolvedValueOnce(undefined);
    button("Select authorized resource").click();
    await vi.waitFor(() =>
        expect(target.textContent).toContain(
            "Management acknowledged selection",
        ),
    );
    expect(target.querySelector('[role="alert"]')).toBeNull();
    expect(target.textContent).toContain(
        "This is policy state only, not Storage authorization, local-copy cleanup completion, or Residency readiness.",
    );
    expect(field("Resource-scoped Storage access token").value).toBe("");
    expect(owner.select).toHaveBeenLastCalledWith({
        deviceId,
        selectionRequest: {
            applicationId,
            id: filesystemId,
            kind: "filesystem",
            storageAccessToken: "fresh-resource-token",
        },
    });
});
