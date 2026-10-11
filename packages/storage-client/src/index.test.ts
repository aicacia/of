import { afterEach, describe, expect, it, vi } from "vitest";

import { StorageClient } from "./index";

afterEach(() => vi.unstubAllGlobals());

class TestSocket extends EventTarget {
    static OPEN = 1;
    readyState = 1;
    constructor(readonly url: string) {
        super();
    }
    send = vi.fn((message: string) => {
        const request = JSON.parse(message);
        const response =
            request.type === "read"
                ? { type: "read", content: [42] }
                : request.type === "write"
                  ? {
                        type: "written",
                        entry: {
                            name: "secret.json",
                            hash: "hash",
                            size: 1,
                            local: true,
                        },
                    }
                  : { type: "error", code: "invalidRequest" };
        queueMicrotask(() =>
            this.dispatchEvent(
                new MessageEvent("message", { data: JSON.stringify(response) }),
            ),
        );
    });
    close = vi.fn();
}

describe("StorageClient", () => {
    it.each([
        {
            name: "missing-user",
            subject: "",
            response: new Response(null),
            message: "Missing OIDC access token",
        },
        {
            name: "denied-exchange",
            subject: "user-token",
            response: new Response(null, { status: 403 }),
            message: "Storage token exchange failed: 403",
        },
        {
            name: "missing-issued-token",
            subject: "user-token",
            response: Response.json({}),
            message: "Storage token exchange returned no access token",
        },
    ])(
        "does not request a catalog or socket after $name",
        async ({ subject, response, message }) => {
            const fetch = vi
                .fn()
                .mockImplementation(async () => response.clone());
            const WebSocket = vi.fn();
            vi.stubGlobal("WebSocket", WebSocket);
            const client = new StorageClient({
                idpBaseUrl: "https://idp.example/idp",
                storageBaseUrl: "https://storage.example/storage",
                clientId: "password-manager-web",
                bearerToken: () => subject,
                fetch,
            });
            await expect(client.listFileSystems()).rejects.toThrow(message);
            await expect(
                client.openSocket("01900000-0000-7000-8000-000000000001"),
            ).rejects.toThrow(message);
            expect(fetch.mock.calls.map(([url]) => url.href)).toEqual(
                subject
                    ? [
                          "https://idp.example/idp/oauth2/token",
                          "https://idp.example/idp/oauth2/token",
                      ]
                    : [],
            );
            expect(WebSocket).not.toHaveBeenCalled();
        },
    );

    it.each([
        "ftp://idp.example/idp",
        "https://user:password@idp.example/idp",
        "https://idp.example/idp?query=true",
        "https://idp.example/idp#fragment",
    ])(
        "rejects invalid service base %s without transmitting the bearer",
        async (idpBaseUrl) => {
            const fetch = vi.fn();
            const client = new StorageClient({
                idpBaseUrl,
                storageBaseUrl: "https://storage.example/storage",
                clientId: "password-manager-web",
                bearerToken: () => "user-token",
                fetch,
            });
            await expect(client.listFileSystems()).rejects.toThrow();
            expect(fetch).not.toHaveBeenCalled();
        },
    );

    it("surfaces current catalog authorization denial instead of claiming an empty catalog", async () => {
        const fetch = vi
            .fn()
            .mockResolvedValueOnce(
                Response.json({ access_token: "read-token" }),
            )
            .mockResolvedValueOnce(new Response(null, { status: 403 }));
        const client = new StorageClient({
            idpBaseUrl: "https://idp.example/idp",
            storageBaseUrl: "https://storage.example/storage",
            clientId: "password-manager-web",
            bearerToken: () => "user-token",
            fetch,
        });
        await expect(client.listFileSystems()).rejects.toThrow(
            "Filesystem list failed: 403",
        );
        expect(fetch).toHaveBeenCalledTimes(2);
    });
    it.each(["", "/"])(
        "uses write-only filesystem creation with service-base trailing slash %s",
        async (slash) => {
            const fetch = vi
                .fn()
                .mockResolvedValueOnce(
                    Response.json({ access_token: "write-token" }),
                )
                .mockResolvedValueOnce(
                    Response.json(
                        { id: "filesystem-id", name: "Vault" },
                        { status: 201 },
                    ),
                );
            const client = new StorageClient({
                idpBaseUrl: new URL(
                    `https://idp.example/deployment/idp${slash}`,
                ),
                storageBaseUrl: new URL(
                    `https://storage.example/deployment/storage${slash}`,
                ),
                clientId: "password-manager-web",
                bearerToken: () => "user-token",
                fetch,
            });
            expect(await client.createFileSystem("Vault")).toEqual({
                id: "filesystem-id",
                name: "Vault",
            });
            expect(fetch.mock.calls.map(([url]) => url.href)).toEqual([
                "https://idp.example/deployment/idp/oauth2/token",
                "https://storage.example/deployment/storage/filesystems",
            ]);
            const body = fetch.mock.calls[0]?.[1]?.body as URLSearchParams;
            expect(body.get("resource")).toBe("storage:filesystems");
            expect(
                JSON.parse(body.get("authorization_details") ?? "null"),
            ).toEqual([{ type: "storage", actions: ["write"] }]);
            expect(fetch.mock.calls[1]?.[1]).toEqual({
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: "Bearer write-token",
                },
                body: '{"name":"Vault"}',
            });
        },
    );

    it("uses the Storage socket base and sends current read/write requests without a legacy envelope", async () => {
        vi.stubGlobal("WebSocket", TestSocket);
        const fetch = vi
            .fn()
            .mockResolvedValue(Response.json({ access_token: "socket-token" }));
        const client = new StorageClient({
            idpBaseUrl: "https://idp.example/idp",
            storageBaseUrl: "https://storage.example/storage/",
            clientId: "password-manager-web",
            bearerToken: () => "user-token",
            fetch,
        });
        const socket = await client.openSocket(
            "01900000-0000-7000-8000-000000000001",
        );
        expect((socket.socket as unknown as TestSocket).url).toBe(
            "wss://storage.example/storage?access_token=socket-token&filesystem_id=01900000-0000-7000-8000-000000000001",
        );
        expect(fetch.mock.calls[0]?.[0]).toEqual(
            new URL("https://idp.example/idp/oauth2/token"),
        );
        const body = fetch.mock.calls[0]?.[1]?.body as URLSearchParams;
        expect(body.get("resource")).toBe("storage:filesystems");
        expect(JSON.parse(body.get("authorization_details") ?? "null")).toEqual(
            [{ type: "storage", actions: ["read", "write"] }],
        );
        expect(
            await Promise.all([
                socket.request({ type: "read", path: "secrets/secret.json" }),
                socket.request({
                    type: "write",
                    path: "secrets/secret.json",
                    content: [42],
                }),
            ]),
        ).toEqual([
            { type: "read", content: [42] },
            {
                type: "written",
                entry: {
                    name: "secret.json",
                    hash: "hash",
                    size: 1,
                    local: true,
                },
            },
        ]);
        expect(
            (socket.socket as unknown as TestSocket).send.mock.calls,
        ).toEqual([
            ['{"type":"read","path":"secrets/secret.json"}'],
            ['{"type":"write","path":"secrets/secret.json","content":[42]}'],
        ]);
        socket.close();
        expect(
            (socket.socket as unknown as TestSocket).close,
        ).toHaveBeenCalledOnce();
    });
    it("exchanges an access token before listing filesystems", async () => {
        const fetch = vi
            .fn()
            .mockResolvedValueOnce(
                Response.json({ access_token: "storage-token" }),
            )
            .mockResolvedValueOnce(
                Response.json([{ id: "filesystem-id", name: "Vault" }]),
            );
        const client = new StorageClient({
            idpBaseUrl: "https://idp.example/idp",
            storageBaseUrl: "https://storage.example/storage",
            clientId: "password-manager-web",
            bearerToken: () => "user-token",
            fetch,
        });

        await expect(client.listFileSystems()).resolves.toEqual([
            { id: "filesystem-id", name: "Vault" },
        ]);
        const exchange = fetch.mock.calls[0];
        expect(exchange?.[0]).toEqual(
            new URL("https://idp.example/idp/oauth2/token"),
        );
        const body = exchange?.[1]?.body as URLSearchParams;
        expect(body.get("grant_type")).toBe(
            "urn:ietf:params:oauth:grant-type:token-exchange",
        );
        expect(body.get("subject_token")).toBe("user-token");
        expect(body.get("resource")).toBe("storage:filesystems");
        expect(body.has("audience")).toBe(false);
        expect(body.has("scope")).toBe(false);
        expect(body.get("subject_token_type")).toBe(
            "urn:ietf:params:oauth:token-type:access_token",
        );
        expect(fetch.mock.calls[1]?.[0]).toEqual(
            new URL("https://storage.example/storage/filesystems"),
        );
        expect(JSON.parse(body.get("authorization_details") ?? "null")).toEqual(
            [{ type: "storage", actions: ["read"] }],
        );
        expect(fetch.mock.calls[1]?.[1]?.headers).toEqual({
            Authorization: "Bearer storage-token",
        });
    });
});
