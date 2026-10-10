export { Configuration as StorageOwnerConfiguration } from "./generated/runtime.js";
export { ResourcesResidencyApi } from "./generated/apis/ResourcesResidencyApi.js";
export { ResidencyMode } from "./generated/models/ResidencyMode.js";
export type { ResourceResidency } from "./generated/models/ResourceResidency.js";

export type StorageRequest =
    | { type: "read"; path: string }
    | { type: "write"; path: string; content: number[] }
    | { type: "append"; path: string; content: number[] }
    | { type: "delete"; path: string }
    | { type: "entry"; path: string }
    | { type: "list"; path: string };

export type StorageEntry = {
    name: string;
    hash: string;
    size: number;
    local: boolean;
};

export type StorageResponse =
    | { type: "authenticated" }
    | { type: "read"; content: number[] }
    | { type: "written"; entry: StorageEntry }
    | { type: "appended"; entry: StorageEntry }
    | { type: "deleted" }
    | { type: "entry"; entry: StorageEntry }
    | { type: "listed"; entries: StorageEntry[] }
    | { type: "error"; code: "invalidRequest" | "operationFailed" };

export type FileSystemResource = { id: string; name: string | null };

type TokenResponse = { access_token?: string };

type FetchFunction = (
    input: URL | RequestInfo,
    init?: RequestInit,
) => Promise<Response>;

export type StorageClientOptions = {
    baseUrl: URL | string;
    audience: string;
    clientId: string;
    bearerToken: () => string | Promise<string>;
    fetch?: FetchFunction;
};

export class StorageSocket {
    #queue = Promise.resolve();

    constructor(readonly socket: WebSocket) {}

    request(request: StorageRequest): Promise<StorageResponse> {
        const response = this.#queue.then(async () => {
            const next = receive(this.socket);
            this.socket.send(JSON.stringify({ type: "request", request }));
            return next;
        });
        this.#queue = response.then(
            () => undefined,
            () => undefined,
        );
        return response;
    }

    close(): void {
        this.socket.close();
    }
}

export class StorageClient {
    constructor(private readonly options: StorageClientOptions) {}

    async listFileSystems(): Promise<FileSystemResource[]> {
        const token = await this.exchangeToken(["read"]);
        const response = await this.request("/storage/filesystems", token);
        if (!response.ok) {
            throw new Error(`Filesystem list failed: ${response.status}`);
        }
        return (await response.json()) as FileSystemResource[];
    }

    async createFileSystem(name?: string): Promise<FileSystemResource> {
        const token = await this.exchangeToken(["write"]);
        const response = await this.request("/storage/filesystems", token, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: name ?? null }),
        });
        if (!response.ok) {
            throw new Error(`Filesystem creation failed: ${response.status}`);
        }
        return (await response.json()) as FileSystemResource;
    }

    async openSocket(filesystemId: string): Promise<StorageSocket> {
        if (!filesystemId) {
            throw new Error("Select a filesystem before opening storage");
        }
        const baseUrl = parseUrl(this.options.baseUrl);
        const token = await this.exchangeToken(["read", "write"]);
        const url = new URL("/storage", baseUrl);
        url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
        url.searchParams.set("access_token", token);
        url.searchParams.set("filesystem_id", filesystemId);
        const socket = new WebSocket(url.href);
        await opened(socket);
        return new StorageSocket(socket);
    }

    private async exchangeToken(actions: string[]): Promise<string> {
        const subjectToken = await this.options.bearerToken();
        if (!subjectToken) {
            throw new Error("Missing OIDC access token");
        }
        const body = new URLSearchParams({
            grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
            subject_token: subjectToken,
            subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
            audience: this.options.audience,
            client_id: this.options.clientId,
            authorization_details: JSON.stringify([
                { type: "storage", actions },
            ]),
        });
        const response = await (this.options.fetch ?? fetch)(
            new URL("/oauth2/token", parseUrl(this.options.baseUrl)),
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                body,
            },
        );
        if (!response.ok) {
            throw new Error(
                `Storage token exchange failed: ${response.status}`,
            );
        }
        const result = (await response.json()) as TokenResponse;
        if (!result.access_token) {
            throw new Error("Storage token exchange returned no access token");
        }
        return result.access_token;
    }

    private request(
        path: string,
        token: string,
        init: RequestInit = {},
    ): Promise<Response> {
        return (this.options.fetch ?? fetch)(
            new URL(path, parseUrl(this.options.baseUrl)),
            {
                ...init,
                headers: { ...init.headers, Authorization: `Bearer ${token}` },
            },
        );
    }
}

function parseUrl(value: URL | string): URL {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        throw new Error("LIDP API URL must use HTTP or HTTPS");
    }
    return url;
}

function opened(socket: WebSocket): Promise<void> {
    if (socket.readyState === WebSocket.OPEN) {
        return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
        const cleanup = () => {
            socket.removeEventListener("open", onOpen);
            socket.removeEventListener("error", onError);
        };
        const onOpen = () => {
            cleanup();
            resolve();
        };
        const onError = () => {
            cleanup();
            reject(new Error("Storage socket failed to open"));
        };
        socket.addEventListener("open", onOpen);
        socket.addEventListener("error", onError);
    });
}

function receive(socket: WebSocket): Promise<StorageResponse> {
    return new Promise((resolve, reject) => {
        const cleanup = () => {
            socket.removeEventListener("message", onMessage);
            socket.removeEventListener("close", onClose);
            socket.removeEventListener("error", onError);
        };
        const onMessage = (event: MessageEvent) => {
            cleanup();
            if (typeof event.data !== "string") {
                reject(
                    new Error("Storage socket returned a non-text response"),
                );
                return;
            }
            try {
                resolve(JSON.parse(event.data) as StorageResponse);
            } catch {
                reject(
                    new Error("Storage socket returned an invalid response"),
                );
            }
        };
        const onClose = () => {
            cleanup();
            reject(new Error("Storage socket closed"));
        };
        const onError = () => {
            cleanup();
            reject(new Error("Storage socket failed"));
        };
        socket.addEventListener("message", onMessage);
        socket.addEventListener("close", onClose);
        socket.addEventListener("error", onError);
    });
}
