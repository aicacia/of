import {
    type FileSystemResource,
    StorageClient,
    type StorageEntry,
    type StorageRequest,
    type StorageResponse,
    type StorageSocket,
} from "@aicacia/storage-client";

import { env } from "$env/dynamic/public";
import { getIdpApiUrl } from "./state/idpClient.svelte";
import { getOidcClient } from "./state/oidc.svelte";

export type {
    FileSystemResource,
    StorageEntry,
    StorageRequest,
    StorageResponse,
    StorageSocket,
};

function client(): StorageClient {
    const idpBaseUrl = getIdpApiUrl();
    if (!idpBaseUrl) throw new Error("LIDP API URL is not configured");
    const storageBaseUrl = env.PUBLIC_STORAGE_BASE_URL;
    if (!storageBaseUrl) throw new Error("Storage API URL is not configured");
    return new StorageClient({
        idpBaseUrl,
        storageBaseUrl,
        clientId: "password-manager-web",
        bearerToken: () => getOidcClient().getAccessToken(),
    });
}

export function listFileSystems(): Promise<FileSystemResource[]> {
    return client().listFileSystems();
}

export function createFileSystem(): Promise<FileSystemResource> {
    return client().createFileSystem("Password Manager");
}

export function openStorageSocket(
    filesystemId: string,
): Promise<StorageSocket> {
    return client().openSocket(filesystemId);
}
