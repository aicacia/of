<script lang="ts">
    import type { ClientRegistration } from "@aicacia/idp-client";
    import {
        idpAdministration,
        type ClientKey,
    } from "$lib/common/state/idpAdministration";
    import { onMount } from "svelte";
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";
    import { page } from "$app/state";
    import { idpApi } from "$lib/common/state/idpClient.svelte";
    import { notifications } from "$lib/common/state/notifications.svelte";

    const clientId = page.params.clientId;

    let loading = $state(false);
    let saving = $state(false);
    let deleting = $state(false);
    let error = $state<string | null>(null);
    let client = $state<ClientRegistration | null>(null);
    let keysLoading = $state(false);
    let keysError = $state<string | null>(null);
    let keys = $state<ClientKey[]>([]);
    let jwkLoadingKeyId = $state<string | null>(null);
    let jwkError = $state<string | null>(null);
    let jwk = $state<Record<string, unknown> | null>(null);
    let jwkKeyId = $state<string | null>(null);

    let clientName = $state("");
    let clientUri = $state("");
    let logoUri = $state("");
    let policyUri = $state("");
    let tosUri = $state("");

    function formatTimestamp(value?: number | null): string {
        if (value == null) {
            return "-";
        }

        return new Date(value * 1000).toLocaleString();
    }

    function applyClient(currentClient: ClientRegistration) {
        client = currentClient;
        clientName = currentClient.clientName ?? "";
        clientUri = currentClient.clientUri ?? "";
        logoUri = currentClient.logoUri ?? "";
        policyUri = currentClient.policyUri ?? "";
        tosUri = currentClient.tosUri ?? "";
    }

    async function loadClientKeys() {
        keysLoading = true;
        keysError = null;
        try {
            keys = await idpAdministration.listClientKeys({ clientId });
        } catch (cause) {
            console.error(cause);
            keysError =
                cause instanceof Error
                    ? cause.message
                    : "Failed to load client keys";
            notifications.add("Failed to load client keys", "error");
        } finally {
            keysLoading = false;
        }
    }

    async function loadClient() {
        loading = true;
        error = null;

        try {
            const currentClient = await idpApi.getRegister({
                clientId,
            });
            applyClient(currentClient);
            void loadClientKeys();
        } catch (cause) {
            console.error(cause);
            error =
                cause instanceof Error
                    ? cause.message
                    : "Failed to load client";
            notifications.add("Failed to load client", "error");
        } finally {
            loading = false;
        }
    }

    async function onLoadJwk(key: ClientKey) {
        jwkLoadingKeyId = key.id;
        jwkError = null;
        try {
            jwk = key.public_jwk;
            if (!jwk) throw new Error("This key has no public JWK");
            jwkKeyId = key.id;
            notifications.add("JWK loaded", "success");
        } catch (cause) {
            console.error(cause);
            jwk = null;
            jwkKeyId = null;
            jwkError =
                cause instanceof Error ? cause.message : "Failed to load JWK";
            notifications.add("Failed to load JWK", "error");
        } finally {
            jwkLoadingKeyId = null;
        }
    }

    async function onSave() {
        if (!client) {
            return;
        }

        saving = true;
        try {
            await idpApi.putRegister({
                clientId,
                clientRegistration: {
                    ...client,
                    clientName,
                    clientUri: clientUri || undefined,
                    logoUri: logoUri || undefined,
                    policyUri: policyUri || undefined,
                    tosUri: tosUri || undefined,
                },
            });
            notifications.add("Client saved", "success");
            await loadClient();
        } catch (cause) {
            console.error(cause);
            notifications.add("Failed to save client", "error");
        } finally {
            saving = false;
        }
    }

    async function onDeleteClient() {
        if (!confirm("Delete this client?")) {
            return;
        }

        deleting = true;
        try {
            await idpApi.deleteRegister({ clientId });
            notifications.add("Client deleted", "success");
            await goto(resolve("/clients"));
        } catch (cause) {
            console.error(cause);
            notifications.add("Failed to delete client", "error");
        } finally {
            deleting = false;
        }
    }

    onMount(() => {
        void loadClient();
    });
</script>

<div class="flex flex-col gap-4">
    <h1 class="mb-0 text-4xl">Client Detail</h1>

    {#if error}
        <div class="card border border-red-700 text-red-200">{error}</div>
    {:else if loading}
        <div class="card">Loading client...</div>
    {:else if client}
        <div class="flex flex-col gap-4">
            <div class="card secondary flex flex-col gap-3">
                <p class="mb-0 text-sm opacity-70">
                    Client ID: {client.clientId ?? "-"}
                </p>
                <label class="flex flex-col gap-1">
                    <span>Name</span>
                    <input bind:value={clientName} type="text" />
                </label>
                <label class="flex flex-col gap-1">
                    <span>Client URI</span>
                    <input bind:value={clientUri} type="url" />
                </label>
                <label class="flex flex-col gap-1">
                    <span>Logo URI</span>
                    <input bind:value={logoUri} type="url" />
                </label>
                <label class="flex flex-col gap-1">
                    <span>Policy URI</span>
                    <input bind:value={policyUri} type="url" />
                </label>
                <label class="flex flex-col gap-1">
                    <span>Terms of service URI</span>
                    <input bind:value={tosUri} type="url" />
                </label>
                <div class="flex justify-end">
                    <button
                        type="button"
                        class="btn primary"
                        onclick={onSave}
                        disabled={saving || deleting}
                        >{saving ? "Saving..." : "Save"}</button
                    >
                </div>
            </div>

            <div class="card secondary flex flex-col gap-3">
                <h2 class="mb-0 text-2xl">Keys</h2>
                {#if keysError}
                    <div class="card border border-red-700 text-red-200">
                        {keysError}
                    </div>
                {:else if keysLoading}
                    <div class="card">Loading keys...</div>
                {:else if keys.length === 0}
                    <div class="card">No keys found.</div>
                {:else}
                    <div class="overflow-x-auto">
                        <table class="min-w-full border-collapse text-left">
                            <thead>
                                <tr
                                    class="border-b border-gray-300 dark:border-gray-700"
                                >
                                    <th class="px-4 py-3">ID</th>
                                    <th class="px-4 py-3">Name</th>
                                    <th class="px-4 py-3">Derivation path</th>
                                    <th class="px-4 py-3">Hardened</th>
                                    <th class="px-4 py-3">Revoked</th>
                                    <th class="px-4 py-3">Expires</th>
                                    <th class="px-4 py-3">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {#each keys as key (key.id)}
                                    <tr
                                        class="border-b border-gray-200 align-top last:border-b-0 dark:border-gray-800"
                                    >
                                        <td class="px-4 py-3">{key.id}</td>
                                        <td class="px-4 py-3">{key.name}</td>
                                        <td class="px-4 py-3"
                                            >{key.derivation_path}</td
                                        >
                                        <td class="px-4 py-3"
                                            >{key.hardened ? "Yes" : "No"}</td
                                        >
                                        <td class="px-4 py-3"
                                            >{key.revoked_at
                                                ? formatTimestamp(key.revoked_at)
                                                : "Active"}</td
                                        >
                                        <td class="px-4 py-3"
                                            >{key.expires_at
                                                ? formatTimestamp(key.expires_at)
                                                : "No expiry"}</td
                                        >
                                        <td class="px-4 py-3">
                                            <button
                                                type="button"
                                                class="btn secondary"
                                                onclick={() => onLoadJwk(key)}
                                                disabled={jwkLoadingKeyId !==
                                                    null}
                                            >
                                                {jwkLoadingKeyId === key.id
                                                    ? "Loading..."
                                                    : "View JWK"}
                                            </button>
                                        </td>
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    </div>
                {/if}

                {#if jwkError}
                    <div class="card border border-red-700 text-red-200">
                        {jwkError}
                    </div>
                {:else if jwkLoadingKeyId !== null}
                    <div class="card">Loading JWK...</div>
                {:else if jwk && jwkKeyId !== null}
                    <div class="flex flex-col gap-2">
                        <p class="mb-0 text-sm opacity-70">
                            JWK for key {jwkKeyId}
                        </p>
                        <pre
                            class="overflow-x-auto rounded-md border border-gray-300 p-4 text-sm dark:border-gray-700">{JSON.stringify(
                                jwk,
                                null,
                                2,
                            )}</pre>
                    </div>
                {/if}
            </div>

            {#if client.redirectUris && client.redirectUris.length > 0}
                <div class="card secondary">
                    <h2 class="mb-2 text-2xl">Redirect URIs</h2>
                    <ul>
                        {#each client.redirectUris as uri (uri)}
                            <li>{uri}</li>
                        {/each}
                    </ul>
                </div>
            {/if}

            {#if client.allowedScopes && client.allowedScopes.length > 0}
                <div class="card secondary">
                    <h2 class="mb-2 text-2xl">Allowed scopes</h2>
                    <ul>
                        {#each client.allowedScopes as scope (scope)}
                            <li>{scope}</li>
                        {/each}
                    </ul>
                </div>
            {/if}

            <div class="card secondary flex flex-col gap-3">
                <h2 class="mb-0 text-2xl">Danger zone</h2>
                <p class="mb-0 text-sm opacity-80">
                    Deleting this client cannot be undone.
                </p>
                <div class="flex justify-end">
                    <button
                        type="button"
                        class="btn danger"
                        onclick={onDeleteClient}
                        disabled={deleting || saving}
                        >{deleting ? "Deleting..." : "Delete client"}</button
                    >
                </div>
            </div>
        </div>
    {/if}
</div>
