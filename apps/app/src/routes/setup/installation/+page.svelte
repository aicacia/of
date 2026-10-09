<script lang="ts">
    import { invoke, isTauri } from "@tauri-apps/api/core";
    import { onMount } from "svelte";
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";

    let { data }: { data: { stage: string } } = $props();
    type Intent = {
        purpose: "create" | "join";
        issuer: string;
        peer?: string;
        name?: string;
    };
    let purpose = $state<"create" | "join">("create");
    let pinned = $state(false);
    let name = $state("");
    let password = $state("");
    let issuer = $state("");
    let peer = $state("");
    let confirmation = $state("");
    let busy = $state(false);
    let loading = $state(true);
    let error = $state("");

    onMount(() => {
        if (!isTauri()) {
            loading = false;
            return;
        }
        invoke<Intent | null>("get_setup_intent")
            .then((intent) => {
                if (intent) {
                    purpose = intent.purpose;
                    issuer = intent.issuer;
                    peer = intent.peer ?? "";
                    name = intent.name ?? "";
                    pinned = true;
                }
            })
            .catch((cause) => {
                error = String(cause);
            })
            .finally(() => {
                loading = false;
            });
    });

    async function provision(event: SubmitEvent) {
        event.preventDefault();
        busy = true;
        error = "";
        try {
            if (purpose === "join") {
                await invoke("join_installation", { issuer, peer, name });
            } else {
                await invoke("provision_initial_administrator", {
                    name,
                    password,
                });
            }
            await goto(resolve("/setup/device"));
        } catch (cause) {
            error = cause instanceof Error ? cause.message : String(cause);
            try {
                const intent = await invoke<Intent | null>("get_setup_intent");
                pinned = intent !== null;
                if (intent) {
                    purpose = intent.purpose;
                    issuer = intent.issuer;
                    peer = intent.peer ?? "";
                    if (intent.name) name = intent.name;
                }
            } catch {
                /* Keep the original setup error and allow explicit reset. */
            }
        } finally {
            password = "";
            busy = false;
        }
    }

    async function retryRuntime() {
        busy = true;
        error = "";
        try {
            await invoke("retry_local_runtime");
            await goto(resolve("/setup"));
        } catch (cause) {
            error = String(cause);
        } finally {
            busy = false;
        }
    }

    async function reset() {
        busy = true;
        error = "";
        try {
            await invoke("reset_device");
        } catch (cause) {
            error = String(cause);
        } finally {
            busy = false;
        }
    }
</script>

<div class="flex grow flex-col items-center justify-center">
    <div class="card w-sm">
        <h1>Installation setup</h1>
        {#if !isTauri()}
            <p role="status">
                Installation is available only in the desktop app.
            </p>
        {:else}
            <p>
                Every Node runs IdP, Management and Storage with its own private
                signer. Completed Nodes remain usable offline.
            </p>
            {#if data.stage === "unavailable"}
                <p role="status">
                    This Node completed setup, but its local services are
                    unavailable. Its persisted completion and keys have not been
                    discarded. This is not a peer-disconnection authorization
                    failure.
                </p>
                <button onclick={retryRuntime} disabled={busy || loading}
                    >Retry local services</button
                >
            {:else}
                <form onsubmit={provision}>
                    <label>
                        Installation
                        <select
                            bind:value={purpose}
                            disabled={busy || loading || pinned}
                        >
                            <option value="create"
                                >Create an Installation</option
                            >
                            <option value="join"
                                >Join through a trusted peer</option
                            >
                        </select>
                    </label>
                    {#if purpose === "join"}
                        <p>
                            Verify the canonical issuer and peer endpoint
                            identity out of band. The trusted peer must
                            explicitly approve this Node using an authorized
                            User session; a password or pairing exchange alone
                            is not approval.
                        </p>
                        <label>
                            Canonical Installation issuer
                            <input
                                bind:value={issuer}
                                type="url"
                                required
                                disabled={busy || loading || pinned}
                            />
                        </label>
                        <label>
                            Trusted peer endpoint ID
                            <input
                                bind:value={peer}
                                required
                                disabled={busy || loading || pinned}
                            />
                        </label>
                        <label>
                            Local Node name
                            <input
                                bind:value={name}
                                required
                                maxlength="256"
                                disabled={busy || loading || pinned}
                            />
                        </label>
                    {:else}
                        <p>
                            Restricted local setup creates the initial User and
                            exact administrator grants. No password is sent to a
                            peer.
                        </p>
                        <label>
                            Administrator name
                            <input
                                bind:value={name}
                                autocomplete="username"
                                required
                                disabled={busy || loading}
                            />
                        </label>
                        <label>
                            Password
                            <input
                                bind:value={password}
                                type="password"
                                autocomplete="new-password"
                                required
                                disabled={busy || loading}
                            />
                        </label>
                    {/if}
                    <button type="submit" disabled={busy || loading}>
                        {busy
                            ? "Preparing Node…"
                            : pinned
                              ? "Retry local setup"
                              : purpose === "join"
                                ? "Request approval and join"
                                : "Create local Node"}
                    </button>
                </form>
                {#if busy && purpose === "join"}
                    <button
                        onclick={() =>
                            invoke("cancel_installation_setup").catch(
                                (cause) => {
                                    error = String(cause);
                                },
                            )}>Cancel pending join</button
                    >
                {/if}
            {/if}
            <p role="status">
                Interrupted setup keeps its identities and remains incomplete.
                An unavailable peer can delay join, but does not invalidate a
                completed Node.
            </p>
            <details>
                <summary>Reset this local Node</summary>
                <p>
                    Reset is explicit and works offline. It removes only this
                    Node's data and local keys, not remote data. Failed secret
                    deletion retains retry state. The app exits after successful
                    reset.
                </p>
                <label
                    >Type RESET to confirm <input
                        bind:value={confirmation}
                        autocomplete="off"
                        disabled={busy}
                    /></label
                >
                <button
                    onclick={reset}
                    disabled={busy || confirmation !== "RESET"}
                    >Reset / retry pending reset</button
                >
            </details>
            {#if error}<p role="alert">{error}</p>{/if}
        {/if}
    </div>
</div>
