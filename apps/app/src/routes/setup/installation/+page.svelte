<script lang="ts">
    import { invoke, isTauri } from "@tauri-apps/api/core";
    import { onMount } from "svelte";
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";
    import { getOidcClient } from "$lib/common/state/oidc.svelte";
    import { resetDevice } from "$lib/common/state/setupClient.svelte";

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
    let revocationPeer = $state("");
    let revocationStatus = $state("");
    type ResetTarget = {
        member_id: string;
        issuer: string;
        status: "pending" | "acknowledged";
    };
    let revocationTargets = $state.raw<ResetTarget[]>([]);
    let revocationMember = $state("");
    let peerBearer = $state("");
    async function loadRevocationTargets() {
        revocationTargets = await invoke<ResetTarget[]>(
            "pending_reset_revocations",
        );
        revocationMember ||=
            revocationTargets.find((target) => target.status === "pending")
                ?.member_id ?? "";
    }
    let busy = $state(false);
    let loading = $state(true);
    let error = $state("");

    onMount(() => {
        if (!isTauri()) {
            loading = false;
            return;
        }
        void loadRevocationTargets().catch((cause) => {
            error = String(cause);
        });
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

    async function recoverReferences() {
        busy = true;
        error = "";
        try {
            await invoke("recover_reset_references");
            error =
                "Deletion references recovered. Damaged files were archived. This does not restore trust; explicitly retry reset.";
        } catch (cause) {
            error = String(cause);
        } finally {
            busy = false;
        }
    }

    async function revokeOnPeer() {
        const bearer =
            peerBearer ||
            getOidcClient().getStoredTokenResponse()?.access_token;
        if (!bearer) {
            error =
                "Sign in with an authorized User session before revoking on a peer.";
            return;
        }
        if (
            !confirm(
                `Revoke this Node's signer and Device on trusted peer ${revocationPeer}?`,
            )
        )
            return;
        busy = true;
        error = "";
        revocationStatus = "";
        try {
            await invoke("revoke_reset_on_peer", {
                peerApi: revocationPeer,
                bearer,
                memberId: revocationMember,
            });
            await loadRevocationTargets();
            revocationStatus =
                "The surviving peer acknowledged signer and Device revocation. Other peers learn it through ordinary scoped security synchronization. Local data and secrets are still retained.";
        } catch (cause) {
            error = String(cause);
        } finally {
            peerBearer = "";
            busy = false;
        }
    }

    async function reset() {
        busy = true;
        error = "";
        try {
            await resetDevice();
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
            {:else if data.stage === "ready"}
                <p role="status">
                    This Node completed local setup and is ready to use offline.
                    Local completion does not sign you in or grant permissions.
                </p>
                <a class="btn" href={resolve("/signin")}>Sign in</a>
            {:else if data.stage === "device"}
                <p role="status">
                    Installation setup is complete. Continue to Device setup to
                    finish configuring this local Node.
                </p>
                <a class="btn" href={resolve("/setup/device")}
                    >Continue Device setup</a
                >
            {:else if data.stage === "installation"}
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
                <p>
                    Offline local reset does not revoke membership on surviving
                    peers. When an authorized User session and trusted peer are
                    available, revoke there first or retry after reset using the
                    retained public member reference. This uses no persisted
                    bearer and never treats a local reset as remote
                    acknowledgement.
                </p>
                <label
                    >Revocation target
                    <select bind:value={revocationMember} disabled={busy}>
                        <option value="">Select retained member</option>
                        {#each revocationTargets as target (target.member_id)}
                            <option value={target.member_id}
                                >{target.member_id} — {target.issuer} ({target.status})</option
                            >
                        {/each}
                    </select>
                </label>
                <label
                    >Authorized peer User access token (optional while signed
                    in)
                    <input
                        type="password"
                        bind:value={peerBearer}
                        autocomplete="off"
                        disabled={busy}
                    />
                </label>
                <p>
                    This transient token is sent only to the explicitly selected
                    trusted HTTPS peer after its Installation issuer matches. It
                    is cleared after the attempt and never stored with the reset
                    record.
                </p>
                <label
                    >Trusted surviving peer IdP URL<input
                        type="url"
                        bind:value={revocationPeer}
                        placeholder="https://peer.example/idp"
                        disabled={busy}
                    /></label
                >
                <button
                    onclick={revokeOnPeer}
                    disabled={busy || !revocationPeer || !revocationMember}
                    >Revoke on surviving peer</button
                >
                {#if revocationStatus}<p role="status">
                        {revocationStatus}
                    </p>{/if}
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
                <button
                    onclick={recoverReferences}
                    disabled={busy || confirmation !== "RESET"}
                    >Recover deletion references from durable backup</button
                >
                <p>
                    Recovery is reset-only: it preserves damaged evidence and
                    does not restore readiness, regenerate a key, or create new
                    trust. Without a valid durable backup, it fails closed.
                </p>
            </details>
            {#if error}<p role="alert">{error}</p>{/if}
        {/if}
    </div>
</div>
