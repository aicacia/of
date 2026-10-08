<script lang="ts">
    import { invoke, isTauri } from "@tauri-apps/api/core";
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";

    let name = $state("");
    let password = $state("");
    let busy = $state(false);
    let error = $state("");
    let result = $state("");

    async function provision(event: SubmitEvent) {
        event.preventDefault();
        busy = true;
        error = "";
        result = "";

        try {
            await invoke<string>("provision_initial_administrator", {
                name,
                password,
            });
            password = "";
            result = "All local services are ready. Continue to Device Setup.";
            await goto(resolve("/setup/device"));
        } catch (cause) {
            error = cause instanceof Error ? cause.message : String(cause);
        } finally {
            busy = false;
        }
    }
</script>

<div class="flex grow flex-col items-center justify-center">
    <div class="card w-sm">
        <h1>Start installation</h1>
        {#if !isTauri()}
            <p role="status">
                Installation is available only in the desktop app.
            </p>
        {:else}
            <p>
                This creates the first IdP user and grants explicit installation
                administration permissions, an independent local signer, and all
                three local services. Once complete, this Node works offline.
            </p>
            <form onsubmit={provision}>
                <label>
                    Administrator name
                    <input
                        bind:value={name}
                        autocomplete="username"
                        required
                        disabled={busy}
                    />
                </label>
                <label>
                    Password
                    <input
                        bind:value={password}
                        type="password"
                        autocomplete="new-password"
                        required
                        disabled={busy}
                    />
                </label>
                <button type="submit" disabled={busy}>
                    {busy ? "Preparing Node…" : "Create local Node"}
                </button>
            </form>
            {#if error}
                <p role="alert">{error}</p>
            {/if}
            {#if result}
                <p role="status">{result}</p>
            {/if}
        {/if}
    </div>
</div>
