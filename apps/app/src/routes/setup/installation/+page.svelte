<script lang="ts">
    import { invoke, isTauri } from "@tauri-apps/api/core";

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
            result =
                "The initial administrator is provisioned. Service credentials and unified runtime setup are still incomplete.";
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
                administration permissions. It does not complete service setup.
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
                    {busy ? "Provisioning…" : "Provision administrator"}
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
