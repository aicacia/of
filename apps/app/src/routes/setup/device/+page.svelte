<script lang="ts">
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";
    import { invoke } from "@tauri-apps/api/core";

    let busy = $state(false);
    let error = $state("");

    async function complete() {
        busy = true;
        error = "";
        try {
            await invoke("complete_device_setup");
            await goto(resolve("/signin"));
        } catch (cause) {
            error = cause instanceof Error ? cause.message : String(cause);
        } finally {
            busy = false;
        }
    }
</script>

<div class="flex grow flex-col items-center justify-center">
    <div class="card w-sm">
        <h1>Device setup</h1>
        <p>
            All three local services are ready. Resource selection starts empty.
            Sign in to select locally trusted resources and configure their
            Residency.
        </p>
        <p role="status">
            Unavailable peers do not invalidate this Node's local setup.
            Passthrough content still requires an authorized reachable Full
            peer.
        </p>
        <button onclick={complete} disabled={busy}>
            {busy ? "Saving…" : "Finish Device setup"}
        </button>
        {#if error}<p role="alert">{error}</p>{/if}
    </div>
</div>
