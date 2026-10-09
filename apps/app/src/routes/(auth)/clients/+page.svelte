<script lang="ts">
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";
    let clientId = $state("");
    function openClient(event: SubmitEvent) {
        event.preventDefault();
        if (clientId.trim())
            void goto(
                resolve(`/clients/${encodeURIComponent(clientId.trim())}`),
            );
    }
</script>

<div class="flex flex-col gap-4">
    <h1>Clients</h1>
    <p>
        Create clients from an <a href={resolve("/applications")}>application</a
        >. The IdP supports authorized lookup by client ID, not a client
        directory.
    </p>
    <form class="card flex flex-col gap-3" onsubmit={openClient}>
        <label>Client ID<input bind:value={clientId} required /></label>
        <button class="btn primary" type="submit">Open client</button>
    </form>
</div>
