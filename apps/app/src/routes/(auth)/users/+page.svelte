<script lang="ts">
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";
    let userId = $state("");
    function openUser(event: SubmitEvent) {
        event.preventDefault();
        if (userId.trim())
            void goto(resolve(`/users/${encodeURIComponent(userId.trim())}`));
    }
</script>

<div class="flex flex-col gap-4">
    <h1>Users</h1>
    <p>The IdP supports authorized lookup by user ID, not a user directory.</p>
    <form class="card flex flex-col gap-3" onsubmit={openUser}>
        <label>User ID<input bind:value={userId} required /></label>
        <button class="btn primary" type="submit">Open user</button>
    </form>
</div>
