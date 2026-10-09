<script lang="ts">
    import {
        idpAdministration,
        type Application,
    } from "$lib/common/state/idpAdministration";
    import { onMount } from "svelte";
    import { resolve } from "$app/paths";

    import { notifications } from "$lib/common/state/notifications.svelte";

    const limit = 25;

    let loading = $state(false);
    let creating = $state(false);
    let error = $state<string | null>(null);
    let applications = $state<Application[]>([]);
    let offset = $state(0);

    let name = $state("");
    let uri = $state("");
    let description = $state("");

    function formatTimestamp(value: number): string {
        return new Date(value * 1000).toLocaleString();
    }

    async function loadApplications() {
        loading = true;
        error = null;

        try {
            applications = await idpAdministration.listApplications({
                offset,
                limit,
            });
        } catch (cause) {
            console.error(cause);
            error =
                cause instanceof Error
                    ? cause.message
                    : "Failed to load applications";
            notifications.add("Failed to load applications", "error");
        } finally {
            loading = false;
        }
    }

    async function onCreateApplication(event: SubmitEvent) {
        event.preventDefault();

        if (!name.trim()) {
            notifications.add("Application name is required", "error");
            return;
        }

        if (!uri.trim()) {
            notifications.add("Application URI is required", "error");
            return;
        }

        creating = true;
        try {
            await idpAdministration.createApplication({
                applicationRegistration: {
                    name: name.trim(),
                    uri: uri.trim(),
                    description: description.trim() || undefined,
                },
            });
            name = "";
            uri = "";
            description = "";
            offset = 0;
            notifications.add("Application created", "success");
            await loadApplications();
        } catch (cause) {
            console.error(cause);
            notifications.add("Failed to create application", "error");
        } finally {
            creating = false;
        }
    }

    async function onPrev() {
        if (offset < limit || loading || creating) {
            return;
        }

        offset -= limit;
        await loadApplications();
    }

    async function onNext() {
        if (loading || creating) {
            return;
        }

        offset += limit;
        await loadApplications();
    }

    onMount(() => {
        void loadApplications();
    });
</script>

<div class="flex flex-col gap-4">
    <div class="flex items-center justify-between">
        <h1 class="mb-0 text-4xl">Applications</h1>
        <p class="mb-0 text-sm opacity-70">Offset: {offset}</p>
    </div>

    <form
        class="card secondary flex flex-col gap-3"
        onsubmit={onCreateApplication}
    >
        <h2 class="mb-0 text-2xl">Create application</h2>
        <label class="flex flex-col gap-1">
            <span>Name</span>
            <input bind:value={name} type="text" required />
        </label>
        <label class="flex flex-col gap-1">
            <span>URI</span>
            <input bind:value={uri} type="text" required />
        </label>
        <label class="flex flex-col gap-1">
            <span>Description</span>
            <textarea bind:value={description} rows="3"></textarea>
        </label>
        <div class="flex justify-end">
            <button
                type="submit"
                class="btn primary"
                disabled={creating || loading}
                >{creating ? "Creating..." : "Create application"}</button
            >
        </div>
    </form>

    {#if error}
        <div class="card border border-red-700 text-red-200">{error}</div>
    {:else if loading}
        <div class="card">Loading applications...</div>
    {:else if applications.length === 0}
        <div class="card">No applications found.</div>
    {:else}
        <div class="card secondary overflow-x-auto p-0">
            <table class="min-w-full border-collapse text-left">
                <thead>
                    <tr class="border-b border-gray-300 dark:border-gray-700">
                        <th class="px-4 py-3">ID</th>
                        <th class="px-4 py-3">Name</th>
                        <th class="px-4 py-3">URI</th>
                        <th class="px-4 py-3">Description</th>
                        <th class="px-4 py-3">Updated</th>
                    </tr>
                </thead>
                <tbody>
                    {#each applications as application (application.id)}
                        <tr
                            class="border-b border-gray-200 align-top last:border-b-0 dark:border-gray-800"
                        >
                            <td class="px-4 py-3">
                                <a
                                    href={resolve(
                                        `/applications/${application.id}`,
                                    )}>{application.id}</a
                                ></td
                            >
                            <td class="px-4 py-3">{application.name}</td>
                            <td class="px-4 py-3">
                                <a
                                    href={resolve(
                                        `/applications/${application.id}`,
                                    )}>{application.uri}</a
                                >
                            </td>
                            <td class="px-4 py-3"
                                >{application.description ?? "-"}</td
                            >
                            <td class="px-4 py-3"
                                >{formatTimestamp(application.updated_at)}</td
                            >
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    {/if}

    <div class="flex items-center justify-end gap-2">
        <button
            type="button"
            class="btn secondary"
            onclick={onPrev}
            disabled={loading || creating || offset === 0}>Prev</button
        >
        <button
            type="button"
            class="btn secondary"
            onclick={onNext}
            disabled={loading || creating}>Next</button
        >
    </div>
</div>
