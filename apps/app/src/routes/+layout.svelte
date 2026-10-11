<script lang="ts" module>
    import "./layout.css";
</script>

<script lang="ts">
    import { getTheme } from "@aicacia/svelte-headless";
    import { Settings } from "@lucide/svelte";
    import { isTauri } from "@tauri-apps/api/core";
    import { onMount } from "svelte";
    import { resolve } from "$app/paths";
    import favicon from "$lib/assets/favicon.svg";
    import ConfigForm from "$lib/common/components/ConfigForm.svelte";
    import Modal from "$lib/common/components/Modal.svelte";
    import Notifications from "$lib/common/components/Notifications.svelte";
    import { m } from "$lib/paraglide/messages";
    import { handleDeepLink } from "$lib/common/util/handleDeepLink";
    import type { LayoutProps } from "./$types";

    let { children }: LayoutProps = $props();
    let configForm = $state<ConfigForm>();
    let configModal = $state<Modal>();

    function showConfig() {
        configForm?.reset();
        configModal?.show();
    }

    $effect(() => {
        if (getTheme() === "dark") {
            document.body.classList.add("dark");
            return;
        }

        document.body.classList.remove("dark");
    });

    onMount(() => {
        document.body.classList.add("hydrated");

        if (!isTauri()) {
            return;
        }

        let onOpenUrlUnlistenFn: (() => void) | undefined;

        import("@tauri-apps/plugin-deep-link").then(({ onOpenUrl }) =>
            onOpenUrl(handleDeepLink).then((unlisten) => {
                onOpenUrlUnlistenFn = unlisten;
            }),
        );

        return () => {
            onOpenUrlUnlistenFn?.();
        };
    });
</script>

<svelte:head>
    <link rel="icon" href={favicon} />
    <link
        rel="manifest"
        crossorigin="use-credentials"
        href={resolve("/manifest.json")}
    />
</svelte:head>

{@render children()}

<button
    type="button"
    class="btn secondary icon fixed right-4 bottom-4 z-10 rounded-full shadow-lg"
    aria-label={m.env_config()}
    title={m.env_config()}
    onclick={showConfig}
>
    <Settings aria-hidden="true" />
</button>

<Modal bind:this={configModal} title={m.env_config()}>
    <ConfigForm bind:this={configForm} onSaved={() => configModal?.close()} />
    {#if isTauri()}
        <a
            class="btn secondary"
            href={resolve("/setup/installation")}
            onclick={() => configModal?.close()}
            >Installation setup / reset this local Node</a
        >
    {/if}
</Modal>

<Notifications />
