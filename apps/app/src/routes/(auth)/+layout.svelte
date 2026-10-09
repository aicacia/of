<script lang="ts">
    import AppWindow from "@lucide/svelte/icons/app-window";
    import Laptop from "@lucide/svelte/icons/laptop";
    import LayoutDashboard from "@lucide/svelte/icons/layout-dashboard";
    import LogOut from "@lucide/svelte/icons/log-out";
    import PanelLeftClose from "@lucide/svelte/icons/panel-left-close";
    import PanelLeftOpen from "@lucide/svelte/icons/panel-left-open";
    import Users from "@lucide/svelte/icons/users";

    import type { Component } from "svelte";
    import { goto } from "$app/navigation";
    import { resolve } from "$app/paths";
    import { page } from "$app/state";
    import { getOidcClient } from "$lib/common/state/oidc.svelte";
    import type { LayoutProps } from "./$types";

    let { children }: LayoutProps = $props();

    let collapsed = $state(false);

    const links: {
        label: string;
        path: string;
        icon: Component;
    }[] = [
        { label: "Dashboard", path: "/", icon: LayoutDashboard },
        { label: "Applications", path: "/applications", icon: AppWindow },
        { label: "Devices", path: "/devices", icon: Laptop },
        { label: "Users", path: "/users", icon: Users },
    ];

    function isActive(path: string): boolean {
        if (path === "/") return page.url.pathname === "/";
        return (
            page.url.pathname === path ||
            page.url.pathname.startsWith(`${path}/`)
        );
    }

    async function onSignOut() {
        getOidcClient().clearStoredTokenResponse();
        await goto(resolve("/signin"));
    }

    function toggleSidebar() {
        collapsed = !collapsed;
    }
</script>

<div class="flex h-full w-full grow overflow-hidden">
    <!-- Sidebar -->
    <aside
        class="flex shrink-0 flex-col border-r border-gray-200 bg-white transition-all duration-200 ease-out dark:border-gray-800 dark:bg-gray-950
           {collapsed ? 'w-17' : 'w-60'}"
    >
        <!-- Header / brand + collapse toggle -->
        <div
            class="flex h-14 items-center border-b border-gray-200 px-3 dark:border-gray-800
             {collapsed ? 'justify-center' : 'justify-between gap-2'}"
        >
            {#if !collapsed}
                <span
                    class="truncate text-sm font-semibold tracking-tight text-gray-900 dark:text-white"
                >
                    Management
                </span>
            {/if}

            <button
                type="button"
                class="btn ghost icon shrink-0 text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white"
                onclick={toggleSidebar}
                aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                title={collapsed ? "Expand" : "Collapse"}
            >
                {#if collapsed}
                    <PanelLeftOpen size={18} />
                {:else}
                    <PanelLeftClose size={18} />
                {/if}
            </button>
        </div>

        <!-- Navigation -->
        <nav class="flex flex-1 flex-col gap-1 p-2">
            {#each links as link (link.path)}
                {@const active = isActive(link.path)}
                <a
                    href={link.path}
                    class="group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors
                 {active
                        ? 'bg-gray-100 text-gray-900 dark:bg-gray-800 dark:text-white'
                        : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900 dark:text-gray-400 dark:hover:bg-gray-900 dark:hover:text-white'}
                 {collapsed ? 'justify-center px-0' : ''}"
                    title={collapsed ? link.label : undefined}
                >
                    <link.icon
                        size={18}
                        class="shrink-0 {active
                            ? 'text-gray-900 dark:text-white'
                            : 'text-gray-500 group-hover:text-gray-700 dark:text-gray-400 dark:group-hover:text-gray-200'}"
                    />
                    {#if !collapsed}
                        <span class="truncate">{link.label}</span>
                    {/if}
                </a>
            {/each}
        </nav>

        <!-- Footer / sign out -->
        <div class="border-t border-gray-200 p-2 dark:border-gray-800">
            <button
                type="button"
                class="group flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-gray-600 transition-colors
               hover:bg-red-50 hover:text-red-600 dark:text-gray-400 dark:hover:bg-red-950/40 dark:hover:text-red-400
               {collapsed ? 'justify-center px-0' : ''}"
                onclick={onSignOut}
                title={collapsed ? "Sign out" : undefined}
            >
                <LogOut
                    size={18}
                    class="shrink-0 text-gray-500 group-hover:text-red-600 dark:text-gray-400 dark:group-hover:text-red-400"
                />
                {#if !collapsed}
                    <span>Sign out</span>
                {/if}
            </button>
        </div>
    </aside>

    <!-- Main content -->
    <section class="flex min-w-0 grow flex-col overflow-hidden">
        <header
            class="flex h-14 items-center justify-end border-b border-gray-200 bg-white px-6 dark:border-gray-800 dark:bg-gray-950"
        >
            <!-- Optional: page title or breadcrumbs can go here -->
        </header>

        <div class="min-h-0 grow overflow-auto p-6">
            {@render children()}
        </div>
    </section>
</div>
