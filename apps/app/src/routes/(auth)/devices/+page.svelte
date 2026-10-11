<script lang="ts">
    import { toDataURL } from "qrcode";
    import { onMount } from "svelte";
    import DevicePolicy from "$lib/common/components/DevicePolicy.svelte";

    import {
        approvePendingNodeJoin,
        rejectPendingNodeJoin,
        pendingNodeJoins,
        nodeJoinAccepting,
        type PendingNodeJoin,
        type DeviceInfo,
        listDevices,
        renameDevice,
        revokeDevice,
    } from "$lib/common/state/devices.svelte";
    import { idpApi } from "$lib/common/state/idpClient.svelte";
    import { notifications } from "$lib/common/state/notifications.svelte";

    let nodeOffers = $state.raw<PendingNodeJoin[]>([]);
    let nodeAccepting = $state(false);
    let nodeError = $state<string | null>(null);
    let nodeBusy = $state(false);
    let nodeLoading = false;

    async function loadNodeOffers() {
        if (nodeLoading) return;
        nodeLoading = true;
        try {
            const [offers, accepting] = await Promise.all([
                pendingNodeJoins(),
                nodeJoinAccepting(),
            ]);
            nodeOffers = offers;
            nodeAccepting = accepting;
            nodeError = null;
        } catch (cause) {
            nodeError = String(cause);
        } finally {
            nodeLoading = false;
        }
    }

    async function setNodeAccepting(accepting: boolean) {
        nodeBusy = true;
        try {
            nodeAccepting = await nodeJoinAccepting(accepting);
            await loadNodeOffers();
        } catch (cause) {
            nodeError = String(cause);
        } finally {
            nodeBusy = false;
        }
    }

    async function decideNodeOffer(offer: PendingNodeJoin, approve: boolean) {
        if (
            approve &&
            !confirm(
                `Approve ${offer.request.name} as an equal Node in ${offer.request.installation}? Verify the authenticated endpoint and independent public signer shown below.`,
            )
        )
            return;
        nodeBusy = true;
        try {
            if (approve) await approvePendingNodeJoin(offer.offer_id);
            else await rejectPendingNodeJoin(offer.offer_id);
            await loadNodeOffers();
        } catch (cause) {
            nodeError = String(cause);
        } finally {
            nodeBusy = false;
        }
    }

    let devices = $state<DeviceInfo[]>([]);
    let loading = $state(false);
    let error = $state<string | null>(null);
    let deviceEndpointId = $state<string | null>(null);
    let editingId = $state<string | null>(null);
    let editingName = $state("");
    let publicIdQr = $state<string | null>(null);

    const initialLoading = $derived(!error && loading && devices.length === 0);
    const empty = $derived(!error && !loading && devices.length === 0);
    const hasDevices = $derived(!error && devices.length > 0);
    function formatTimestamp(value: number): string {
        return new Date(value * 1000).toLocaleString();
    }

    function shortValue(value: string): string {
        return value.length > 20
            ? `${value.slice(0, 10)}…${value.slice(-8)}`
            : value;
    }

    async function loadDevices() {
        if (loading) return;
        loading = true;
        error = null;
        try {
            devices = await listDevices();
        } catch (cause) {
            console.error(cause);
            error =
                cause instanceof Error
                    ? cause.message
                    : "Failed to load devices";
        } finally {
            loading = false;
        }
    }

    async function onCopy(value: string, label: string) {
        try {
            await navigator.clipboard.writeText(value);
            notifications.add(`${label} copied`, "success");
        } catch {
            notifications.add(`Could not copy ${label.toLowerCase()}`, "error");
        }
    }

    function onStartRename(device: DeviceInfo) {
        editingId = device.id;
        editingName = device.name;
    }

    async function onRename(device: DeviceInfo) {
        if (!editingName.trim()) {
            return;
        }
        try {
            await renameDevice(device.id, editingName.trim());
            editingId = null;
            notifications.add("Device renamed", "success");
            await loadDevices();
        } catch (cause) {
            console.error(cause);
            notifications.add("Failed to rename device", "error");
        }
    }

    async function onRevoke(device: DeviceInfo) {
        if (
            !confirm(
                `Revoke ${device.name}? This stops future synchronization.`,
            )
        ) {
            return;
        }
        try {
            await revokeDevice(device.id);
            notifications.add("Device revoked", "success");
            await loadDevices();
        } catch (cause) {
            console.error(cause);
            notifications.add("Failed to revoke device", "error");
        }
    }

    onMount(() => {
        void idpApi
            .device()
            .then(async (device) => {
                deviceEndpointId = device.publicKey;
                publicIdQr = await toDataURL(device.publicKey);
            })
            .catch(console.error);
        void loadDevices();
        void loadNodeOffers();
        const timer = setInterval(() => {
            if (nodeBusy) return;
            void loadDevices();
            void loadNodeOffers();
        }, 5000);
        return () => {
            clearInterval(timer);
        };
    });
</script>

<div class="flex flex-col gap-4">
    <div class="flex items-center justify-between">
        <h1 class="mb-0 text-4xl">Devices</h1>
        <div class="flex gap-2">
            <button
                type="button"
                class="btn secondary"
                onclick={() => void loadDevices()}
                disabled={loading}>Refresh</button
            >
        </div>
    </div>

    <DevicePolicy {devices} />

    <section class="flex flex-col gap-2" aria-labelledby="node-joining-heading">
        <h2 id="node-joining-heading">Equal-Node joining</h2>
        <p>
            Approval enrolls an independent Node signer. Public bootstrap must
            still complete; this does not grant Storage access.
        </p>
        <button
            type="button"
            class="btn secondary"
            disabled={nodeBusy}
            onclick={() => void setNodeAccepting(!nodeAccepting)}
        >
            {nodeAccepting ? "Stop accepting Node joins" : "Accept Node joins"}
        </button>
        <button
            type="button"
            class="btn secondary"
            disabled={nodeBusy}
            onclick={() => void loadNodeOffers()}>Refresh Node offers</button
        >
        {#if nodeError}<p role="alert">{nodeError}</p>{/if}
        {#each nodeOffers as offer (offer.offer_id)}
            <article class="flex flex-col gap-2">
                <h3>{offer.request.name}</h3>
                <dl>
                    <dt>Installation</dt>
                    <dd class="break-all">{offer.request.installation}</dd>
                    <dt>Authenticated endpoint</dt>
                    <dd class="break-all">{offer.authenticated_endpoint}</dd>
                    <dt>Member</dt>
                    <dd class="break-all">{offer.request.member_id}</dd>
                    <dt>Approving endpoint</dt>
                    <dd class="break-all">{offer.request.approving_peer}</dd>
                    <dt>Independent public signer</dt>
                    <dd>
                        <pre
                            class="whitespace-pre-wrap break-all">{JSON.stringify(
                                offer.request.public_signer,
                                null,
                                2,
                            )}</pre>
                    </dd>
                </dl>
                <div class="flex gap-2">
                    <button
                        type="button"
                        class="btn primary"
                        disabled={nodeBusy}
                        onclick={() => void decideNodeOffer(offer, true)}
                        >Approve equal Node</button
                    >
                    <button
                        type="button"
                        class="btn secondary"
                        disabled={nodeBusy}
                        onclick={() => void decideNodeOffer(offer, false)}
                        >Reject</button
                    >
                </div>
            </article>
        {/each}
    </section>

    {#if deviceEndpointId}
        <section class="card flex flex-col gap-3">
            <h2>Local Node endpoint</h2>
            <code class="break-all">{deviceEndpointId}</code>
            <button
                class="btn secondary"
                onclick={() =>
                    deviceEndpointId &&
                    void onCopy(deviceEndpointId, "Endpoint ID")}
                >Copy endpoint ID</button
            >
            {#if publicIdQr}<img
                    class="h-64 w-64 bg-white p-2"
                    src={publicIdQr}
                    alt="Local Node endpoint QR code"
                />{/if}
            <p>
                Use this endpoint on the joining Node. Enable equal-Node joining
                above separately; copying does not open admission.
            </p>
        </section>
    {/if}

    {#if error}<div class="card border border-red-700 text-red-200">
            {error}
        </div>{/if}
    {#if initialLoading}<div class="card">Loading devices...</div>{/if}

    {#if empty}
        <div class="card secondary">
            <h2 class="mb-0 text-2xl">No devices yet</h2>
        </div>
    {/if}

    {#if hasDevices}
        <div class="card secondary overflow-x-auto p-0">
            <table class="min-w-full border-collapse text-left">
                <thead>
                    <tr class="border-b border-gray-300 dark:border-gray-700">
                        <th class="px-4 py-3">Name</th>
                        <th class="px-4 py-3">State</th>
                        <th class="px-4 py-3">Public key</th>
                        <th class="px-4 py-3">Updated</th>
                        <th class="px-4 py-3">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {#each devices as device (device.id)}
                        <tr
                            class="border-b border-gray-200 align-top last:border-b-0 dark:border-gray-800"
                        >
                            <td class="px-4 py-3">
                                {#if editingId === device.id}
                                    <form
                                        class="flex gap-2"
                                        onsubmit={(event) => {
                                            event.preventDefault();
                                            void onRename(device);
                                        }}
                                    >
                                        <input
                                            bind:value={editingName}
                                            type="text"
                                            aria-label="Device name"
                                        />
                                        <button
                                            type="submit"
                                            class="btn secondary">Save</button
                                        >
                                    </form>
                                {:else}
                                    {device.name}
                                {/if}
                            </td>
                            <td class="px-4 py-3">{device.state}</td>
                            <td class="px-4 py-3"
                                ><code title={device.publicKey}
                                    >{shortValue(device.publicKey)}</code
                                ></td
                            >
                            <td class="px-4 py-3"
                                >{formatTimestamp(device.updatedAt)}</td
                            >
                            <td class="px-4 py-3">
                                {#if device.state !== "revoked"}
                                    <div class="flex gap-2">
                                        <button
                                            type="button"
                                            class="btn secondary"
                                            onclick={() =>
                                                onStartRename(device)}
                                            >Rename</button
                                        >
                                        {#if deviceEndpointId !== null && device.publicKey !== deviceEndpointId}
                                            <button
                                                type="button"
                                                class="btn secondary"
                                                onclick={() =>
                                                    void onRevoke(device)}
                                                >Revoke</button
                                            >
                                        {/if}
                                    </div>
                                {/if}
                            </td>
                        </tr>
                    {/each}
                </tbody>
            </table>
        </div>
    {/if}
</div>
