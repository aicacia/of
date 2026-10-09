<script lang="ts">
    import { toDataURL } from "qrcode";
    import { onMount } from "svelte";

    import Modal from "$lib/common/components/Modal.svelte";
    import {
        approveDevice,
        approvePendingNodeJoin,
        rejectPendingNodeJoin,
        pendingNodeJoins,
        nodeJoinAccepting,
        type PendingNodeJoin,
        type DeviceInfo,
        getDeviceApprovalPayload,
        getPairingAccepting,
        listDevices,
        requestDevicePairing,
        renameDevice,
        revokeDevice,
    } from "$lib/common/state/devices.svelte";
    import { idpApi } from "$lib/common/state/idpClient.svelte";
    import { notifications } from "$lib/common/state/notifications.svelte";

    interface BarcodeDetectorResult {
        rawValue?: string;
    }

    interface BarcodeDetector {
        detect(source: ImageBitmapSource): Promise<BarcodeDetectorResult[]>;
    }

    interface BarcodeDetectorConstructor {
        new (options?: { formats?: string[] }): BarcodeDetector;
    }

    let nodeOffers = $state.raw<PendingNodeJoin[]>([]);
    let nodeAccepting = $state(false);
    let nodeError = $state<string | null>(null);
    let nodeBusy = $state(false);

    async function loadNodeOffers() {
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
    let pendingPrompt = $state<DeviceInfo | null>(null);
    let editingId = $state<number | null>(null);
    let editingName = $state("");
    let publicIdQr = $state<string | null>(null);
    let pairingAccepting = $state(false);
    let manualPairingName = $state("");
    let manualPublicKey = $state("");
    let startingManualPairing = $state(false);
    let scanning = $state(false);
    let scannerVideo = $state<HTMLVideoElement | undefined>(undefined);
    let scannerStream: MediaStream | null = null;
    let scannerTimer: ReturnType<typeof setInterval> | null = null;
    let addDeviceModal = $state<Modal>();

    const initialLoading = $derived(!error && loading && devices.length === 0);
    const empty = $derived(!error && !loading && devices.length === 0);
    const hasDevices = $derived(!error && devices.length > 0);
    const localDeviceApproved = $derived(
        devices.some(
            (device) =>
                device.state === "approved" &&
                device.publicKey === deviceEndpointId,
        ),
    );

    const supportsScanner = $derived(
        typeof window !== "undefined" && "BarcodeDetector" in window,
    );

    function formatTimestamp(value: number): string {
        return new Date(value * 1000).toLocaleString();
    }

    function shortValue(value: string): string {
        return value.length > 20
            ? `${value.slice(0, 10)}…${value.slice(-8)}`
            : value;
    }

    async function loadDevices() {
        loading = true;
        error = null;
        try {
            const [nextDevices, accepting] = await Promise.all([
                listDevices(),
                getPairingAccepting(),
            ]);
            pairingAccepting = accepting;
            const newlyPending = nextDevices.find(
                (device) =>
                    device.state === "pending" &&
                    !devices.some((current) => current.id === device.id),
            );
            devices = nextDevices;
            if (localDeviceApproved) {
                pendingPrompt ??= newlyPending ?? null;
            }
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
            pairingAccepting = await getPairingAccepting(true);
            await navigator.clipboard.writeText(value);
            notifications.add(`${label} copied`, "success");
        } catch {
            notifications.add(`Could not copy ${label.toLowerCase()}`, "error");
        }
    }

    async function onSetPairingAccepting(accepting: boolean) {
        try {
            pairingAccepting = await getPairingAccepting(accepting);
        } catch {
            notifications.add("Could not update pairing mode", "error");
        }
    }

    async function onStartManualPairing(event: SubmitEvent) {
        event.preventDefault();
        const publicKey = manualPublicKey.trim();
        if (!manualPairingName.trim() || !publicKey) {
            return;
        }
        startingManualPairing = true;
        try {
            const device = await idpApi.device();
            await requestDevicePairing(
                manualPairingName.trim(),
                device.publicKey,
                device.address,
                publicKey,
            );
            addDeviceModal?.close();
            notifications.add("Pairing request sent for approval", "success");
            await loadDevices();
        } catch (cause) {
            console.error(cause);
            notifications.add("Failed to start pairing", "error");
        } finally {
            startingManualPairing = false;
        }
    }

    async function onApprove(device: DeviceInfo) {
        try {
            const payload = await getDeviceApprovalPayload(device.id);
            const { signature } = await idpApi.signDeviceMessage({
                signDeviceMessage: { message: payload },
            });
            await approveDevice(device.id, signature);
            pendingPrompt = null;
            notifications.add("Device approved", "success");
            await loadDevices();
        } catch (cause) {
            console.error(cause);
            notifications.add("Failed to approve device", "error");
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

    function stopScanner() {
        if (scannerTimer) {
            clearInterval(scannerTimer);
            scannerTimer = null;
        }
        scannerStream?.getTracks().forEach((track) => {
            track.stop();
        });
        scannerStream = null;
        scanning = false;
    }

    async function onStartScanner() {
        const BarcodeDetector = (
            window as typeof window & {
                BarcodeDetector?: BarcodeDetectorConstructor;
            }
        ).BarcodeDetector;
        const video = scannerVideo;
        if (!BarcodeDetector || !video) {
            return;
        }

        try {
            const detector = new BarcodeDetector({ formats: ["qr_code"] });
            scannerStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: "environment" },
            });
            video.srcObject = scannerStream;
            await video.play();
            scanning = true;
            scannerTimer = setInterval(() => {
                void detector.detect(video).then((codes) => {
                    const value = codes[0]?.rawValue;
                    if (!value) {
                        return;
                    }
                    manualPublicKey = value;
                    stopScanner();
                });
            }, 500);
        } catch (cause) {
            console.error(cause);
            stopScanner();
            notifications.add("Could not start the QR scanner", "error");
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
            void loadDevices();
            void loadNodeOffers();
        }, 5000);
        return () => {
            clearInterval(timer);
            stopScanner();
        };
    });
</script>

<div class="flex flex-col gap-4">
    <div class="flex items-center justify-between">
        <h1 class="mb-0 text-4xl">Devices</h1>
        <div class="flex gap-2">
            <button
                type="button"
                class="btn primary"
                onclick={() => addDeviceModal?.show()}>Add device</button
            >
            <button
                type="button"
                class="btn secondary"
                onclick={() => void loadDevices()}
                disabled={loading}>Refresh</button
            >
        </div>
    </div>

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

    <Modal bind:this={addDeviceModal} title="Add device">
        {#if supportsScanner}
            <p class="mb-0">
                Scan a device QR code or paste its public ID or endpoint
                address.
            </p>
            <video
                class="max-w-full"
                style:display={scanning ? "block" : "none"}
                bind:this={scannerVideo}
                muted
                playsinline
            ></video>
            {#if scanning}
                <button
                    type="button"
                    class="btn secondary"
                    onclick={stopScanner}>Stop scanner</button
                >
            {:else}
                <button
                    type="button"
                    class="btn primary"
                    onclick={() => void onStartScanner()}>Scan device QR</button
                >
            {/if}
        {/if}

        <form class="flex flex-col gap-2" onsubmit={onStartManualPairing}>
            <p class="mb-0">
                The other device must be online and accepting join requests.
            </p>
            <label class="flex flex-col gap-1">
                <span>Device name</span>
                <input bind:value={manualPairingName} type="text" required />
            </label>
            <label class="flex flex-col gap-1">
                <span>Public ID or endpoint address</span>
                <input bind:value={manualPublicKey} type="text" required />
            </label>
            <button
                type="submit"
                class="btn secondary self-start"
                disabled={startingManualPairing}
                >{startingManualPairing
                    ? "Starting pairing..."
                    : "Start pairing"}</button
            >
        </form>
    </Modal>

    {#if localDeviceApproved}
        <div class="card secondary flex flex-col gap-3">
            <h2 class="mb-0 text-2xl">Pair another device</h2>
            <p class="mb-0">
                Turn on join requests before sharing this device's public ID.
            </p>
            <button
                type="button"
                class="btn secondary self-start"
                onclick={() => void onSetPairingAccepting(!pairingAccepting)}
                >{pairingAccepting
                    ? "Stop accepting join requests"
                    : "Accept join requests"}</button
            >
            <code class="break-all select-all">{deviceEndpointId}</code>
            <button
                type="button"
                class="btn secondary self-start"
                onclick={() =>
                    deviceEndpointId &&
                    void onCopy(deviceEndpointId, "Public key")}
                >Copy public ID and accept requests</button
            >
            {#if publicIdQr}
                <img
                    class="h-64 w-64 self-start bg-white p-2"
                    src={publicIdQr}
                    alt="Device public ID QR code"
                />
            {/if}
        </div>
    {/if}

    {#if pendingPrompt}
        <div class="card secondary flex flex-col gap-3">
            <h2 class="mb-0 text-2xl">Approve new device?</h2>
            <p class="mb-0">{pendingPrompt.name} wants to join your devices.</p>
            <div class="flex justify-end gap-2">
                <button
                    type="button"
                    class="btn secondary"
                    onclick={() => (pendingPrompt = null)}>Not now</button
                >
                <button
                    type="button"
                    class="btn primary"
                    onclick={() =>
                        pendingPrompt && void onApprove(pendingPrompt)}
                    >Approve</button
                >
            </div>
        </div>
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
                                        {#if localDeviceApproved && device.state === "pending"}
                                            <button
                                                type="button"
                                                class="btn primary"
                                                onclick={() =>
                                                    (pendingPrompt = device)}
                                                >Review</button
                                            >
                                        {/if}
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
