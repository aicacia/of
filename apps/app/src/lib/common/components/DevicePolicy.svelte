<script lang="ts">
  import { SelectionKind, type DeviceRestriction } from "@aicacia/management-client";
  import type { DeviceInfo } from "@aicacia/idp-client";
  import * as v from "valibot";
  import { managementApi } from "$lib/common/state/managementClient.svelte";

  let { devices }: { devices: DeviceInfo[] } = $props();
  let deviceId = $state("");
  let applicationId = $state("");
  let resourceId = $state("");
  let kind = $state<SelectionKind>(SelectionKind.Database);
  let storageAccessToken = $state("");
  let restriction = $state.raw<DeviceRestriction | null>(null);
  let busy = $state(false);
  let error = $state("");
  let status = $state("");
  const uuid = v.pipe(v.string(), v.uuid());

  async function readRestriction() {
    busy = true;
    error = "";
    restriction = null;
    try {
      v.parse(uuid, deviceId);
      restriction = await managementApi.getDeviceRestriction({ deviceId });
    } catch (cause) { error = String(cause); }
    finally { busy = false; }
  }
  async function updateRestriction(allowed: boolean) {
    if (!confirm(`${allowed ? "Allow" : "Restrict"} replication policy for Device ${deviceId}? This is not a resource grant.`)) return;
    busy = true;
    error = "";
    status = "";
    try {
      v.parse(uuid, deviceId);
      await managementApi.putDeviceRestriction({ deviceId, deviceRestriction: { adminAllowed: allowed } });
      restriction = await managementApi.getDeviceRestriction({ deviceId });
      status = "Management acknowledged the restriction. Local-copy retirement may still be pending; no resource is reported ready.";
    } catch (cause) { error = String(cause); }
    finally { busy = false; }
  }
  async function updateSelection(select: boolean) {
    busy = true;
    error = "";
    status = "";
    try {
      for (const id of [deviceId, applicationId, resourceId]) v.parse(uuid, id);
      if (select) {
        if (!storageAccessToken.trim()) throw new Error("An independently authorized, resource-scoped Storage token is required");
        await managementApi.putDeviceSelection({ deviceId, selectionRequest: { applicationId, id: resourceId, kind, storageAccessToken } });
      } else {
        if (!confirm(`Deselect ${kind} ${resourceId} in application ${applicationId}? Local retirement may remain incomplete.`)) return;
        await managementApi.deleteDeviceResourceSelection({ deviceId, applicationId, kind, resourceId });
      }
      status = `Management acknowledged ${select ? "selection" : "deselection"}. This is policy state only, not Storage authorization, local-copy cleanup completion, or Residency readiness.`;
    } catch (cause) { error = String(cause); }
    finally { storageAccessToken = ""; busy = false; }
  }
</script>

<section class="card flex flex-col gap-3" aria-labelledby="device-policy-heading">
  <h2 id="device-policy-heading">Device selections and restrictions</h2>
  <p>These operations use current Management owner APIs. Each request independently enforces its exact User permission and Device/resource owner binding; signing in or joining does not grant access.</p>
  <label>Device
    <select bind:value={deviceId} disabled={busy} onchange={() => { restriction = null; status = ""; }}>
      <option value="">Select a Device</option>
      {#each devices as device (device.id)}<option value={device.id}>{device.name} — {device.id}</option>{/each}
    </select>
  </label>
  <button class="btn secondary" onclick={readRestriction} disabled={busy || !deviceId}>Read current restriction</button>
  {#if restriction}<p>Current administrative replication permission: {restriction.adminAllowed ? "allowed" : "restricted"}.</p>{/if}
  <div class="flex gap-2">
    <button class="btn secondary" onclick={() => updateRestriction(false)} disabled={busy || !deviceId}>Restrict replication</button>
    <button class="btn secondary" onclick={() => updateRestriction(true)} disabled={busy || !deviceId}>Allow replication policy</button>
  </div>
  <form class="flex flex-col gap-3" onsubmit={(event) => { event.preventDefault(); void updateSelection(true); }}>
    <label>Application UUID<input bind:value={applicationId} required disabled={busy} /></label>
    <label>Resource UUID<input bind:value={resourceId} required disabled={busy} /></label>
    <label>Resource kind<select bind:value={kind} disabled={busy}><option value={SelectionKind.Database}>Database</option><option value={SelectionKind.Filesystem}>Filesystem</option></select></label>
    <label>Resource-scoped Storage access token<input type="password" bind:value={storageAccessToken} autocomplete="off" disabled={busy} /></label>
    <p>The Storage token is transient request data, not a saved credential or substitute for the Management User permission. It is cleared after each attempt.</p>
    <div class="flex gap-2">
      <button class="btn primary" type="submit" disabled={busy || !deviceId}>Select authorized resource</button>
      <button class="btn secondary" type="button" onclick={() => updateSelection(false)} disabled={busy || !deviceId || !applicationId || !resourceId}>Deselect exact resource</button>
    </div>
  </form>
  <fieldset disabled aria-describedby="residency-blocker">
    <legend>Local resource Residency</legend>
    <label>Requested mode<select><option>Full</option><option>Passthrough</option></select></label>
    <button class="btn secondary" type="button">Apply local Residency</button>
  </fieldset>
  <p id="residency-blocker" role="status">Incomplete: the composed desktop runtime has no authorized public Residency/retirement handle. No Residency setting is applied or persisted here. Whole-resource cleanup remains fail-closed until owner handle invalidation/removal is supported and reviewed. Full/Passthrough is not a Node role; Passthrough content requires an authorized reachable Full peer.</p>
  <p>The owner API does not expose a User-readable selection directory. Mutation acknowledgements above are not presented as a current selection list.</p>
  {#if status}<p role="status">{status}</p>{/if}
  {#if error}<p role="alert">{error}</p>{/if}
</section>
