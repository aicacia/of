<script lang="ts">
  import { ResidencyMode, ResourcesResidencyApi, StorageOwnerConfiguration } from "@aicacia/storage-client";
  import { isTauri } from "@tauri-apps/api/core";
  import * as v from "valibot";
  import { ensureLocalhostBaseUrl } from "$lib/common/state/localhostBaseUrl.svelte";

  let { filesystemId }: { filesystemId: string } = $props();
  const desktop = isTauri();
  let accessToken = $state("");
  let requestedMode = $state<ResidencyMode>(ResidencyMode.Full);
  let observed = $state.raw<{ id: string; mode: ResidencyMode } | null>(null);
  let busy = $state(false);
  let status = $state("");
  let error = $state("");
  let currentMode = $derived(observed?.id === filesystemId ? observed.mode : null);

  async function residency(apply: boolean) {
    const id = filesystemId;
    const mode = requestedMode;
    if (busy) return;
    busy = true;
    status = "";
    error = "";
    observed = null;
    try {
      if (!desktop) throw new Error("Residency controls require the local desktop owner");
      v.parse(v.pipe(v.string(), v.uuid()), id);
      const token = accessToken.trim();
      if (!token) throw new Error("A Storage-filesystem User token with the required read/write action is required");
      if (apply && !confirm(`Set whole filesystem ${id} to ${mode} on this Node? This does not change the selected Device, grant access, complete cleanup, or confirm content availability.`)) return;
      const api = new ResourcesResidencyApi(new StorageOwnerConfiguration({
        basePath: `${await ensureLocalhostBaseUrl()}/storage`,
        accessToken: token,
        fetchApi: fetch,
      }));
      if (apply) {
        await api.putFileSystemResidency({ filesystemId: id, resourceResidency: { mode } }, { redirect: "error" });
        status = `Storage acknowledged local ${mode} for filesystem ${id}. Read current mode to verify it; no content or cleanup readiness is inferred.`;
      } else {
        const result = await api.getFileSystemResidency({ filesystemId: id }, { redirect: "error" });
        observed = { id, mode: result.mode };
        status = `Storage reports ${result.mode} for filesystem ${id} on this Node.`;
      }
    } catch (cause) {
      error = `${String(cause)}. No success is claimed. The owner may have retained progress; read current mode or retry with current authorization. Resource denial does not reset this Node's completed setup.`;
    } finally {
      accessToken = "";
      busy = false;
    }
  }
</script>

<fieldset disabled={busy || !desktop || !filesystemId} class="flex flex-col gap-3" aria-describedby="residency-scope">
  <legend>Local whole-filesystem Residency</legend>
  <label>Storage-filesystem User access token
    <input type="password" bind:value={accessToken} autocomplete="off" />
  </label>
  <p>GET requires read; PUT requires write. The token determines the User/Application namespace, independently of the Management fields above. It is transient and cleared after every attempt.</p>
  <label>Requested mode
    <select bind:value={requestedMode}>
      <option value={ResidencyMode.Full}>Full</option>
      <option value={ResidencyMode.Passthrough}>Passthrough</option>
    </select>
  </label>
  <div class="flex gap-2">
    <button class="btn secondary" type="button" onclick={() => residency(false)} disabled={!accessToken.trim()}>Read current local mode</button>
    <button class="btn secondary" type="button" onclick={() => residency(true)} disabled={!accessToken.trim()}>Apply local Residency</button>
  </div>
</fieldset>
<p id="residency-scope">This controls only this Node's whole filesystem, not the selected remote Device or a Node role. Full permits local content operations but does not prove all content is available. Passthrough is read-only and requires an authorized reachable Full peer for content; this control does not test peer availability or stream content. Cleanup fences remain enforced by Storage.</p>
{#if !desktop}<p role="status">Unavailable outside the native desktop; no local Residency is applied here.</p>{/if}
{#if currentMode}<p role="status">Current owner-reported local mode: {currentMode}.</p>{/if}
{#if status}<p role="status">{status}</p>{/if}
{#if error}<p role="alert">{error}</p>{/if}
