<script lang="ts">
  import { goto } from "$app/navigation";
  import { page } from "$app/state";

  let retrying = $state(false);
  let retryError = $state("");

  async function retry() {
    retrying = true;
    retryError = "";
    try {
      // Reloading the document would discard the desktop's memory-only session.
      await goto(page.url, { invalidateAll: true, replaceState: true });
    } catch {
      retryError = "Retry failed. Please try again.";
    } finally {
      retrying = false;
    }
  }
</script>

<svelte:head>
  <title>{page.status} — {page.error?.message ?? "Error"}</title>
</svelte:head>

<main class="mx-auto flex max-w-xl flex-col gap-4 p-8">
  <h1 class="text-xl font-semibold">{page.status}</h1>
  <p role="alert">{page.error?.message ?? "An unexpected error occurred."}</p>
  {#if page.status === 502 || page.status === 503}
    <button type="button" class="btn primary" onclick={retry} disabled={retrying}>
      {retrying ? "Retrying…" : "Retry"}
    </button>
    {#if retryError}
      <p role="alert">{retryError}</p>
    {/if}
  {/if}
</main>
