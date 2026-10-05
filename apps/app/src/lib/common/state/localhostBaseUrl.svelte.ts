import { createStorage } from "@aicacia/svelte-headless";
import { invoke, isTauri } from "@tauri-apps/api/core";

const localhostBaseUrl = createStorage<string | null>(
  "localhost-base-url",
  null,
);
let baseUrlLoadPromise: Promise<string | null> | null = null;

const MAX_ATTEMPTS = 300;
const RETRY_DELAY_MS = 100;

function wait(delayMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, delayMs));
}

async function isLocalhostServerReady(baseUrl: string): Promise<boolean> {
  for (const path of ["/idp/health", "/lidp/setup/status"]) {
    try {
      const response = await fetch(`${baseUrl}${path}`);
      if (response.ok) {
        return true;
      }
    } catch {
      continue;
    }
  }
  return false;
}

export function getLocalhostBaseUrlCached(): string | null {
  return localhostBaseUrl.item;
}

export async function loadLocalhostBaseUrl(): Promise<string | null> {
  if (!isTauri()) {
    return null;
  }

  if (baseUrlLoadPromise) {
    return baseUrlLoadPromise;
  }

  baseUrlLoadPromise = (async () => {
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      try {
        const baseUrl = await invoke<string>("get_localhost_server_base_url");
        const normalized = baseUrl?.trim() ?? "";
        if (normalized && (await isLocalhostServerReady(normalized))) {
          localhostBaseUrl.item = normalized;
          return normalized;
        }
      } catch {
        // Continue retry loop while startup is still in progress.
      }

      await wait(RETRY_DELAY_MS);
    }

    return null;
  })().finally(() => {
    baseUrlLoadPromise = null;
  });

  return baseUrlLoadPromise;
}

export async function ensureLocalhostBaseUrl(): Promise<string> {
  const baseUrl = await loadLocalhostBaseUrl();
  if (!baseUrl) {
    throw new Error("Localhost server URL is not available yet");
  }
  return baseUrl;
}
