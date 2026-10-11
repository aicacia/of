import { invoke, isTauri } from "@tauri-apps/api/core";
import { clearOidcSession } from "./oidc.svelte";

export async function resetDevice(): Promise<void> {
  clearOidcSession();
  await invoke("reset_device");
}

export type SetupStage = "installation" | "device" | "ready" | "unavailable";

export async function getSetupStage(): Promise<SetupStage> {
  if (!isTauri()) {
    throw new Error("Setup status is only available in the desktop app");
  }

  return invoke<SetupStage>("get_setup_stage");
}
