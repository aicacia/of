import { invoke, isTauri } from "@tauri-apps/api/core";

export type SetupStage = "installation" | "device" | "ready" | "unavailable";

export async function getSetupStage(): Promise<SetupStage> {
  if (!isTauri()) {
    throw new Error("Setup status is only available in the desktop app");
  }

  return invoke<SetupStage>("get_setup_stage");
}
