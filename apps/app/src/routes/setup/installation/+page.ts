import { error } from "@sveltejs/kit";
import { isTauri } from "@tauri-apps/api/core";
import { getSetupStage } from "$lib/common/state/setupClient.svelte";

export async function load() {
  if (!isTauri()) return { stage: "desktop-only" };
  const stage = await getSetupStage();
  if (
    stage !== "installation" &&
    stage !== "unavailable" &&
    stage !== "ready" &&
    stage !== "device"
  ) {
    throw error(
      503,
      "Local setup evidence is invalid. Readiness has not been established.",
    );
  }
  return { stage };
}
