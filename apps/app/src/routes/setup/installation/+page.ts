import { redirect } from "@sveltejs/kit";
import { isTauri } from "@tauri-apps/api/core";
import { getSetupStage } from "$lib/common/state/setupClient.svelte";

export async function load() {
  if (!isTauri()) return { stage: "desktop-only" };
  const stage = await getSetupStage();
  if (stage !== "installation" && stage !== "unavailable") {
    throw redirect(302, stage === "ready" ? "/signin" : "/setup/device");
  }
  return { stage };
}
