import { redirect } from "@sveltejs/kit";
import { isTauri } from "@tauri-apps/api/core";
import { getSetupStage } from "$lib/common/state/setupClient.svelte";

export async function load() {
  if (!isTauri()) throw redirect(302, "/setup/installation");
  const stage = await getSetupStage();
  if (stage !== "device") {
    throw redirect(302, stage === "ready" ? "/signin" : "/setup/installation");
  }
}
