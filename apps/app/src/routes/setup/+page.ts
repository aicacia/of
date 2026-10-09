import { redirect } from "@sveltejs/kit";
import { isTauri } from "@tauri-apps/api/core";
import { getSetupStage } from "$lib/common/state/setupClient.svelte";

export async function load() {
  if (!isTauri()) {
    throw redirect(302, "/signin");
  }

  const stage = await getSetupStage();
  throw redirect(
    302,
    stage === "ready"
      ? "/signin"
      : stage === "device"
        ? "/setup/device"
        : "/setup/installation",
  );
}
