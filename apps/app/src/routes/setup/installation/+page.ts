import { redirect } from "@sveltejs/kit";
import { getSetupStage } from "$lib/common/state/setupClient.svelte";

export async function load() {
  const stage = await getSetupStage();
  if (stage !== "installation" && stage !== "unavailable") {
    throw redirect(302, stage === "ready" ? "/signin" : "/setup/device");
  }
  return { stage };
}
