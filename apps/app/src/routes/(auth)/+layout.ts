import { invoke, isTauri } from "@tauri-apps/api/core";
import { redirect } from "@sveltejs/kit";
import { resolve } from "$app/paths";
import { afterSigninRedirect } from "$lib/common/state/afterSigninRedirect.svelte";
import {
  ensureTauriIdpApiUrl,
  idpApi,
} from "$lib/common/state/idpClient.svelte";
import { ensureTauriManagementApiUrl } from "$lib/common/state/managementClient.svelte";
import {
  ensureOidcClientId,
  getOidcClient,
} from "$lib/common/state/oidc.svelte";
import type { LayoutLoad } from "./$types";

export const prerender = false;

export const load: LayoutLoad = async (event) => {
  await event.parent();

  if (isTauri()) {
    await ensureTauriIdpApiUrl();
    await ensureOidcClientId();
    await ensureTauriManagementApiUrl();
  }

  const installation = isTauri()
    ? await invoke<{ issuer: string } | null>("get_setup_intent")
    : null;
  const oidcClient = getOidcClient();
  const token = oidcClient.getStoredTokenResponse();
  if (
    !token?.access_token ||
    (isTauri() && token.iss && token.iss !== installation?.issuer)
  ) {
    oidcClient.clearStoredTokenResponse();
    afterSigninRedirect.setURL(event.url);
    redirect(302, resolve("/signin"));
  }

  try {
    const currentUserInfo = { ...(await idpApi.userinfo()) };

    if (currentUserInfo) {
      return {
        userInfo: currentUserInfo,
      };
    }
  } catch {
    oidcClient.clearStoredTokenResponse();
    afterSigninRedirect.setURL(event.url);
    redirect(302, resolve("/signin"));
  }
};
