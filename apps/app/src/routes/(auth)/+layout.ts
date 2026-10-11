import { FetchError, ResponseError, type UserInfo } from "@aicacia/idp-client";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { error, redirect } from "@sveltejs/kit";
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

export const load = (async (event) => {
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

    let userInfo: UserInfo;
    try {
        userInfo = await idpApi.userinfo();
    } catch (cause) {
        if (cause instanceof ResponseError) {
            const status = cause.response.status;
            const body =
                status === 400
                    ? await cause.response
                          .clone()
                          .json()
                          .catch(() => null)
                    : null;
            if (
                status === 401 ||
                status === 403 ||
                body?.error === "invalid_grant"
            ) {
                oidcClient.clearStoredTokenResponse();
                afterSigninRedirect.setURL(event.url);
                redirect(302, resolve("/signin"));
            }
        }
        if (
            cause instanceof FetchError ||
            (cause instanceof ResponseError && cause.response.status >= 500)
        ) {
            error(
                503,
                "Authentication service unavailable. Your session has been preserved. Retry when the service is reachable.",
            );
        }
        error(
            502,
            "Unable to verify your session. Your session has been preserved, but access is not granted. Retry to verify it again.",
        );
    }
    if (typeof userInfo?.sub !== "string" || !userInfo.sub.trim()) {
        error(
            502,
            "Unable to verify your session. Your session has been preserved, but access is not granted. Retry to verify it again.",
        );
    }
    return { userInfo: { ...userInfo } };
}) satisfies LayoutLoad;
