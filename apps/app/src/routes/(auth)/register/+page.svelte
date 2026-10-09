<script lang="ts">
    import {
        ClientRegistrationFromJSON,
        ClientRegistrationToJSON,
        ClientType,
        TokenEndpointAuthMethod,
        type ClientRegistration,
    } from "@aicacia/idp-client";
    import {
        handleNativeCallbackRequest,
        type NativeRequest,
    } from "@aicacia/native-fetch";
    import * as v from "valibot";
    import { page } from "$app/state";
    import { idpApi } from "$lib/common/state/idpClient.svelte";
    import { redirectToUrl } from "$lib/common/util/redirectToUrl";

    const metadataSchema = v.object({
        application: v.object({ uri: v.pipe(v.string(), v.nonEmpty()) }),
        client_name: v.pipe(v.string(), v.nonEmpty()),
        profile: v.picklist([
            "web_application",
            "user_agent_based_application",
            "native_application",
        ]),
        client_type: v.literal("public"),
        token_endpoint_auth_method: v.literal("none"),
        redirect_uris: v.array(v.pipe(v.string(), v.url())),
    });
    const nativeSchema = v.object({
        url: v.pipe(v.string(), v.url()),
        callbackUrl: v.pipe(v.string(), v.url()),
        state: v.pipe(v.string(), v.nonEmpty()),
        method: v.string(),
        headers: v.record(v.string(), v.string()),
        body: v.nullable(v.string()),
    });
    let request = $derived.by((): ClientRegistration | null => {
        try {
            const json = JSON.parse(
                page.url.searchParams.get("registration") ?? "null",
            );
            v.parse(metadataSchema, json);
            if (json.client_secret || json.client_id) return null;
            return ClientRegistrationFromJSON(json);
        } catch {
            return null;
        }
    });
    let destination = $derived.by(() => {
        try {
            const redirect = new URL(
                page.url.searchParams.get("redirect_uri") ?? "",
            );
            if (!request?.redirectUris?.includes(redirect.href)) return null;
            const encodedNative = page.url.searchParams.get("native");
            const native: NativeRequest | undefined = encodedNative
                ? v.parse(nativeSchema, JSON.parse(encodedNative))
                : undefined;
            if (native && new URL(native.callbackUrl).href !== redirect.href)
                return null;
            return { redirect, native };
        } catch {
            return null;
        }
    });
    let loading = $state(false);
    let error = $state<string | null>(null);
    let registered = $state<ClientRegistration | null>(null);
    async function respond(body: object, status = 200) {
        if (!destination)
            throw new Error("A registered redirect URI is required");
        if (destination.native) {
            await redirectToUrl(
                await handleNativeCallbackRequest(
                    destination.native,
                    () =>
                        new Response(JSON.stringify(body), {
                            status,
                            headers: { "Content-Type": "application/json" },
                        }),
                ),
            );
        } else {
            const url = new URL(destination.redirect);
            url.searchParams.set(
                status === 200 ? "client" : "error",
                status === 200 ? JSON.stringify(body) : "registration_denied",
            );
            const state = page.url.searchParams.get("state");
            if (state) url.searchParams.set("state", state);
            await redirectToUrl(url);
        }
    }
    async function accept() {
        if (!request || !destination || loading) return;
        loading = true;
        error = null;
        try {
            // Retain a successful result if only callback delivery fails; retry must not create another client.
            registered ??= await idpApi.register({
                clientRegistration: {
                    ...request,
                    clientType: ClientType.Public,
                    tokenEndpointAuthMethod: TokenEndpointAuthMethod.None,
                },
            });
            if (registered.clientSecret)
                throw new Error(
                    "Refusing to send a client secret through a redirect",
                );
            await respond(ClientRegistrationToJSON(registered));
        } catch (cause) {
            error =
                cause instanceof Error ? cause.message : "Registration failed";
        } finally {
            loading = false;
        }
    }
    async function reject() {
        try {
            await respond({ error: "registration_denied" }, 403);
        } catch (cause) {
            error = cause instanceof Error ? cause.message : "Callback failed";
        }
    }
</script>

<div class="card mx-auto flex max-w-xl flex-col gap-4">
    <h1>Register public client</h1>
    {#if request && destination}
        <p>
            Approve registration for {request.clientName} in {request
                .application.uri}?
        </p>
        <p>Callback: {destination.redirect.href}</p>
        <pre class="overflow-auto">{JSON.stringify(
                ClientRegistrationToJSON(request),
                null,
                2,
            )}</pre>
        <button class="btn primary" onclick={accept} disabled={loading}
            >{loading
                ? "Registering…"
                : registered
                  ? "Retry callback"
                  : "Approve"}</button
        >
        <button class="btn secondary" onclick={reject} disabled={loading}
            >Reject</button
        >
    {:else}
        <p>
            Invalid request. This page accepts public registrations only, with
            an exact requested redirect URI. Confidential clients must use the
            authenticated IdP API directly.
        </p>
    {/if}
    {#if error}<p role="alert">{error}</p>{/if}
</div>
