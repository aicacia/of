<script lang="ts" module>
    export interface AuthorizeProps {
        userInfo: OidcUserInfo;
        authorizationRequest: AuthorizationRequest;
        registration?: string;
    }
</script>

<script lang="ts">
    import {
        FetchError,
        ResponseError,
        type AuthorizationRequest,
        type ClientRegistration,
    } from "@aicacia/idp-client";
    import type { OidcUserInfo } from "@aicacia/oidc-client";
    import { LoaderCircle } from "@lucide/svelte";
    import { isTauri } from "@tauri-apps/api/core";
    import { goto } from "$app/navigation";
    import { idpApi } from "$lib/common/state/idpClient.svelte";
    import { m } from "$lib/paraglide/messages";
    import AuthorizeClient from "./_AuthorizeClient.svelte";
    import {
        rejectAuthorizationRequest,
        resolveAuthorizationRequest,
    } from "./_utils";
    import type { ApplicationRegistration } from "@aicacia/idp-client";

    let { userInfo, authorizationRequest, registration }: AuthorizeProps =
        $props();

    type CandidateClientRegistration = Partial<ClientRegistration> & {
        grantTypes?: NonNullable<ClientRegistration["allowedGrantTypes"]>;
        scope?: string;
    };

    function asString(value: unknown): string | undefined {
        return typeof value === "string" ? value : undefined;
    }

    function asStringArray(value: unknown): Array<string> | undefined {
        if (!Array.isArray(value)) {
            return undefined;
        }
        return value.filter(
            (entry): entry is string => typeof entry === "string",
        );
    }

    function normalizeRegistration(
        value: unknown,
    ): CandidateClientRegistration | undefined {
        if (!value || typeof value !== "object") {
            return undefined;
        }
        const record = value as Record<string, unknown>;
        return {
            application: record.application as ApplicationRegistration,
            clientId: asString(record.clientId ?? record.client_id),
            clientName: asString(record.clientName ?? record.client_name),
            profile: asString(record.profile) as ClientRegistration["profile"],
            tokenEndpointAuthMethod: asString(
                record.tokenEndpointAuthMethod ??
                    record.token_endpoint_auth_method,
            ) as ClientRegistration["tokenEndpointAuthMethod"],
            redirectUris: asStringArray(
                record.redirectUris ?? record.redirect_uris,
            ),
            allowedGrantTypes: asStringArray(
                record.allowedGrantTypes ?? record.allowed_grant_types,
            ) as ClientRegistration["allowedGrantTypes"],
            grantTypes: asStringArray(
                record.grantTypes ?? record.grant_types,
            ) as CandidateClientRegistration["grantTypes"],
            responseTypes: asStringArray(
                record.responseTypes ?? record.response_types,
            ) as ClientRegistration["responseTypes"],
            allowedScopes: asStringArray(
                record.allowedScopes ?? record.allowed_scopes,
            ),
            scope: asString(record.scope),
            clientType: asString(
                record.clientType ?? record.client_type,
            ) as ClientRegistration["clientType"],
            clientUri: asString(record.clientUri ?? record.client_uri),
            logoUri: asString(record.logoUri ?? record.logo_uri),
            policyUri: asString(record.policyUri ?? record.policy_uri),
            tosUri: asString(record.tosUri ?? record.tos_uri),
            contacts: asStringArray(record.contacts),
        };
    }

    function parseRegistration(
        value?: string,
    ): CandidateClientRegistration | undefined {
        if (!value) {
            return undefined;
        }
        try {
            return normalizeRegistration(JSON.parse(value));
        } catch (e) {
            console.error("Failed to parse registration query param", e);
            return undefined;
        }
    }

    function splitScope(scope?: string): Array<string> {
        return (scope ?? "").split(/\s+/).filter((entry) => entry.length > 0);
    }

    let registrationCandidate = $derived(parseRegistration(registration));
    let effectiveClientId = $derived(
        authorizationRequest.clientId === "unknown"
            ? (registrationCandidate?.clientId ?? authorizationRequest.clientId)
            : authorizationRequest.clientId,
    );
    let lookupClientId = $derived(
        authorizationRequest.clientId === "unknown"
            ? registrationCandidate?.clientId
            : authorizationRequest.clientId,
    );
    let requestedScopes = $derived(
        splitScope(authorizationRequest.scope ?? ""),
    );

    let client = $state<ClientRegistration | null>(null);

    let loadingClient = $state(true);
    $effect(() => {
        loadingClient = true;
        if (!lookupClientId) {
            console.debug(
                "ClientRegistration ID is unknown, skipping client info fetch",
            );
            client = null;
            loadingClient = false;
            return;
        }
        console.debug("Fetching client info for clientId", lookupClientId);
        idpApi
            .getRegister({ clientId: lookupClientId })
            .catch((e) => {
                console.error("Error fetching client info", e);
                return null;
            })
            .then((c) => {
                client = c;
            })
            .finally(() => {
                loadingClient = false;
            });
    });

    let loadingUserAllowed = $state(true);
    $effect(() => {
        if (loadingClient) {
            console.debug(
                "Still loading client info, skipping user allowed check",
            );
            return;
        }
        if (!client) {
            console.debug(
                "ClientRegistration info not available, skipping user allowed check",
            );
            loadingUserAllowed = false;
            return;
        }
        loadingUserAllowed = true;
        console.debug(
            "Checking if user has already allowed this client and scopes",
        );
        idpApi
            .isAllowedForUser({
                isAllowedForUserRequest: {
                    clientId: effectiveClientId,
                    redirectUri: authorizationRequest.redirectUri ?? "",
                    scope: authorizationRequest.scope ?? "",
                },
            })
            .then((response) => {
                if (response.allowed) {
                    onAuthorize();
                }
            })
            .catch((error) => {
                // Not yet approved or scopes changed; fall back to consent screen
                console.error(
                    "Error checking if user has allowed client",
                    error,
                );
            })
            .finally(() => {
                loadingUserAllowed = false;
            });
    });

    let loadingAuthorizationRequest = $state(false);
    let loadingRegistration = $state(false);
    async function onAuthorize() {
        loadingAuthorizationRequest = true;
        console.debug(
            "Resolving authorize request for clientId",
            effectiveClientId,
        );
        try {
            await resolveAuthorizationRequest({
                ...authorizationRequest,
                clientId: effectiveClientId,
            });
            if (isTauri()) {
                await goto("/");
            }
        } catch (e) {
            console.error("Error resolving authorize request", e);
        } finally {
            loadingAuthorizationRequest = false;
        }
    }
    async function onAllow() {
        try {
            await idpApi.approveForUser({
                approveForUserRequest: {
                    clientId: effectiveClientId,
                    redirectUri: authorizationRequest.redirectUri ?? "",
                    scope: authorizationRequest.scope ?? "",
                },
            });
            await onAuthorize();
        } catch (e) {
            console.error("Error approving client for user", e);
        }
    }
    async function onDeny() {
        rejectAuthorizationRequest(
            authorizationRequest,
            "access_denied",
            m.authorize_access_denied_reason(),
        );
    }

    async function onRegister() {
        if (!registrationCandidate) {
            return;
        }
        if (
            !registrationCandidate.application?.uri ||
            !registrationCandidate.clientName ||
            !registrationCandidate.profile ||
            !registrationCandidate.tokenEndpointAuthMethod
        ) {
            console.error("Registration data missing required fields");
            return;
        }
        loadingRegistration = true;
        const redirectUris = (
            registrationCandidate.redirectUris ?? [
                authorizationRequest.redirectUri ?? "",
            ]
        ).filter((entry) => entry.length > 0);
        const allowedGrantTypes = (registrationCandidate.allowedGrantTypes ??
            registrationCandidate.grantTypes ?? [
                "authorization_code",
            ]) as ClientRegistration["allowedGrantTypes"];
        const responseTypes = (registrationCandidate.responseTypes ?? [
            authorizationRequest.responseType,
        ]) as ClientRegistration["responseTypes"];
        const allowedScopes =
            registrationCandidate.allowedScopes ??
            (registrationCandidate.scope
                ? splitScope(registrationCandidate.scope)
                : undefined) ??
            splitScope(authorizationRequest.scope ?? "");

        const payload: ClientRegistration = {
            application: registrationCandidate.application,
            clientId: registrationCandidate.clientId ?? effectiveClientId,
            clientName: registrationCandidate.clientName,
            profile: registrationCandidate.profile,
            tokenEndpointAuthMethod:
                registrationCandidate.tokenEndpointAuthMethod,
            redirectUris,
            allowedGrantTypes,
            responseTypes,
            allowedScopes,
            clientType: registrationCandidate.clientType,
            clientUri: registrationCandidate.clientUri,
            logoUri: registrationCandidate.logoUri,
            policyUri: registrationCandidate.policyUri,
            tosUri: registrationCandidate.tosUri,
            contacts: registrationCandidate.contacts,
        };
        try {
            client = await idpApi.register({ clientRegistration: payload });
        } catch (e) {
            console.error("Error registering client", e);
        } finally {
            loadingRegistration = false;
        }
    }

    let loading = $derived(
        loadingClient ||
            loadingUserAllowed ||
            loadingAuthorizationRequest ||
            loadingRegistration,
    );
    let disabled = $derived(loading);
</script>

{#if loading}
    <div class="flex flex-row items-center justify-center">
        <LoaderCircle class="animate-spin" />
    </div>
{:else if client}
    <AuthorizeClient {userInfo} {client} {disabled} {onAllow} {onDeny} />
{:else if registrationCandidate}
    <section>
        <h5>{m.authorize_new_client_request()}</h5>
        <p>{m.authorize_client_not_found()}</p>
        <dl class="mt-3 space-y-1 text-sm">
            <div>
                <dt class="font-semibold">Client</dt>
                <dd>
                    {registrationCandidate.clientName ??
                        registrationCandidate.clientId ??
                        effectiveClientId}
                </dd>
            </div>
            <div>
                <dt class="font-semibold">Client ID</dt>
                <dd>
                    {registrationCandidate.clientId ?? effectiveClientId}
                </dd>
            </div>
            <div>
                <dt class="font-semibold">Redirect URI</dt>
                <dd>{authorizationRequest.redirectUri ?? "-"}</dd>
            </div>
            <div>
                <dt class="font-semibold">Requested scopes</dt>
                <dd>
                    {requestedScopes.length > 0
                        ? requestedScopes.join(", ")
                        : "-"}
                </dd>
            </div>
        </dl>
        <div class="mt-4 flex flex-row justify-center gap-4">
            <button type="button" class="btn primary" onclick={onRegister}>
                {m.client_accept()}
            </button>
            <button type="button" class="btn secondary" onclick={onDeny}>
                {m.client_reject()}
            </button>
        </div>
    </section>
{:else}
    <section>
        <h5>{m.authorize_invalid_request()}</h5>
        <p>{m.authorize_client_not_found()}</p>
        <div class="mt-4 flex flex-row justify-center gap-4">
            <button type="button" class="btn secondary" onclick={onDeny}>
                {m.authorize_button_deny()}
            </button>
        </div>
    </section>
{/if}
