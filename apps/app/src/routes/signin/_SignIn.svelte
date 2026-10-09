<script lang="ts" module>
    import * as v from "valibot";
    import { m } from "$lib/paraglide/messages";

    const SignInSchema = () =>
        v.object({
            username: v.pipe(
                v.string(),
                v.nonEmpty(m.errors_message_username_required()),
            ),
            password: v.pipe(
                v.string(),
                v.nonEmpty(m.errors_message_password_required()),
                v.minLength(
                    1,
                    m.errors_message_password_min_length({ characters: 1 }),
                ),
            ),
        });
</script>

<script lang="ts">
    import { createForm } from "@aicacia/svelte-forms";
    import { isTauri } from "@tauri-apps/api/core";
    import Issues from "$lib/common/components/Issues.svelte";
    import { afterSigninRedirect } from "$lib/common/state/afterSigninRedirect.svelte";
    import {
        ensureTauriIdpApiUrl,
        passwordToken,
    } from "$lib/common/state/idpClient.svelte";
    import { notifications } from "$lib/common/state/notifications.svelte";
    import {
        ensureOidcClientId,
        getOidcClient,
    } from "$lib/common/state/oidc.svelte";

    const form = createForm(SignInSchema(), {
        username: "",
        password: "",
    });

    async function onSubmit(e: SubmitEvent) {
        e.preventDefault();

        const [_input, output, error] = await form.validate();

        if (error) {
            return;
        }
        try {
            if (isTauri()) {
                await ensureTauriIdpApiUrl();
            }

            const token = await passwordToken(
                await ensureOidcClientId(),
                output.username,
                output.password,
            );

            getOidcClient().setToken({
                token_type: token.tokenType,
                iss: token.iss,
                scope: token.scope ?? undefined,
                access_token: token.accessToken,
                refresh_token: token.refreshToken,
                refresh_token_expires_in:
                    token.refreshTokenExpiresIn ?? undefined,
                id_token: token.idToken,
                expires_in: token.expiresIn ?? undefined,
            });

            await afterSigninRedirect.onReturn();
        } catch (e) {
            console.error("Error during sign-in:", e);
            notifications.add(
                e instanceof Error ? e.message : m.errors_message_internal(),
            );
        }
    }
</script>

<form onsubmit={onSubmit} class="flex flex-col">
    <label class="flex flex-col">
        {m.signin_username_label()}
        <input
            type="text"
            aria-label={m.signin_username_label()}
            autocomplete="username"
            placeholder={m.signin_username_placeholder()}
            bind:value={form.fields.username.value}
        />
        <Issues issues={form.fields.username.issues} />
    </label>
    <label class="flex flex-col">
        {m.signin_password_label()}
        <input
            aria-label={m.signin_password_label()}
            type="password"
            autocomplete="current-password"
            placeholder={m.signin_password_placeholder()}
            bind:value={form.fields.password.value}
        />
        <Issues issues={form.fields.password.issues} />
    </label>
    <input class="btn primary mt-4" type="submit" value={m.sign_in()} />
</form>
