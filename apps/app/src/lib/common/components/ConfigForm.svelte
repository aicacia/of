<script lang="ts" module>
    import * as v from "valibot";
    import { m } from "$lib/paraglide/messages";
    import { validateIdpApiUrl } from "$lib/common/state/idpClient.svelte";
    import { validateManagementApiUrl } from "$lib/common/state/managementClient.svelte";

    const configSchema = v.objectAsync({
        idpApiUrl: v.pipeAsync(
            v.string(),
            v.nonEmpty(m.errors_message_required()),
            v.url(m.errors_message_invalid_url()),
            v.checkAsync(validateIdpApiUrl, m.errors_message_invalid_url()),
        ),
        managementApiUrl: v.pipeAsync(
            v.string(),
            v.nonEmpty(m.errors_message_required()),
            v.url(m.errors_message_invalid_url()),
            v.checkAsync(
                validateManagementApiUrl,
                m.errors_message_invalid_url(),
            ),
        ),
    });
</script>

<script lang="ts">
    import { createForm } from "@aicacia/svelte-forms";
    import Issues from "$lib/common/components/Issues.svelte";
    import {
        getIdpApiUrl,
        setIdpApiUrl,
    } from "$lib/common/state/idpClient.svelte";
    import {
        getManagementApiUrl,
        setManagementApiUrl,
    } from "$lib/common/state/managementClient.svelte";
    import { notifications } from "$lib/common/state/notifications.svelte";

    interface Props {
        onSaved?: () => void;
    }

    let { onSaved = () => {} }: Props = $props();

    const form = createForm(configSchema, {
        idpApiUrl: getIdpApiUrl() ?? "",
        managementApiUrl: getManagementApiUrl() ?? "",
    });

    export function reset() {
        form.fields.idpApiUrl.value = getIdpApiUrl() ?? "";
        form.fields.managementApiUrl.value = getManagementApiUrl() ?? "";
    }

    async function onSubmit(event: SubmitEvent) {
        event.preventDefault();

        const [_input, output, error] = await form.validate();
        if (error) {
            notifications.add(m.errors_message_invalid(), "error");
            return;
        }

        setIdpApiUrl(output.idpApiUrl);
        setManagementApiUrl(output.managementApiUrl);
        onSaved();
    }
</script>

<form onsubmit={onSubmit} class="flex flex-col gap-4">
    <label class="flex flex-col">
        {m.env_config_idp_url()}
        <input
            type="text"
            aria-label={m.env_config_idp_url()}
            placeholder={m.env_config_idp_url_placeholder()}
            bind:value={form.fields.idpApiUrl.value}
        />
        <Issues issues={form.fields.idpApiUrl.issues} />
    </label>
    <label class="flex flex-col">
        {m.env_config_management_url()}
        <input
            type="text"
            aria-label={m.env_config_management_url()}
            placeholder={m.env_config_management_url_placeholder()}
            bind:value={form.fields.managementApiUrl.value}
        />
        <Issues issues={form.fields.managementApiUrl.issues} />
    </label>
    <input type="submit" value={m.env_config_save()} class="btn primary" />
</form>
