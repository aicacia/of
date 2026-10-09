import {
  Configuration,
  type ConfigurationParameters,
  DefaultApi,
} from "@aicacia/management-client";
import { createStorage } from "@aicacia/svelte-headless";
import { isTauri } from "@tauri-apps/api/core";
import { goto } from "$app/navigation";
import { resolve } from "$app/paths";
import { page } from "$app/state";
import { env } from "$env/dynamic/public";
import { afterSigninRedirect } from "./afterSigninRedirect.svelte";
import {
  ensureLocalhostBaseUrl,
  loadLocalhostBaseUrl,
} from "./localhostBaseUrl.svelte";
import { ownerAccessToken } from "./idpClient.svelte";

const managementApiUrl = createStorage<string | null>(
  "management-api-url",
  (isTauri() ? null : env.PUBLIC_LIDP_MANAGEMENT_BASE_URL) ?? null,
);

async function hydrateTauriManagementApiUrl(): Promise<void> {
  if (!isTauri()) {
    return;
  }

  const baseUrl = await loadLocalhostBaseUrl();
  if (baseUrl) {
    managementApiUrl.item = `${baseUrl}/management`;
  }
}

void hydrateTauriManagementApiUrl();

function readAccessToken(): Promise<string> {
  return ownerAccessToken("idp-management");
}

function readBasePath(): string | undefined {
  const basePath = managementApiUrl.item;
  return basePath === null ? undefined : basePath;
}

const defaultConfigurationParameters: ConfigurationParameters = {
  middleware: [
    {
      pre: async (context) => ({
        ...context,
        init: {
          ...context.init,
          mode: "cors",
        },
      }),
    },
    {
      post: async (context) => {
        if (context.response.status === 401) {
          afterSigninRedirect.setURL(page.url);
          await goto(resolve("/signin"));
        }
        return context.response;
      },
    },
  ],
  accessToken(): Promise<string> {
    return readAccessToken();
  },
  get basePath(): string | undefined {
    return readBasePath();
  },
  get fetchApi() {
    return fetch;
  },
  credentials: "same-origin",
};

export const lidpManagementConfiguration = new Configuration(
  defaultConfigurationParameters,
);

export const managementApi = new DefaultApi(lidpManagementConfiguration);

export function setManagementApiUrl(newManagementApiUrl: string) {
  managementApiUrl.item = newManagementApiUrl;
}

export async function ensureTauriManagementApiUrl(): Promise<void> {
  if (isTauri())
    managementApiUrl.item = `${await ensureLocalhostBaseUrl()}/management`;
}

export function getManagementApiUrl(): string | null {
  return managementApiUrl.item;
}

export async function validateManagementApiUrl(
  basePath: string,
): Promise<boolean> {
  if (!basePath) {
    return false;
  }
  const configuration = new Configuration({
    ...defaultConfigurationParameters,
    basePath,
  });
  const api = new DefaultApi(configuration);

  try {
    const version = await api.version();
    return version.name === "management-server";
  } catch {
    return false;
  }
}
