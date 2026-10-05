import {
  Configuration,
  type ConfigurationParameters,
  DefaultApi,
} from "@aicacia/idp-client";
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
import { getOidcClient } from "./oidc.svelte";

const idpApiUrl = createStorage<string | null>(
  "idp-api-url",
  (isTauri() ? null : env.PUBLIC_LIDP_BASE_URL) ?? null,
);

async function hydrateTauriApiUrl(): Promise<void> {
  if (!isTauri()) {
    return;
  }

  const baseUrl = await loadLocalhostBaseUrl();
  if (baseUrl) {
    idpApiUrl.item = `${baseUrl}/idp`;
  }
}

void hydrateTauriApiUrl();

function readAccessToken(): string {
  const oidcClient = getOidcClient();
  if (!oidcClient) {
    return "";
  }
  return oidcClient.getStoredTokenResponse()?.access_token ?? "";
}

function readBasePath(): string | undefined {
  const basePath = idpApiUrl.item;
  return basePath === null ? undefined : basePath;
}

export const defaultConfigurationParameters: ConfigurationParameters = {
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
  get fetchApi() {
    return fetch;
  },
  accessToken(_name, _scopes): string {
    return readAccessToken();
  },
  get basePath(): string | undefined {
    return readBasePath();
  },
  credentials: "same-origin",
};

export const lidpConfiguration = new Configuration(
  defaultConfigurationParameters,
);

export const idpApi = new DefaultApi(lidpConfiguration);

export function setIdpApiUrl(newIdpApiUrl: string) {
  idpApiUrl.item = newIdpApiUrl;
}
export function getIdpApiUrl(): string | null {
  return idpApiUrl.item;
}

export async function ensureTauriIdpApiUrl(): Promise<string | null> {
  if (!isTauri()) {
    return idpApiUrl.item;
  }

  const baseUrl = await ensureLocalhostBaseUrl();
  idpApiUrl.item = `${baseUrl}/idp`;
  return idpApiUrl.item;
}

export async function validateIdpApiUrl(basePath: string): Promise<boolean> {
  if (!basePath) {
    return false;
  }
  const configuration = new Configuration({
    ...defaultConfigurationParameters,
    basePath,
  });
  const api = new DefaultApi(configuration);

  try {
    const metadata = await api.openidConfiguration();
    return (
      metadata.tokenEndpoint === `${basePath.replace(/\/$/, "")}/oauth2/token`
    );
  } catch {
    return false;
  }
}

async function hydrateWebApiUrl(): Promise<void> {
  if (isTauri() || (await validateIdpApiUrl(idpApiUrl.item ?? ""))) {
    return;
  }

  const fallback = env.PUBLIC_LIDP_BASE_URL;
  if (fallback && (await validateIdpApiUrl(fallback))) {
    idpApiUrl.item = fallback;
  }
}

void hydrateWebApiUrl();
