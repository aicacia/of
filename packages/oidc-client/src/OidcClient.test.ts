import { expect, test, vi } from "vitest";
import { OidcClient } from "./OidcClient.js";
import { OidcClientError } from "./OidcClientError.js";
import type { OidcConfiguration } from "./OidcConfiguration.js";

test("memory sessions remove old plaintext caches and never persist tokens", () => {
  const values = new Map<string, string>([
    ["oidc.token:https://issuer.example:response", '{"access_token":"old"}'],
    ["oidc.pkce:https://issuer.example:last", "old-verifier"],
    [
      "oidc.token:https://previous.example:response",
      '{"refresh_token":"old-refresh"}',
    ],
    ["oidc.pkce:https://previous.example:state:pending", "previous-verifier"],
    ["unrelated", "retain"],
  ]);
  const setItem = vi.fn((key: string, value: string) => values.set(key, value));
  vi.stubGlobal("window", {
    location: { origin: "https://app.example" },
    localStorage: {
      get length() {
        return values.size;
      },
      key: (index: number) => [...values.keys()][index] ?? null,
      getItem: (key: string) => values.get(key) ?? null,
      setItem,
      removeItem: (key: string) => values.delete(key),
    },
  });
  try {
    const options = {
      clientConfig: {
        authority: "https://issuer.example",
        redirectUri: "https://app.example/callback",
      },
      storage: "memory" as const,
    };
    const client = new OidcClient(options);
    expect(client.getStoredTokenResponse()).toBeNull();
    expect([...values]).toEqual([["unrelated", "retain"]]);
    client.setToken({ access_token: "access", refresh_token: "refresh" });
    expect(client.getStoredTokenResponse()?.access_token).toBe("access");
    expect(new OidcClient(options).getStoredTokenResponse()).toBeNull();
    expect(setItem).not.toHaveBeenCalled();
    values.set("oidc.token:https://previous.example:response", "old-refresh");
    values.set("oidc.pkce:https://previous.example:last", "previous-verifier");
    client.clearStoredTokenResponse();
    expect(client.getStoredTokenResponse()).toBeNull();
    expect([...values]).toEqual([["unrelated", "retain"]]);
  } finally {
    vi.unstubAllGlobals();
  }
});

function createClient(): OidcClient {
  return new OidcClient({
    clientConfig: {
      authority: "https://issuer.example",
      registration: {
        redirectUris: ["https://app.example/callback"],
      },
    },
  });
}

function createOidcConfiguration(
  overrides: Partial<OidcConfiguration> = {},
): OidcConfiguration {
  return {
    issuer: "https://issuer.example",
    authorization_endpoint: "https://issuer.example/oauth/authorize",
    token_endpoint: "https://issuer.example/oauth/token",
    check_session_iframe: "https://issuer.example/oauth/session",
    end_session_endpoint: "https://issuer.example/oauth/logout",
    jwks_uri: "https://issuer.example/oauth/jwks",
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    ...overrides,
  };
}

test("getUserInfo throws NO_ACCESS_TOKEN when token is missing", async () => {
  const client = createClient();

  try {
    await client.getUserInfo();
    expect(true).toBe(false);
  } catch (error) {
    expect(error).toBeInstanceOf(OidcClientError);
    if (error instanceof OidcClientError) {
      expect(error.code).toBe("NO_ACCESS_TOKEN");
    }
  }
});

test("getUserInfo throws NO_USERINFO_ENDPOINT when provider does not expose endpoint", async () => {
  const client = createClient();
  const testClient = client as unknown as {
    getStoredTokenResponse: () => { access_token?: string } | null;
    getOidcConfiguration: () => Promise<OidcConfiguration>;
  };

  testClient.getStoredTokenResponse = () => ({
    access_token: "access-token",
  });
  testClient.getOidcConfiguration = async () =>
    createOidcConfiguration({
      userinfo_endpoint: undefined,
    });

  try {
    await client.getUserInfo();
    expect(true).toBe(false);
  } catch (error) {
    expect(error).toBeInstanceOf(OidcClientError);
    if (error instanceof OidcClientError) {
      expect(error.code).toBe("NO_USERINFO_ENDPOINT");
    }
  }
});

test("handleSigninCallback rejects a callback without state", async () => {
  const client = createClient();

  await expect(
    client.handleSigninCallback(
      new URL("https://app.example/callback?code=code"),
    ),
  ).rejects.toMatchObject({ code: "MISSING_STATE" });
});

test("handleSigninCallback rejects an unknown state", async () => {
  const client = createClient();

  await expect(
    client.handleSigninCallback(
      new URL("https://app.example/callback?code=code&state=unknown"),
    ),
  ).rejects.toMatchObject({ code: "INVALID_STATE" });
});

test("getAccessToken refreshes an expired access token", async () => {
  const client = createClient();
  let requestBody: URLSearchParams | undefined;
  const testClient = client as unknown as {
    getStoredTokenResponse: () => {
      access_token: string;
      access_token_expires_at: number;
      refresh_token: string;
    };
    getOidcConfiguration: () => Promise<OidcConfiguration>;
    getClientId: () => Promise<string>;
    requestToken: (
      endpoint: string,
      headers: Record<string, string>,
      body: URLSearchParams,
    ) => Promise<{ access_token: string; expires_in: number }>;
    rememberTokenResponse: () => void;
  };
  testClient.getStoredTokenResponse = () => ({
    access_token: "expired",
    access_token_expires_at: 0,
    refresh_token: "refresh-token",
  });
  testClient.getOidcConfiguration = async () => createOidcConfiguration();
  testClient.getClientId = async () => "client-id";
  testClient.requestToken = async (_endpoint, _headers, body) => {
    requestBody = body;
    return { access_token: "refreshed", expires_in: 60 };
  };
  testClient.rememberTokenResponse = () => {};

  await expect(client.getAccessToken()).resolves.toBe("refreshed");
  expect(requestBody?.get("grant_type")).toBe("refresh_token");
  expect(requestBody?.get("refresh_token")).toBe("refresh-token");
  expect(requestBody?.get("client_id")).toBe("client-id");
});
