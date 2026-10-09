import { EventEmitter } from "eventemitter3";
import type { OidcClientConfig } from "./OidcClientConfig.js";
import { OidcClientError } from "./OidcClientError.js";
import type { OidcClientMetadata } from "./OidcClientMetadata.js";
import type { OidcClientRegistrationResponse } from "./OidcClientRegistrationResponse.js";
import type { OidcConfiguration } from "./OidcConfiguration.js";
import {
  createFetchWithTimeout,
  type Fetch,
} from "./util/createFetchWithTimeout.js";
import { generatePkcePair } from "./util/generatePkcePair.js";
import {
  createNativeFetch,
  generateState,
  isNativeProtocol,
  NativeFetch,
  openUrl,
} from "@aicacia/native-fetch";
import { snakeCase, snakeCaseKeys } from "./util/snakeCaseKeys.js";

export type OidcClientEvents = {
  registered: (response: OidcClientRegistrationResponse) => void;
  error: (error: unknown) => void;
};

export type OidcClientOptions = {
  clientConfig: OidcClientConfig;
  disableNativeRequests?: boolean;
  storage?: "local" | "memory";
  fetch?: Fetch;
};

export type AuthorizationUrlOptions = {
  state?: string;
  extraParams?: Record<string, string | number | boolean>;
};

export type RegistrationOptions = {
  redirectUri?: string;
  registration?: OidcClientMetadata;
  popup?: boolean;
  windowFeatures?: string;
};

const PKCE_STORAGE_PREFIX = "oidc.pkce";
const TOKEN_STORAGE_PREFIX = "oidc.token";

const OPTIONAL_AUTHORIZATION_PARAMS = [
  "prompt",
  "display",
  "maxAge",
  "uiLocales",
  "acrValues",
  "resource",
  "responseMode",
] as const;

export type SigninOptions = AuthorizationUrlOptions & {
  popup?: boolean;
  extraParams?: Record<string, string | number | boolean>;
  windowFeatures?: string;
};

export type SignoutOptions = {
  redirectUri?: string;
  extraParams?: Record<string, string | number | boolean>;
  popup?: boolean;
  windowFeatures?: string;
};

export type OidcUserInfo = {
  sub: string;
  [key: string]: unknown;
};

export type OidcTokenResponse = {
  access_token?: string;
  id_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number | string;
  access_token_expires_at?: number;
  refresh_token_expires_in?: number | string;
  scope?: string;
  state?: string;
  [key: string]: unknown;
};

export class OidcClient<
  UserInfo extends OidcUserInfo = OidcUserInfo,
> extends EventEmitter<OidcClientEvents> {
  private readonly config: OidcClientConfig;
  private readonly disableNativeRequests: boolean;
  private readonly nativeFetch: NativeFetch;
  private readonly fetch: Fetch;
  private readonly memoryOnly: boolean;
  private tokenResponse: OidcTokenResponse | null = null;

  private oidcConfigPromise: Promise<OidcConfiguration> | null = null;
  private readonly pkceVerifiersByState = new Map<string, string>();
  private lastPkceVerifier: string | null = null;
  private readonly pkceStoragePrefix: string;
  private readonly tokenStoragePrefix: string;

  constructor(options: OidcClientOptions) {
    super();
    this.config = OidcClient.validateConfig(options.clientConfig);
    this.pkceStoragePrefix = `${PKCE_STORAGE_PREFIX}:${this.config.authority}`;
    this.tokenStoragePrefix = `${TOKEN_STORAGE_PREFIX}:${this.config.authority}`;
    this.memoryOnly = options.storage === "memory";
    if (this.memoryOnly) this.removePersistentSession();
    this.disableNativeRequests = options.disableNativeRequests ?? false;
    this.nativeFetch = createNativeFetch(this.config.authority);
    this.fetch = this.config.requestTimeoutInSeconds
      ? createFetchWithTimeout(
          this.config.requestTimeoutInSeconds * 1000,
          options.fetch,
        )
      : (options.fetch ?? fetch);
  }

  private removePersistentSession(): void {
    if (typeof window === "undefined") return;
    const storage = window.localStorage;
    for (let index = storage.length - 1; index >= 0; index--) {
      const key = storage.key(index);
      if (
        key?.startsWith(`${TOKEN_STORAGE_PREFIX}:`) ||
        key?.startsWith(`${PKCE_STORAGE_PREFIX}:`)
      ) {
        storage.removeItem(key);
      }
    }
  }

  private getStorage(): Storage | null {
    if (this.memoryOnly || typeof window === "undefined") {
      return null;
    }
    try {
      return window.localStorage;
    } catch {
      return null;
    }
  }

  private getPkceStorageKey(state: string): string {
    return `${this.pkceStoragePrefix}:state:${state}`;
  }

  private getPkceLastStorageKey(): string {
    return `${this.pkceStoragePrefix}:last`;
  }

  private getTokenStorageKey(): string {
    return `${this.tokenStoragePrefix}:response`;
  }

  private rememberTokenResponse(tokenResponse: OidcTokenResponse): void {
    if (this.memoryOnly) {
      this.tokenResponse = tokenResponse;
      return;
    }
    const storage = this.getStorage();
    if (!storage) {
      return;
    }
    storage.setItem(this.getTokenStorageKey(), JSON.stringify(tokenResponse));
  }

  getStoredTokenResponse(): OidcTokenResponse | null {
    if (this.memoryOnly) return this.tokenResponse;
    const storage = this.getStorage();
    if (!storage) {
      return null;
    }
    const value = storage.getItem(this.getTokenStorageKey());
    if (!value) {
      return null;
    }
    try {
      return JSON.parse(value) as OidcTokenResponse;
    } catch {
      return null;
    }
  }

  setToken(tokenResponse: OidcTokenResponse) {
    this.rememberTokenResponse(this.normalizeTokenResponse(tokenResponse));
  }

  clearStoredTokenResponse(): void {
    this.tokenResponse = null;
    if (this.memoryOnly) {
      this.pkceVerifiersByState.clear();
      this.lastPkceVerifier = null;
      this.removePersistentSession();
      return;
    }
    const storage = this.getStorage();
    if (!storage) {
      return;
    }
    storage.removeItem(this.getTokenStorageKey());
  }

  private rememberPkceVerifier(state: string, codeVerifier: string): void {
    this.pkceVerifiersByState.set(state, codeVerifier);
    this.lastPkceVerifier = codeVerifier;

    const storage = this.getStorage();
    if (!storage) {
      return;
    }
    storage.setItem(this.getPkceStorageKey(state), codeVerifier);
    storage.setItem(this.getPkceLastStorageKey(), codeVerifier);
  }

  private consumePkceVerifier(state?: string | null): string | undefined {
    const storage = this.getStorage();
    if (state) {
      const memoryValue = this.pkceVerifiersByState.get(state);
      this.pkceVerifiersByState.delete(state);
      const storageKey = this.getPkceStorageKey(state);
      const storageValue = storage?.getItem(storageKey) ?? null;
      storage?.removeItem(storageKey);
      storage?.removeItem(this.getPkceLastStorageKey());
      this.lastPkceVerifier = null;
      return memoryValue ?? storageValue ?? undefined;
    }

    const last =
      this.lastPkceVerifier ??
      storage?.getItem(this.getPkceLastStorageKey()) ??
      null;
    this.lastPkceVerifier = null;
    storage?.removeItem(this.getPkceLastStorageKey());
    return last ?? undefined;
  }

  private readCallbackParam(
    queryParams: URLSearchParams,
    hashParams: URLSearchParams,
    name: string,
  ): string | null {
    return queryParams.get(name) ?? hashParams.get(name);
  }

  private getHashParams(url: URL): URLSearchParams {
    let hash = "";

    try {
      hash = url.hash;
    } catch {
      if (typeof window !== "undefined") {
        hash = new URL(window.location.href).hash;
      }
    }

    return new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);
  }

  private normalizeTokenResponse(input: OidcTokenResponse): OidcTokenResponse {
    const expiresInRaw = input.expires_in;
    const expiresIn =
      typeof expiresInRaw === "number"
        ? expiresInRaw
        : typeof expiresInRaw === "string"
          ? Number.parseInt(expiresInRaw, 10)
          : undefined;
    const refreshTokenExpiresInRaw = input.refresh_token_expires_in;
    const refreshTokenExpiresIn =
      typeof refreshTokenExpiresInRaw === "number"
        ? refreshTokenExpiresInRaw
        : typeof refreshTokenExpiresInRaw === "string"
          ? Number.parseInt(refreshTokenExpiresInRaw, 10)
          : undefined;

    return {
      ...input,
      access_token:
        typeof input.access_token === "string" ? input.access_token : undefined,
      id_token: typeof input.id_token === "string" ? input.id_token : undefined,
      refresh_token:
        typeof input.refresh_token === "string"
          ? input.refresh_token
          : undefined,
      token_type:
        typeof input.token_type === "string" ? input.token_type : undefined,
      expires_in: Number.isNaN(expiresIn ?? Number.NaN) ? undefined : expiresIn,
      access_token_expires_at:
        typeof input.access_token_expires_at === "number"
          ? input.access_token_expires_at
          : typeof expiresIn === "number"
            ? Date.now() + expiresIn * 1000
            : undefined,
      refresh_token_expires_in: Number.isNaN(
        refreshTokenExpiresIn ?? Number.NaN,
      )
        ? undefined
        : refreshTokenExpiresIn,
      scope: typeof input.scope === "string" ? input.scope : undefined,
      state: typeof input.state === "string" ? input.state : undefined,
    };
  }

  private buildTokenRequest(
    clientId: string,
    code: string,
    codeVerifier?: string,
  ): { headers: Record<string, string>; body: URLSearchParams } {
    const body = new URLSearchParams();
    const headers = this.addClientAuthentication(clientId, body);

    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", this.getRedirectUri());
    if (codeVerifier) {
      body.set("code_verifier", codeVerifier);
    }

    return { headers, body };
  }

  private addClientAuthentication(
    clientId: string,
    body: URLSearchParams,
  ): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    const tokenEndpointAuthMethod =
      this.config.registration?.tokenEndpointAuthMethod;

    if (tokenEndpointAuthMethod === "client_secret_post") {
      body.set("client_id", clientId);
      if (this.config.clientSecret) {
        body.set("client_secret", this.config.clientSecret);
      }
    } else if (
      tokenEndpointAuthMethod === "none" ||
      !this.config.clientSecret
    ) {
      body.set("client_id", clientId);
    } else {
      headers.Authorization = `Basic ${this.encodeBasicAuth(clientId, this.config.clientSecret)}`;
    }

    return headers;
  }

  private encodeBasicAuth(clientId: string, clientSecret: string): string {
    const value = `${clientId}:${clientSecret}`;
    if (typeof btoa === "function") {
      return btoa(value);
    }
    const bufferCtor = (
      globalThis as {
        Buffer?: {
          from(
            data: string,
            encoding: string,
          ): { toString(encoding: string): string };
        };
      }
    ).Buffer;
    if (bufferCtor) {
      return bufferCtor.from(value, "utf8").toString("base64");
    }
    throw new Error("No base64 encoder available for basic auth");
  }

  private isTimeoutError(error: unknown): boolean {
    if (!(error instanceof Error)) {
      return false;
    }
    if (error.name === "AbortError") {
      return true;
    }
    return error.message.toLowerCase().includes("timeout");
  }

  private async getResponseText(
    response: Response,
  ): Promise<string | undefined> {
    try {
      const responseText = await response.clone().text();
      return responseText ? responseText : undefined;
    } catch {
      return undefined;
    }
  }

  async getUserInfo(): Promise<UserInfo> {
    const tokenResponse = this.getStoredTokenResponse();
    const accessToken = tokenResponse?.access_token;
    if (!accessToken) {
      throw new OidcClientError(
        "NO_ACCESS_TOKEN",
        "Missing access token in stored token response",
      );
    }

    const config = await this.getOidcConfiguration();
    if (!config.userinfo_endpoint) {
      throw new OidcClientError(
        "NO_USERINFO_ENDPOINT",
        "Provider does not support userinfo endpoint",
        { endpoint: this.config.authority },
      );
    }
    const userInfoUrl = new URL(config.userinfo_endpoint);

    let userInfoResponse: Response;
    try {
      const isNative =
        !this.disableNativeRequests && isNativeProtocol(userInfoUrl);
      if (isNative) {
        userInfoResponse = await this.nativeFetch(userInfoUrl, {
          method: "GET",
          headers: {
            "Content-Type": "application/json;charset=UTF-8",
            Authorization: `Bearer ${accessToken}`,
          },
          credentials: this.config.fetchRequestCredentials ?? "same-origin",
          timeout: this.config.requestTimeoutInSeconds
            ? this.config.requestTimeoutInSeconds * 1000
            : undefined,
        });
      } else {
        userInfoResponse = await this.fetch(userInfoUrl, {
          method: "GET",
          headers: {
            "Content-Type": "application/json;charset=UTF-8",
            Authorization: `Bearer ${accessToken}`,
          },
          credentials: this.config.fetchRequestCredentials ?? "same-origin",
        });
      }
    } catch (error: unknown) {
      if (this.isTimeoutError(error)) {
        throw new OidcClientError(
          "NETWORK_TIMEOUT",
          "Userinfo request timed out",
          {
            endpoint: userInfoUrl.toString(),
            cause: error,
          },
        );
      }
      throw new OidcClientError("NETWORK_ERROR", "Userinfo request failed", {
        endpoint: userInfoUrl.toString(),
        cause: error,
      });
    }
    if (!userInfoResponse.ok) {
      throw new OidcClientError(
        "HTTP_ERROR",
        `Failed userinfo request: ${userInfoResponse.status} ${userInfoResponse.statusText}`,
        {
          status: userInfoResponse.status,
          statusText: userInfoResponse.statusText,
          endpoint: userInfoUrl.toString(),
          responseText: await this.getResponseText(userInfoResponse),
        },
      );
    }

    let userInfo: UserInfo;
    try {
      userInfo = (await userInfoResponse.json()) as UserInfo;
    } catch (error: unknown) {
      throw new OidcClientError(
        "JSON_PARSE_ERROR",
        "Failed to parse userinfo response",
        {
          endpoint: userInfoUrl.toString(),
          cause: error,
        },
      );
    }

    if (
      !userInfo ||
      typeof userInfo !== "object" ||
      typeof (userInfo as OidcUserInfo).sub !== "string"
    ) {
      throw new OidcClientError(
        "INVALID_USERINFO_RESPONSE",
        "Userinfo response did not include a valid sub claim",
        {
          endpoint: userInfoUrl.toString(),
        },
      );
    }

    return userInfo;
  }

  private async requestToken(
    tokenEndpointUrlOrString: URL | string,
    headers: Record<string, string>,
    body: URLSearchParams,
  ): Promise<OidcTokenResponse> {
    const tokenEndpointUrl =
      typeof tokenEndpointUrlOrString === "string"
        ? new URL(tokenEndpointUrlOrString)
        : tokenEndpointUrlOrString;
    const isNative =
      !this.disableNativeRequests && isNativeProtocol(tokenEndpointUrl);

    if (isNative) {
      const response = await this.nativeFetch(tokenEndpointUrl, {
        method: "POST",
        headers,
        body: body.toString(),
        credentials: this.config.fetchRequestCredentials ?? "same-origin",
        timeout: this.config.requestTimeoutInSeconds
          ? this.config.requestTimeoutInSeconds * 1000
          : undefined,
      });
      if (!response.ok) {
        throw new Error(
          `Failed token request: ${response.status} ${response.statusText}`,
        );
      }
      return (await response.json()) as OidcTokenResponse;
    }

    const response = await this.fetch(tokenEndpointUrl, {
      method: "POST",
      headers,
      body: body.toString(),
      credentials: this.config.fetchRequestCredentials ?? "same-origin",
    });

    if (!response.ok) {
      throw new Error(
        `Failed token request: ${response.status} ${response.statusText}`,
      );
    }

    return (await response.json()) as OidcTokenResponse;
  }

  async handleSigninCallback(url?: URL): Promise<OidcTokenResponse | null> {
    if (!url) {
      url = new URL(window.location.href);
    }

    const queryParams = url.searchParams;
    const hashParams = this.getHashParams(url);

    const callbackError = this.readCallbackParam(
      queryParams,
      hashParams,
      "error",
    );
    if (callbackError) {
      throw new Error(callbackError);
    }

    const callbackState = this.readCallbackParam(
      queryParams,
      hashParams,
      "state",
    );

    const accessToken = this.readCallbackParam(
      queryParams,
      hashParams,
      "access_token",
    );
    const idToken = this.readCallbackParam(queryParams, hashParams, "id_token");
    if (accessToken || idToken) {
      const tokenResponse = this.normalizeTokenResponse({
        access_token: accessToken ?? undefined,
        id_token: idToken ?? undefined,
        refresh_token:
          this.readCallbackParam(queryParams, hashParams, "refresh_token") ??
          undefined,
        token_type:
          this.readCallbackParam(queryParams, hashParams, "token_type") ??
          undefined,
        expires_in:
          this.readCallbackParam(queryParams, hashParams, "expires_in") ??
          undefined,
        refresh_token_expires_in:
          this.readCallbackParam(
            queryParams,
            hashParams,
            "refresh_token_expires_in",
          ) ?? undefined,
        scope:
          this.readCallbackParam(queryParams, hashParams, "scope") ?? undefined,
        state: callbackState ?? undefined,
      });
      this.rememberTokenResponse(tokenResponse);
      return tokenResponse;
    }

    const authorizationCode = this.readCallbackParam(
      queryParams,
      hashParams,
      "code",
    );
    if (!authorizationCode) {
      return null;
    }

    if (!callbackState) {
      throw new OidcClientError(
        "MISSING_STATE",
        "Signin callback is missing state",
      );
    }

    const codeVerifier = this.consumePkceVerifier(callbackState);
    if (!codeVerifier) {
      throw new OidcClientError(
        "INVALID_STATE",
        "Signin callback state is unknown or has expired",
      );
    }

    const config = await this.getOidcConfiguration();
    const clientId = await this.getClientId(config);
    const { headers, body } = this.buildTokenRequest(
      clientId,
      authorizationCode,
      codeVerifier,
    );
    const json = await this.requestToken(config.token_endpoint, headers, body);
    const tokenResponse = this.normalizeTokenResponse({
      ...json,
      state: callbackState ?? json.state,
    });
    this.rememberTokenResponse(tokenResponse);
    return tokenResponse;
  }

  async refreshToken(): Promise<OidcTokenResponse> {
    const storedToken = this.getStoredTokenResponse();
    if (!storedToken?.refresh_token) {
      throw new OidcClientError(
        "NO_REFRESH_TOKEN",
        "Missing refresh token in stored token response",
      );
    }

    const config = await this.getOidcConfiguration();
    const clientId = await this.getClientId(config);
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: storedToken.refresh_token,
    });
    const headers = this.addClientAuthentication(clientId, body);
    const refreshed = this.normalizeTokenResponse({
      ...storedToken,
      ...(await this.requestToken(config.token_endpoint, headers, body)),
    });
    this.rememberTokenResponse(refreshed);
    return refreshed;
  }

  async getAccessToken(): Promise<string> {
    const storedToken = this.getStoredTokenResponse();
    if (!storedToken?.access_token && !storedToken?.refresh_token) {
      throw new OidcClientError(
        "NO_ACCESS_TOKEN",
        "Missing access token in stored token response",
      );
    }

    if (
      storedToken.access_token &&
      typeof storedToken.access_token_expires_at === "number" &&
      storedToken.access_token_expires_at > Date.now() + 30_000
    ) {
      return storedToken.access_token;
    }

    if (storedToken.refresh_token) {
      const refreshed = await this.refreshToken();
      if (refreshed.access_token) {
        return refreshed.access_token;
      }
    }

    throw new OidcClientError(
      "NO_ACCESS_TOKEN",
      "Missing refreshed access token",
    );
  }

  static validateConfig(config: OidcClientConfig): OidcClientConfig {
    if (!config.authority || typeof config.authority !== "string") {
      throw new Error("Invalid authority URL");
    }
    config.authority = config.authority.endsWith("/")
      ? config.authority.slice(0, -1)
      : config.authority;

    if (
      config.redirectUri !== undefined &&
      typeof config.redirectUri !== "string"
    ) {
      throw new Error("Invalid redirectUri");
    }

    if (!OidcClient.resolveRedirectUri(config)) {
      throw new Error(
        "Missing redirectUri: set redirectUri or registration.redirectUris[0]",
      );
    }

    return config;
  }

  private static resolveRedirectUri(
    config: OidcClientConfig,
  ): string | undefined {
    return config.redirectUri ?? config.registration?.redirectUris?.[0];
  }

  private getRedirectUri(): string {
    return OidcClient.resolveRedirectUri(this.config) ?? "";
  }

  private getRegistrationMetadata(): OidcClientMetadata {
    if (!this.config.registration) {
      throw new Error(
        "Missing registration metadata for dynamic client registration",
      );
    }
    return this.config.registration;
  }

  private async fetchOidcConfiguration(): Promise<OidcConfiguration> {
    const urlString = `${this.config.authority}/.well-known/openid-configuration`;
    const url = new URL(urlString);
    const isNative = !this.disableNativeRequests && isNativeProtocol(url);

    if (isNative) {
      const response = await this.nativeFetch(url, {
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
        },
        timeout: this.config.requestTimeoutInSeconds
          ? this.config.requestTimeoutInSeconds * 1000
          : undefined,
      });
      if (!response.ok) {
        throw new Error(
          `Failed to fetch OIDC configuration: ${response.status} ${response.statusText}`,
        );
      }
      return (await response.json()) as OidcConfiguration;
    }

    const res = await this.fetch(url, {
      credentials: this.config.fetchRequestCredentials ?? "same-origin",
    });
    if (!res.ok) {
      throw new Error(
        `Failed to fetch OIDC configuration: ${res.status} ${res.statusText}`,
      );
    }
    return res.json() as Promise<OidcConfiguration>;
  }

  async getOidcConfiguration(): Promise<OidcConfiguration> {
    if (!this.oidcConfigPromise) {
      this.oidcConfigPromise = this.fetchOidcConfiguration();
    }
    return this.oidcConfigPromise;
  }

  async signin(options: SigninOptions = {}): Promise<void> {
    const url = await this.getAuthorizationUrl(options);

    console.debug(
      "Opening signin URL:",
      url.toString(),
      JSON.stringify(options, null, 2),
    );

    openUrl(url, {
      popup: options.popup,
      windowFeatures: options.windowFeatures,
    });
  }

  async signout(options: SignoutOptions = {}): Promise<void> {
    const config = await this.getOidcConfiguration();
    if (config.end_session_endpoint) {
      const url = new URL(config.end_session_endpoint);
      if (options.extraParams) {
        for (const [k, v] of Object.entries(options.extraParams)) {
          url.searchParams.set(k, String(v));
        }
      }
      if (options.redirectUri) {
        url.searchParams.set("post_logout_redirect_uri", options.redirectUri);
      }

      openUrl(url, {
        popup: options.popup,
        windowFeatures: options.windowFeatures,
      });
    }
    this.clearStoredTokenResponse();
  }

  async getRegistrationUrl(options: RegistrationOptions = {}): Promise<URL> {
    const config = await this.getOidcConfiguration();
    if (!config.registration_endpoint) {
      throw new Error("Provider does not support dynamic client registration");
    }

    const url = new URL(config.registration_endpoint);
    url.searchParams.set(
      "redirect_uri",
      options.redirectUri ?? this.getRedirectUri(),
    );
    if (options.registration) {
      url.searchParams.set(
        "registration",
        JSON.stringify(snakeCaseKeys(options.registration)),
      );
    }
    return url;
  }

  async startRegistration(options: RegistrationOptions = {}): Promise<URL> {
    const url = await this.getRegistrationUrl(options);

    await openUrl(url, {
      popup: options.popup,
      windowFeatures: options.windowFeatures,
    });
    return url;
  }

  private async registerClient(config: OidcConfiguration): Promise<string> {
    const endpointUrlString = config.registration_endpoint;
    if (!endpointUrlString) {
      throw new Error(
        "registration_endpoint is required for dynamic client registration",
      );
    }
    const endpointUrl = new URL(endpointUrlString);
    const isNative =
      !this.disableNativeRequests && isNativeProtocol(endpointUrl);

    if (isNative) {
      const nativeFetch = createNativeFetch(endpointUrl);
      const registrationMetadata = this.getRegistrationMetadata();
      endpointUrl.searchParams.set("redirect_uri", this.getRedirectUri());
      endpointUrl.searchParams.set(
        "registration",
        JSON.stringify(snakeCaseKeys(registrationMetadata)),
      );
      const response = await nativeFetch(endpointUrl, {
        headers: {
          "Content-Type": "application/json;charset=UTF-8",
        },
      });
      if (!response.ok) {
        throw new Error(
          `Failed dynamic client registration: ${response.status}`,
        );
      }
      const json = (await response.json()) as OidcClientRegistrationResponse;
      if (!json.client_id) {
        throw new Error("registration response missing client_id");
      }
      this.config.clientId = json.client_id;
      if (json.client_secret) {
        this.config.clientSecret = json.client_secret;
      }
      this.emit("registered", json);
      return json.client_id;
    }

    const res = await this.fetch(endpointUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json;charset=UTF-8" },
      body: JSON.stringify(snakeCaseKeys(this.getRegistrationMetadata())),
    });
    if (!res.ok) {
      throw new Error(`Failed dynamic client registration: ${res.status}`);
    }

    const json = (await res.json()) as OidcClientRegistrationResponse;
    if (!json.client_id) {
      throw new Error("registration response missing client_id");
    }

    this.config.clientId = json.client_id;
    if (json.client_secret) {
      this.config.clientSecret = json.client_secret;
    }
    this.emit("registered", json);
    return json.client_id;
  }

  private async getClientId(config: OidcConfiguration): Promise<string> {
    if (this.config.clientId) {
      return this.config.clientId;
    }
    if (!config.registration_endpoint) {
      throw new Error("clientId is required for signin");
    }

    return await this.registerClient(config);
  }

  async getAuthorizationUrl(
    options: AuthorizationUrlOptions = {},
  ): Promise<URL> {
    const config = await this.getOidcConfiguration();
    const clientId = await this.getClientId(config);
    const url = new URL(config.authorization_endpoint);

    if (this.config.extraQueryParams) {
      for (const [k, v] of Object.entries(this.config.extraQueryParams)) {
        url.searchParams.set(k, String(v));
      }
    }

    if (options.extraParams) {
      for (const [k, v] of Object.entries(options.extraParams)) {
        url.searchParams.set(k, String(v));
      }
    }

    const responseType =
      this.config.responseType ??
      this.config.registration?.responseTypes?.[0] ??
      "code";

    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", this.getRedirectUri());
    url.searchParams.set("response_type", responseType);

    if (!this.config.omitScopeWhenRequesting) {
      url.searchParams.set(
        "scope",
        this.config.registration?.scope ?? "openid",
      );
    }

    const state = options.state ?? generateState();
    url.searchParams.set("state", state);

    if (responseType.includes("code")) {
      const pkcePair = await generatePkcePair();
      url.searchParams.set("code_challenge_method", "S256");
      url.searchParams.set("code_challenge", pkcePair.codeChallenge);
      this.rememberPkceVerifier(state, pkcePair.codeVerifier);
    }

    for (const key of OPTIONAL_AUTHORIZATION_PARAMS) {
      const value =
        this.config[key] ??
        (key === "maxAge"
          ? this.config.registration?.defaultMaxAge
          : key === "acrValues"
            ? this.config.registration?.defaultAcrValues?.join(" ")
            : key === "responseMode"
              ? "query"
              : undefined);
      if (value !== undefined && value !== null) {
        url.searchParams.set(snakeCase(key), String(value));
      }
    }

    if (this.config.registration) {
      url.searchParams.set(
        "registration",
        JSON.stringify(snakeCaseKeys(this.config.registration)),
      );
    }

    return url;
  }
}
