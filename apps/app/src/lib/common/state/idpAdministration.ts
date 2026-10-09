import type { CreateApplicationRequest, GetApplicationRequest, ListApplicationsRequest, ListClientKeysRequest, ListConsentsRequest, UpdateApplicationRequest } from "@aicacia/idp-client";
import * as v from "valibot";
import { idpApi } from "./idpClient.svelte";

// These owner responses have no body schema in OpenAPI. Validate their actual wire contracts.
const id = v.pipe(v.string(), v.uuid());
const applicationSchema = v.object({ id, name: v.string(), uri: v.string(), description: v.nullable(v.string()), created_at: v.number(), updated_at: v.number() });
const consentSchema = v.object({ id, user_id: id, client_id: v.string(), redirect_uri: v.string(), scope: v.string(), created_at: v.number(), updated_at: v.number() });
const keySchema = v.object({ id, name: v.string(), derivation_path: v.string(), hardened: v.boolean(), public_jwk: v.nullable(v.record(v.string(), v.unknown())), revoked_at: v.nullable(v.number()), expires_at: v.nullable(v.number()) });
export type Application = v.InferOutput<typeof applicationSchema>;
export type Consent = v.InferOutput<typeof consentSchema>;
export type ClientKey = v.InferOutput<typeof keySchema>;

export const idpAdministration = {
  async listApplications(request: ListApplicationsRequest): Promise<Application[]> {
    return v.parse(v.array(applicationSchema), await (await idpApi.listApplicationsRaw(request)).raw.json());
  },
  async getApplication(request: GetApplicationRequest): Promise<Application> {
    return v.parse(applicationSchema, await (await idpApi.getApplicationRaw(request)).raw.json());
  },
  async createApplication(request: CreateApplicationRequest): Promise<Application> {
    return v.parse(applicationSchema, await (await idpApi.createApplicationRaw(request)).raw.json());
  },
  async updateApplication(request: UpdateApplicationRequest): Promise<Application> {
    return v.parse(applicationSchema, await (await idpApi.updateApplicationRaw(request)).raw.json());
  },
  async listConsents(request: ListConsentsRequest): Promise<Consent[]> {
    return v.parse(v.array(consentSchema), await (await idpApi.listConsentsRaw(request)).raw.json());
  },
  async listClientKeys(request: ListClientKeysRequest): Promise<ClientKey[]> {
    return v.parse(v.array(keySchema), await (await idpApi.listClientKeysRaw(request)).raw.json());
  },
};
