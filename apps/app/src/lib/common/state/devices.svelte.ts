import { invoke } from "@tauri-apps/api/core";
import type {
  DeviceEnrollment,
  DeviceInfo,
  DeviceState,
} from "@aicacia/idp-client";
import { idpApi, idpOwnerAccessToken } from "./idpClient.svelte";

export type { DeviceEnrollment, DeviceInfo, DeviceState };

export interface PendingNodeJoin {
  offer_id: string;
  authenticated_endpoint: string;
  request: {
    installation: string;
    member_id: string;
    endpoint_id: string;
    approving_peer: string;
    name: string;
    public_signer: Record<string, unknown>;
  };
}

async function nodeJoinBearer(): Promise<string> {
  const token = await idpOwnerAccessToken();
  if (!token) throw new Error("Sign in to manage Node joining");
  return token;
}

export async function nodeJoinAccepting(accepting?: boolean): Promise<boolean> {
  return invoke("node_join_accepting", {
    bearer: await nodeJoinBearer(),
    accepting,
  });
}

export async function pendingNodeJoins(): Promise<PendingNodeJoin[]> {
  return invoke("pending_node_joins", { bearer: await nodeJoinBearer() });
}

export async function approvePendingNodeJoin(offerId: string): Promise<void> {
  return invoke("approve_pending_node_join", {
    bearer: await nodeJoinBearer(),
    offerId,
  });
}

export async function rejectPendingNodeJoin(offerId: string): Promise<void> {
  return invoke("reject_pending_node_join", {
    bearer: await nodeJoinBearer(),
    offerId,
  });
}

export function listDevices(): Promise<DeviceInfo[]> {
  return idpApi.listDevices();
}

export function renameDevice(id: string, name: string): Promise<DeviceInfo> {
  return idpApi.updateDevice({ id, updateDeviceRequest: { name } });
}

export function revokeDevice(id: string): Promise<void> {
  return idpApi.revokeDevice({ id });
}
