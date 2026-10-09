import { invoke } from "@tauri-apps/api/core";
import type {
  DeviceEnrollment,
  DeviceInfo,
  DeviceState,
} from "@aicacia/idp-client";
import { getOidcClient } from "./oidc.svelte";
import { getIdpApiUrl, idpApi } from "./idpClient.svelte";

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

function nodeJoinBearer(): string {
  const token = getOidcClient()?.getStoredTokenResponse()?.access_token;
  if (!token) throw new Error("Sign in to manage Node joining");
  return token;
}

export function nodeJoinAccepting(accepting?: boolean): Promise<boolean> {
  return invoke("node_join_accepting", { bearer: nodeJoinBearer(), accepting });
}

export function pendingNodeJoins(): Promise<PendingNodeJoin[]> {
  return invoke("pending_node_joins", { bearer: nodeJoinBearer() });
}

export function approvePendingNodeJoin(offerId: string): Promise<void> {
  return invoke("approve_pending_node_join", {
    bearer: nodeJoinBearer(),
    offerId,
  });
}

export function rejectPendingNodeJoin(offerId: string): Promise<void> {
  return invoke("reject_pending_node_join", {
    bearer: nodeJoinBearer(),
    offerId,
  });
}

export function listDevices(): Promise<DeviceInfo[]> {
  return idpApi.listDevices();
}

export function enrollDevice(
  name: string,
  publicKey: string,
  address: string,
): Promise<DeviceEnrollment> {
  return idpApi.enrollDevice({
    deviceEnrollmentRequest: { name, publicKey, address },
  });
}

export function requestDevicePairing(
  name: string,
  publicKey: string,
  address: string,
  acceptingPublicKey: string,
): Promise<DeviceEnrollment> {
  return idpApi.requestPairing({
    devicePairingRequest: { name, publicKey, address, acceptingPublicKey },
  });
}
export async function getPairingAccepting(
  accepting?: boolean,
): Promise<boolean> {
  const baseUrl = getIdpApiUrl();
  if (!baseUrl) {
    throw new Error("Local API URL is not available");
  }
  const token = getOidcClient()?.getStoredTokenResponse()?.access_token;
  const response = await fetch(`${baseUrl}/devices/pairing-accepting`, {
    method: accepting === undefined ? "GET" : "PUT",
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(accepting === undefined
        ? {}
        : { "Content-Type": "application/json" }),
    },
    body: accepting === undefined ? undefined : JSON.stringify({ accepting }),
  });
  if (!response.ok) {
    throw new Error("Could not update pairing mode");
  }
  return ((await response.json()) as { accepting: boolean }).accepting;
}

export async function getDeviceApprovalPayload(id: number): Promise<string> {
  return (await idpApi.pairingApprovalPayload({ id })).payload;
}

export function approveDevice(
  id: number,
  signature: string,
): Promise<DeviceInfo> {
  return idpApi.approveDevice({
    id,
    devicePairingApprovalRequest: { signature },
  });
}

export function renameDevice(id: number, name: string): Promise<DeviceInfo> {
  return idpApi.updateDevice({ id, updateDeviceRequest: { name } });
}

export function revokeDevice(id: number): Promise<void> {
  return idpApi.revokeDevice({ id });
}
