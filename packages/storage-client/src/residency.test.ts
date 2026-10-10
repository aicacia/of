import { expect, it, vi } from "vitest";
import {
  ResidencyMode,
  ResourcesResidencyApi,
  StorageOwnerConfiguration,
} from "./index.js";

it("calls the generated public owner with one Storage prefix, exact target and transient bearer", async () => {
  const fetchApi = vi
    .fn()
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
    .mockResolvedValueOnce(Response.json({ mode: "passthrough" }));
  const api = new ResourcesResidencyApi(
    new StorageOwnerConfiguration({
      basePath: "https://localhost:4443/storage",
      accessToken: "transient-user-token",
      fetchApi,
    }),
  );
  await api.putFileSystemResidency({
    filesystemId: "01900000-0000-7000-8000-000000000001",
    resourceResidency: { mode: ResidencyMode.Passthrough },
  });
  expect(fetchApi.mock.calls[0]?.[0]).toBe(
    "https://localhost:4443/storage/filesystems/01900000-0000-7000-8000-000000000001/residency",
  );
  expect(fetchApi.mock.calls[0]?.[1]).toMatchObject({
    method: "PUT",
    headers: { Authorization: "Bearer transient-user-token" },
    body: '{"mode":"passthrough"}',
  });
  await expect(
    api.getFileSystemResidency({
      filesystemId: "01900000-0000-7000-8000-000000000001",
    }),
  ).resolves.toEqual({ mode: "passthrough" });
});

it.each([401, 403, 409, 500, 503])(
  "preserves owner failure %i without success or fallback",
  async (status) => {
    const fetchApi = vi.fn().mockResolvedValue(new Response(null, { status }));
    const api = new ResourcesResidencyApi(
      new StorageOwnerConfiguration({
        basePath: "https://localhost:4443/storage",
        accessToken: "transient-user-token",
        fetchApi,
      }),
    );
    await expect(
      api.putFileSystemResidency({
        filesystemId: "01900000-0000-7000-8000-000000000001",
        resourceResidency: { mode: ResidencyMode.Full },
      }),
    ).rejects.toMatchObject({ response: { status } });
    expect(fetchApi).toHaveBeenCalledTimes(1);
  },
);
