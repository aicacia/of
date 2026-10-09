import { json } from "@sveltejs/kit";
import { env } from "$env/dynamic/public";

export const prerender = true;

export function GET() {
  const fingerprint = env.PUBLIC_CERT_FINGERPRINT;
  if (!fingerprint) return json([]);
  return json([
    {
      relation: ["delegate_permission/common.handle_all_urls"],
      target: {
        namespace: "android_app",
        package_name: "com.aicacia.local",
        sha256_cert_fingerprints: [fingerprint],
      },
    },
  ]);
}
