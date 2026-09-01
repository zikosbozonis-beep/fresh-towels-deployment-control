import { canonicalJson, sha256 } from "./control-contract.mjs";

const allowedRedirectStatuses = new Set([301, 302, 307, 308]);

async function boundedFetch(fetcher, url) {
  let response;
  try {
    response = await fetcher(url, {
      method: "GET",
      redirect: "manual",
      headers: { accept: "text/html,application/xhtml+xml" },
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw new Error("WordPress fallback transport failed");
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength > 2 * 1024 * 1024) {
    throw new Error("WordPress fallback response exceeded its boundary");
  }
  return { response, bytes };
}

function safeLocation(response) {
  const location = response.headers.get("location");
  if (!location) return null;
  let url;
  try {
    url = new URL(location, "https://freshtowels.gr");
  } catch {
    throw new Error("WordPress fallback redirect is invalid");
  }
  if (url.protocol !== "https:" || url.hostname !== "freshtowels.gr") {
    throw new Error("WordPress fallback redirect leaves the canonical host");
  }
  return url.pathname + url.search;
}

export async function verifyWordPressFallback({ fetcher = globalThis.fetch } = {}) {
  if (typeof fetcher !== "function") {
    throw new Error("WordPress fallback verifier is unavailable");
  }
  const [home, www, pricing] = await Promise.all([
    boundedFetch(fetcher, "https://freshtowels.gr/"),
    boundedFetch(fetcher, "https://www.freshtowels.gr/"),
    boundedFetch(fetcher, "https://freshtowels.gr/prices/"),
  ]);
  if (home.response.status !== 200 || home.bytes.byteLength < 256) {
    throw new Error("WordPress fallback home is unavailable through Cloudflare");
  }
  if (!allowedRedirectStatuses.has(www.response.status) || safeLocation(www.response) !== "/") {
    throw new Error("WordPress fallback www canonical redirect differs");
  }
  if (
    pricing.response.status !== 200 &&
    !allowedRedirectStatuses.has(pricing.response.status)
  ) {
    throw new Error("WordPress fallback legacy pricing route is unavailable");
  }
  const pricingLocation = allowedRedirectStatuses.has(pricing.response.status)
    ? safeLocation(pricing.response)
    : null;
  const proof = {
    homeStatus: home.response.status,
    homeBytesSha256: sha256(home.bytes),
    pricingLocation,
    pricingStatus: pricing.response.status,
    wwwLocation: "/",
    wwwStatus: www.response.status,
  };
  return Object.freeze({
    verified: true,
    proofSha256: sha256(Buffer.from(canonicalJson(proof) + "\n", "utf8")),
  });
}
