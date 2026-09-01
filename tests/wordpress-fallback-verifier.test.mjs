import assert from "node:assert/strict";
import test from "node:test";

import { verifyWordPressFallback } from "../scripts/wordpress-fallback-verifier.mjs";

function html(status, body = "x".repeat(300), location = null) {
  return new Response(body, { status, headers: location ? { location } : {} });
}

test("external WordPress fallback proves apex HTTPS, www canonical and the verified live price route", async () => {
  const urls = [];
  const result = await verifyWordPressFallback({ fetcher: async (url) => {
    urls.push(url);
    if (url === "https://www.freshtowels.gr/") return html(301, "", "https://freshtowels.gr/");
    return html(200);
  } });
  assert.equal(result.verified, true);
  assert.ok(urls.some((url) => new URL(url).pathname === "/prices/"));
});

test("fallback rejects off-host www redirects and an unavailable legacy route", async () => {
  await assert.rejects(
    verifyWordPressFallback({ fetcher: async (url) => url.includes("www") ? html(301, "", "https://evil.example/") : html(200) }),
    /canonical host/,
  );
  await assert.rejects(
    verifyWordPressFallback({ fetcher: async (url) => {
      if (url.includes("www")) return html(301, "", "https://freshtowels.gr/");
      if (new URL(url).pathname !== "/") return html(404, "not found");
      return html(200);
    } }),
    /legacy pricing route/,
  );
});
