import assert from "node:assert/strict";
import test from "node:test";

import { verifyConvergedDnsDelegation, verifyDnsDelegationOnce } from "../scripts/dns-delegation-verifier.mjs";

function json(value) {
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/dns-json" } });
}

function fetcher({ ds = [], googleNs = ["ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."] } = {}) {
  return async (url) => {
    const isDs = url.includes("type=DS");
    const nameservers = url.includes("dns.google") ? googleNs : ["bob.ns.cloudflare.com.", "ada.ns.cloudflare.com."];
    return json({ Status: 0, Answer: isDs ? ds : nameservers.map((data) => ({ type: 2, data })) });
  };
}

test("two independent DoH resolvers prove exact NS equality and DS NOERROR/NODATA", async () => {
  const result = await verifyDnsDelegationOnce({
    domain: "freshtowels.gr",
    expectedNameServers: ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
    fetcher: fetcher(),
  });
  assert.equal(result.cloudflareVerified, true);
  assert.equal(result.googleVerified, true);
  assert.equal(result.dsNoData, true);
});

test("resolver disagreement or a stale DS record fails closed", async () => {
  await assert.rejects(
    verifyDnsDelegationOnce({ domain: "freshtowels.gr", expectedNameServers: ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"], fetcher: fetcher({ googleNs: ["old.example.net.", "other.example.net."] }) }),
    /not converged/,
  );
  await assert.rejects(
    verifyDnsDelegationOnce({ domain: "freshtowels.gr", expectedNameServers: ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"], fetcher: fetcher({ ds: [{ type: 43, data: "1 13 2 deadbeef" }] }) }),
    /not converged/,
  );
});

test("bounded convergence retries reads only and returns the first exact state", async () => {
  let calls = 0;
  const stable = fetcher();
  const result = await verifyConvergedDnsDelegation({
    domain: "freshtowels.gr",
    expectedNameServers: ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"],
    attempts: 2,
    delay: async () => undefined,
    fetcher: async (...args) => {
      calls += 1;
      if (calls <= 2) throw new Error("synthetic transient DNS state");
      return stable(...args);
    },
  });
  assert.equal(result.dsNoData, true);
});
