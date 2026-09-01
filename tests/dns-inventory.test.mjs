import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalDnsInventory,
  decodeCloudflareTxtContent,
  dnsInventorySha256,
} from "../scripts/dns-inventory.mjs";

const base = {
  type: "A",
  name: "freshtowels.gr",
  content: "192.0.2.10",
  proxied: true,
  ttl: 1,
  priority: null,
};

test("DNS inventory identity ignores arbitrary provider IDs but binds every operational field", () => {
  const left = [{ ...base, id: "a".repeat(32) }];
  const right = [{ ...base, id: "b".repeat(32) }];
  assert.deepEqual(canonicalDnsInventory(left), canonicalDnsInventory(right));
  assert.equal(dnsInventorySha256(left), dnsInventorySha256(right));
  assert.notEqual(
    dnsInventorySha256(left),
    dnsInventorySha256([{ ...base, id: "a".repeat(32), proxied: false }]),
  );
});

test("DNS inventory rejects unsupported or malformed provider records rather than ignoring them", () => {
  assert.throws(
    () => canonicalDnsInventory([{ ...base, type: "CAA" }]),
    /unsupported or malformed/,
  );
  assert.throws(
    () => canonicalDnsInventory([{ ...base, proxied: "true" }]),
    /unsupported or malformed/,
  );
});

test("Cloudflare quoted SPF and split DKIM TXT readback normalize to exact logical bytes", () => {
  assert.equal(
    decodeCloudflareTxtContent('"v=spf1 include:amazonses.com ~all"'),
    "v=spf1 include:amazonses.com ~all",
  );
  assert.equal(
    decodeCloudflareTxtContent('"p=first" "second\\\"quoted"'),
    'p=firstsecond"quoted',
  );
  const logical = [{
    type: "TXT",
    name: "resend._domainkey.notify.freshtowels.gr",
    content: "p=firstsecond",
    proxied: false,
    ttl: 300,
    priority: null,
  }];
  assert.deepEqual(
    canonicalDnsInventory([{ ...logical[0], id: "a".repeat(32), content: '"p=first" "second"' }]),
    canonicalDnsInventory(logical),
  );
  for (const malformed of ['"unterminated', '"one"junk', 'plain"quote', '"bad\\000"']) {
    assert.throws(() => decodeCloudflareTxtContent(malformed), /malformed/);
  }
});
