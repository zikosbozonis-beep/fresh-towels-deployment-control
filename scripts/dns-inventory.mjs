import { canonicalJson, sha256 } from "./control-contract.mjs";

const supportedTypes = new Set(["A", "AAAA", "CNAME", "MX", "TXT"]);

export function decodeCloudflareTxtContent(value) {
  if (typeof value !== "string" || /[\r\n\0]/.test(value)) {
    throw new Error("Cloudflare TXT content is malformed");
  }
  if (!value.startsWith('"')) {
    if (value.includes('"')) throw new Error("Cloudflare TXT content is malformed");
    return value;
  }
  let cursor = 0;
  let decoded = "";
  let chunks = 0;
  while (cursor < value.length) {
    while (cursor < value.length && /\s/.test(value[cursor])) cursor += 1;
    if (cursor >= value.length) break;
    if (value[cursor] !== '"') throw new Error("Cloudflare TXT content is malformed");
    cursor += 1;
    chunks += 1;
    let closed = false;
    while (cursor < value.length) {
      const character = value[cursor];
      cursor += 1;
      if (character === '"') {
        closed = true;
        break;
      }
      if (character !== "\\") {
        decoded += character;
        continue;
      }
      if (cursor >= value.length) throw new Error("Cloudflare TXT content is malformed");
      const decimal = value.slice(cursor, cursor + 3);
      if (/^[0-9]{3}$/.test(decimal)) {
        const code = Number(decimal);
        if (code > 255 || code === 0) throw new Error("Cloudflare TXT content is malformed");
        decoded += String.fromCharCode(code);
        cursor += 3;
      } else {
        decoded += value[cursor];
        cursor += 1;
      }
    }
    if (!closed) throw new Error("Cloudflare TXT content is malformed");
    if (cursor < value.length && !/\s/.test(value[cursor])) {
      throw new Error("Cloudflare TXT content is malformed");
    }
  }
  if (chunks < 1 || /[\r\n\0]/.test(decoded)) {
    throw new Error("Cloudflare TXT content is malformed");
  }
  return decoded;
}

export function canonicalDnsInventory(records) {
  if (!Array.isArray(records) || records.length > 10_000) {
    throw new Error("Cloudflare DNS inventory is malformed");
  }
  const normalized = records.map((record) => {
    if (
      record === null ||
      typeof record !== "object" ||
      Array.isArray(record) ||
      !supportedTypes.has(record.type) ||
      typeof record.name !== "string" ||
      typeof record.content !== "string" ||
      !Number.isSafeInteger(record.ttl) ||
      typeof record.proxied !== "boolean" ||
      (record.proxied && record.ttl !== 1) ||
      (record.priority !== undefined &&
        record.priority !== null &&
        !Number.isSafeInteger(record.priority))
    ) {
      throw new Error("Cloudflare DNS inventory contains an unsupported or malformed record");
    }
    return {
      type: record.type,
      name: record.name,
      content: record.type === "TXT" ? decodeCloudflareTxtContent(record.content) : record.content,
      proxied: record.proxied,
      ttl: record.ttl,
      priority: record.priority ?? null,
    };
  });
  normalized.sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return Object.freeze(normalized.map((record) => Object.freeze(record)));
}

export function dnsInventorySha256(records) {
  return sha256(Buffer.from(canonicalJson(canonicalDnsInventory(records)) + "\n", "utf8"));
}
