const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function exactNameServer(value) {
  if (typeof value !== "string") throw new Error("DNS delegation nameserver is invalid");
  const normalized = value.toLowerCase().replace(/\.$/, "");
  if (!domainPattern.test(normalized)) throw new Error("DNS delegation nameserver is invalid");
  return normalized;
}

function exactExpectedNameServers(value) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error("DNS delegation must contain exactly two nameservers");
  }
  const normalized = value.map(exactNameServer).sort();
  if (new Set(normalized).size !== 2) throw new Error("DNS delegation nameservers are duplicated");
  return normalized;
}

async function dnsJson(fetcher, url, label) {
  let response;
  try {
    response = await fetcher(url, {
      headers: { accept: "application/dns-json" },
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new Error(label + " DNS-over-HTTPS transport failed");
  }
  if (!response.ok) throw new Error(label + " DNS-over-HTTPS request failed");
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength < 2 || bytes.byteLength > 131_072) {
    throw new Error(label + " DNS-over-HTTPS response boundary failed");
  }
  let body;
  try {
    body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(label + " DNS-over-HTTPS response is invalid");
  }
  if (body?.Status !== 0) throw new Error(label + " DNS-over-HTTPS status is not NOERROR");
  return body;
}

function nsAnswers(body) {
  return (Array.isArray(body.Answer) ? body.Answer : [])
    .filter((answer) => answer?.type === 2)
    .map((answer) => exactNameServer(answer.data))
    .sort();
}

function hasDsAnswer(body) {
  return (Array.isArray(body.Answer) ? body.Answer : []).some((answer) => answer?.type === 43);
}

export async function verifyDnsDelegationOnce({
  domain,
  expectedNameServers,
  fetcher = globalThis.fetch,
}) {
  if (domain !== "freshtowels.gr" || typeof fetcher !== "function") {
    throw new Error("DNS delegation verification target is invalid");
  }
  const expected = exactExpectedNameServers(expectedNameServers);
  const encoded = encodeURIComponent(domain);
  const queries = [
    {
      label: "Cloudflare",
      ns: `https://cloudflare-dns.com/dns-query?name=${encoded}&type=NS`,
      ds: `https://cloudflare-dns.com/dns-query?name=${encoded}&type=DS`,
    },
    {
      label: "Google",
      ns: `https://dns.google/resolve?name=${encoded}&type=NS`,
      ds: `https://dns.google/resolve?name=${encoded}&type=DS`,
    },
  ];
  const results = [];
  for (const query of queries) {
    const [ns, ds] = await Promise.all([
      dnsJson(fetcher, query.ns, query.label),
      dnsJson(fetcher, query.ds, query.label),
    ]);
    const actual = nsAnswers(ns);
    results.push({
      resolver: query.label.toLowerCase(),
      nameservers: actual,
      nsMatches: JSON.stringify(actual) === JSON.stringify(expected),
      dsNoData: !hasDsAnswer(ds),
    });
  }
  if (results.some((result) => !result.nsMatches || !result.dsNoData)) {
    throw new Error("DNS delegation has not converged to the exact safe state");
  }
  return Object.freeze({
    nameservers: expected,
    cloudflareVerified: true,
    googleVerified: true,
    dsNoData: true,
  });
}

export async function verifyConvergedDnsDelegation({
  attempts = 12,
  delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  ...input
}) {
  if (!Number.isSafeInteger(attempts) || attempts < 1 || attempts > 30 || typeof delay !== "function") {
    throw new Error("DNS convergence boundary is invalid");
  }
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await verifyDnsDelegationOnce(input);
    } catch (error) {
      lastError = error;
      if (attempt + 1 < attempts) await delay(10_000);
    }
  }
  throw lastError ?? new Error("DNS delegation convergence failed");
}
