#!/usr/bin/env node

import { randomBytes, randomUUID } from 'node:crypto';
import { appendFile } from 'node:fs/promises';

async function main() {
  const output = process.env.GITHUB_OUTPUT?.trim();
  if (!output) throw new Error('GITHUB_OUTPUT is required');
  const requestId = randomUUID();
  const nonce = randomBytes(32).toString('base64url');
  await appendFile(
    output,
    `request_id=${requestId}\nnonce=${nonce}\ntransport_tag=deployment-control/${requestId}\n`,
    'utf8',
  );
}

main().catch((error) => {
  console.error(`Packaging identity generation stopped: ${error.message}`);
  process.exitCode = 1;
});
