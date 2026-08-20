import crypto from 'node:crypto';

export function stableId(value) {
  const digest = crypto.createHash('sha256').update(value).digest();
  let id = 0n;
  for (let i = 0; i < 7; i += 1) id = (id << 8n) | BigInt(digest[i]);
  const safe = Number(id % 9007199254740000n);
  return safe === 0 ? 1 : safe;
}

export function packageKey(name, ecosystem = 'npm') {
  return `${ecosystem}:${name.trim().toLowerCase()}`;
}

export function versionKey(name, version, ecosystem = 'npm') {
  return `${packageKey(name, ecosystem)}@${version}`;
}
