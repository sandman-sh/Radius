const osvUrl = String(process.env.OSV_API_URL || 'https://api.osv.dev').replace(/\/$/, '');

const ecosystemNames = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
  go: 'Go',
  maven: 'Maven'
};

export async function scanDependencies(dependencies = []) {
  const normalized = uniqueDependencies(dependencies);
  const supported = normalized.filter((dependency) => ecosystemNames[dependency.ecosystem]);
  const skipped = normalized.filter((dependency) => !ecosystemNames[dependency.ecosystem]).map((dependency) => ({ ...dependency, reason: 'OSV ecosystem mapping unavailable' }));
  const findings = [];

  for (const chunk of chunks(supported, 100)) {
    const response = await fetch(`${osvUrl}/v1/querybatch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ queries: chunk.map((dependency) => ({ package: { name: dependency.name, ecosystem: ecosystemNames[dependency.ecosystem] }, version: dependency.version })) }),
      signal: AbortSignal.timeout(20000)
    });
    if (!response.ok) throw new Error(`OSV returned ${response.status}.`);
    const body = await response.json();
    const results = Array.isArray(body.results) ? body.results : [];
    const ids = results.flatMap((result, index) => (result?.vulns || []).map((vulnerability) => ({ ...vulnerability, dependency: chunk[index] }))).filter((item) => item.id);
    const details = await mapWithConcurrency(ids, 8, async (item) => {
      try {
        const detailResponse = await fetch(`${osvUrl}/v1/vulns/${encodeURIComponent(item.id)}`, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(12000) });
        if (!detailResponse.ok) return normalizeFinding(item, null);
        return normalizeFinding(item, await detailResponse.json());
      } catch {
        return normalizeFinding(item, null);
      }
    });
    findings.push(...details);
  }

  return { source: 'OSV.dev', scanned: supported.length, findings: uniqueFindings(findings), skipped };
}

export function advisoryConfig() {
  return { source: 'OSV.dev', url: osvUrl, configured: true };
}

function normalizeFinding(item, detail) {
  const affected = detail?.affected || [];
  const fixedVersions = unique(affected.flatMap((entry) => (entry.ranges || []).flatMap((range) => (range.events || []).map((event) => event.fixed).filter(Boolean))));
  const severity = detail?.database_specific?.severity || detail?.severity?.[0]?.score || '';
  return {
    id: item.id,
    aliases: unique([...(detail?.aliases || []), ...(detail?.related || [])]),
    package: item.dependency.name,
    version: item.dependency.version,
    ecosystem: item.dependency.ecosystem,
    summary: detail?.summary || detail?.details?.split('\n')[0] || 'Vulnerability record available from OSV.',
    details: detail?.details || '',
    severity,
    published: detail?.published || '',
    modified: detail?.modified || item.modified || '',
    fixedVersions,
    references: (detail?.references || []).slice(0, 8).map((reference) => ({ type: reference.type || 'WEB', url: reference.url })).filter((reference) => reference.url),
    source: detail ? `${osvUrl}/v1/vulns/${encodeURIComponent(item.id)}` : osvUrl
  };
}

function uniqueDependencies(dependencies) {
  const seen = new Set();
  return dependencies.map((dependency) => ({ name: String(dependency.name || '').trim(), version: String(dependency.version || '').trim(), ecosystem: String(dependency.ecosystem || 'npm').toLowerCase().trim() })).filter((dependency) => {
    const key = `${dependency.ecosystem}:${dependency.name}:${dependency.version}`;
    if (!dependency.name || !dependency.version || seen.has(key)) return false;
    seen.add(key); return true;
  });
}

function uniqueFindings(findings) { return [...new Map(findings.map((finding) => [`${finding.ecosystem}:${finding.package}:${finding.version}:${finding.id}`, finding])).values()]; }
function unique(values) { return [...new Set(values.filter(Boolean))]; }
function chunks(items, size) { const result = []; for (let index = 0; index < items.length; index += size) result.push(items.slice(index, index + size)); return result; }
async function mapWithConcurrency(items, limit, worker) { const output = []; let cursor = 0; async function consume() { while (cursor < items.length) { const index = cursor++; output[index] = await worker(items[index]); } } await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => consume())); return output; }
