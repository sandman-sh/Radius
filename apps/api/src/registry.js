import { upsertProfile } from './local-store.js';

const npmBase = 'https://registry.npmjs.org';
const npmSearch = 'https://registry.npmjs.org/-/v1/search';
const pypiBase = 'https://pypi.org/pypi';

export async function fetchPackageProfile(name, version = '', ecosystem = 'npm') {
  if (ecosystem === 'pypi') return fetchPyPiProfile(name, version);
  return fetchNpmProfile(name, version);
}

export async function fetchNpmPackage(name, version = '') {
  const result = await fetchNpmProfile(name, version);
  return { data: result.data, selected: result.selected, profile: result.profile };
}

async function fetchNpmProfile(name, version = '') {
  const scopedName = name.startsWith('@') ? `@${name.slice(1).split('/').map(encodeURIComponent).join('/')}` : encodeURIComponent(name);
  try {
    const response = await fetch(`${npmBase}/${scopedName}`, { signal: AbortSignal.timeout(12000) });
    if (response.ok) {
      const data = await response.json();
      const selected = version ? data.versions?.[version] : data.versions?.[data['dist-tags']?.latest];
      const repository = normalizeRepository(data.repository);
      const hosts = unique([selected?.dist?.tarball ? safeHostname(selected.dist.tarball) : '', repository ? safeHostname(repository) : ''].filter(Boolean));
      const maintainers = (data.maintainers || []).map((person) => person.name).filter(Boolean);
      const profile = { ecosystem: 'npm', name: data.name || name, version: version || selected?.version || data['dist-tags']?.latest || '', description: data.description || '', latest: data['dist-tags']?.latest || '', repository, homepage: data.homepage || '', maintainers, publisher: selected?.maintainers?.[0]?.name || maintainers[0] || '', hosts, publishedAt: data.time?.[version || selected?.version] || '', source: `${npmBase}/${scopedName}` };
      return { data, selected: selected || { version }, profile };
    }
  } catch (_error) {
    // Fall back to snapshot-derived profile on network/registry failure
  }
  const fallback = { ecosystem: 'npm', name, version, description: 'Package indexed from evidence snapshot', latest: version, repository: '', homepage: '', maintainers: [], publisher: '', hosts: [], publishedAt: '', source: 'evidence' };
  return { data: { name, description: '', versions: { [version]: { version } } }, selected: { version }, profile: fallback };
}

async function fetchPyPiProfile(name, version = '') {
  const response = await fetch(`${pypiBase}/${encodeURIComponent(name)}/json`, { signal: AbortSignal.timeout(12000) });
  if (!response.ok) throw new Error(`PyPI returned ${response.status} for ${name}`);
  const data = await response.json(); const info = data.info || {}; const selectedVersion = version || info.version || '';
  if (version && !data.releases?.[version]) throw new Error(`${name}==${version} was not found on PyPI.`);
  const projectUrls = Object.values(info.project_urls || {}); const repository = projectUrls.find((url) => /github|gitlab|bitbucket|sourceforge/i.test(url)) || info.home_page || '';
  const hosts = unique([safeHostname(data.urls?.find((item) => item.packagetype === 'sdist')?.url || ''), safeHostname(repository)].filter(Boolean));
  const maintainers = unique([info.author, info.maintainer].filter(Boolean));
  const release = data.releases?.[selectedVersion]?.[0];
  const profile = { ecosystem: 'pypi', name: info.name || name, version: selectedVersion, description: info.summary || '', latest: info.version || '', repository, homepage: info.home_page || '', maintainers, publisher: info.author || info.maintainer || '', hosts, publishedAt: release?.upload_time_iso_8601 || '', source: `${pypiBase}/${encodeURIComponent(name)}/json` };
  return { data, selected: info, profile };
}

export async function findTyposquats(name, ecosystem = 'npm') {
  if (ecosystem === 'pypi') return findPyPiTyposquats(name);
  try {
    const response = await fetch(`${npmSearch}?text=${encodeURIComponent(name)}&size=40`, { signal: AbortSignal.timeout(10000) }); if (!response.ok) return [];
    const body = await response.json(); return (body.objects || []).map((item) => item.package).filter((pkg) => pkg?.name && pkg.name !== name).map((pkg) => ({ ecosystem: 'npm', name: pkg.name, version: pkg.version || '', description: pkg.description || '', similarity: Math.round(similarity(name, pkg.name) * 100), source: `${npmBase}/${encodeURIComponent(pkg.name)}` })).filter((item) => item.similarity >= 62).sort((a, b) => b.similarity - a.similarity).slice(0, 8);
  } catch { return []; }
}

async function findPyPiTyposquats(name) {
  const candidates = new Set([name.replace(/[-_.]/g, '-'), name.replace(/[-_.]/g, '_'), name.replace(/-/g, ''), `${name}-dev`, `${name}-api`, `${name}2`]); const results = [];
  for (const candidate of candidates) {
    if (!candidate || candidate.toLowerCase() === name.toLowerCase()) continue;
    try { const response = await fetch(`${pypiBase}/${encodeURIComponent(candidate)}/json`, { signal: AbortSignal.timeout(4500) }); if (!response.ok) continue; const data = await response.json(); const info = data.info || {}; const score = Math.round(similarity(name, candidate) * 100); if (score >= 62) results.push({ ecosystem: 'pypi', name: info.name || candidate, version: info.version || '', description: info.summary || '', similarity: score, source: `${pypiBase}/${encodeURIComponent(candidate)}/json` }); } catch {}
  }
  return results.sort((a, b) => b.similarity - a.similarity).slice(0, 8);
}

export async function enrichProfile(name, version = '', withTyposquats = false, ecosystem = 'npm') {
  const { profile } = await fetchPackageProfile(name, version, ecosystem); if (withTyposquats) profile.typosquats = await findTyposquats(name, ecosystem); await upsertProfile(profile); return profile;
}

export function normalizeRepository(repository) { if (!repository) return ''; const value = typeof repository === 'string' ? repository : repository.url || ''; return value.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^git:/, 'https:').replace(/^ssh:\/\/git@github\.com\//, 'https://github.com/'); }
function safeHostname(url) { try { return new URL(url).hostname; } catch { return ''; } }
function similarity(a, b) { const left = a.toLowerCase(); const right = b.toLowerCase(); return 1 - levenshtein(left, right) / Math.max(left.length, right.length, 1); }
function levenshtein(a, b) { const row = Array.from({ length: b.length + 1 }, (_, index) => index); for (let i = 1; i <= a.length; i += 1) { let previous = row[0]; row[0] = i; for (let j = 1; j <= b.length; j += 1) { const current = row[j]; row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1)); previous = current; } } return row[b.length]; }
function unique(values) { return [...new Set(values)]; }
