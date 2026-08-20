const versionPattern = /\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?/;

export function parsePackageLock(text, fileName = 'package-lock.json') {
  return parseDependencyFile(text, fileName, 'npm');
}

export function parseDependencyFile(text, fileName = 'dependencies.json', requestedEcosystem = 'auto') {
  const cleanName = String(fileName || 'dependencies.json').toLowerCase();
  const json = tryJson(text);
  if (json?.packages && (cleanName.endsWith('package-lock.json') || json.lockfileVersion)) return parseNpmLock(json, fileName);
  if (json?.bomFormat === 'CycloneDX' || json?.bomFormat === 'cyclonedx') return parseCycloneDx(json, fileName);
  if (json?.spdxVersion) return parseSpdx(json, fileName);
  if (json?.default && (json._meta || json.develop)) return parsePipfile(json, fileName);
  if (cleanName.endsWith('pipfile.lock')) return parsePipfile(json || {}, fileName);
  if (cleanName.endsWith('requirements.txt') || cleanName.endsWith('requirements.in') || cleanName.endsWith('.txt')) return parseRequirements(text, fileName, requestedEcosystem === 'auto' ? 'pypi' : requestedEcosystem);
  if (cleanName.endsWith('cargo.lock')) return parseCargoLock(text, fileName);
  if (cleanName.endsWith('go.mod')) return parseGoMod(text, fileName);
  if (cleanName.endsWith('pom.xml')) return parsePom(text, fileName);
  if (cleanName.endsWith('poetry.lock') || cleanName.endsWith('uv.lock')) return parsePythonTomlLock(text, fileName);
  if (json) throw new Error(`Unsupported dependency JSON format in ${fileName}. Use package-lock, Pipfile.lock, CycloneDX, or SPDX.`);
  throw new Error(`Unsupported dependency file ${fileName}. Use package-lock.json, requirements.txt, Pipfile.lock, poetry.lock, uv.lock, Cargo.lock, go.mod, pom.xml, CycloneDX, or SPDX.`);
}

function parseNpmLock(document, fileName) {
  const packages = document.packages;
  if (packages && typeof packages === 'object') {
    const entries = Object.entries(packages).filter(([path, entry]) => path !== '' && entry?.name && entry?.version).map(([path, entry]) => ({ path, name: entry.name, version: normalizeVersion(entry.version), dependencies: entry.dependencies || {} }));
    const byPath = new Map(entries.map((entry) => [entry.path, entry]));
    const root = packages[''] || {};
    const rootDeps = { ...(root.dependencies || {}), ...(root.devDependencies || {}) };
    const edges = [];
    for (const entry of entries) for (const dependencyName of Object.keys(entry.dependencies)) {
      const nested = `${entry.path}/node_modules/${dependencyName}`; const top = `node_modules/${dependencyName}`; const resolvedPath = byPath.has(nested) ? nested : top; const target = byPath.get(resolvedPath);
      if (target) edges.push({ from: entry, to: target, requested: entry.dependencies[dependencyName] });
    }
    const roots = Object.entries(rootDeps).map(([name, requested]) => { const target = byPath.get(`node_modules/${name}`); return target ? { name, requested, target } : null; }).filter(Boolean);
    return { ecosystem: 'npm', fileName, format: 'package-lock', lockfileVersion: document.lockfileVersion || 1, entries, edges, roots };
  }
  return parseLegacyNpmLock(document, fileName);
}

function parseLegacyNpmLock(document, fileName) {
  const entries = []; const edges = [];
  function walk(dependencies, parent = null, path = '') {
    for (const [name, value] of Object.entries(dependencies || {})) {
      if (!value?.version) continue;
      const entry = { path: `${path}${name}`, name, version: normalizeVersion(value.version), dependencies: value.dependencies || {} }; entries.push(entry);
      if (parent) edges.push({ from: parent, to: entry, requested: value.version }); walk(value.dependencies, entry, `${entry.path}/node_modules/`);
    }
  }
  walk(document.dependencies); return { ecosystem: 'npm', fileName, format: 'package-lock-v1', lockfileVersion: 1, entries, edges, roots: entries.filter((entry) => !edges.some((edge) => edge.to === entry)).map((target) => ({ name: target.name, requested: target.version, target })) };
}

function parsePipfile(document, fileName) {
  const entries = [];
  for (const section of ['default', 'develop']) for (const [name, value] of Object.entries(document?.[section] || {})) {
    const version = normalizeVersion(typeof value === 'string' ? value : value?.version);
    if (version) entries.push({ path: `${section}/${name}`, name: normalizePythonName(name), version, dependencies: {} });
  }
  return { ecosystem: 'pypi', fileName, format: 'Pipfile.lock', lockfileVersion: 1, entries, edges: [], roots: entries.map((target) => ({ name: target.name, requested: target.version, target })) };
}

function parseRequirements(text, fileName, ecosystem) {
  const entries = [];
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim(); if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const match = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:===|==|@\s*[^ ]+\s*)\s*([^;\s#]+)(?:;.*)?$/);
    if (!match) throw new Error(`Unpinned dependency in ${fileName}: ${line}. Production ingestion requires exact versions.`);
    entries.push({ path: match[1], name: ecosystem === 'pypi' ? normalizePythonName(match[1]) : match[1], version: normalizeVersion(match[2]), dependencies: {} });
  }
  return { ecosystem, fileName, format: 'requirements', lockfileVersion: 1, entries, edges: [], roots: entries.map((target) => ({ name: target.name, requested: target.version, target })) };
}

function parseCycloneDx(document, fileName) {
  const components = document.components || []; const entries = components.map((component, index) => { const purl = component.purl || ''; const parsed = parsePurl(purl); return { path: component['bom-ref'] || purl || `${component.name}:${index}`, name: component.name || parsed.name, version: normalizeVersion(component.version || parsed.version), ecosystem: parsed.ecosystem, dependencies: {} }; });
  const byRef = new Map(entries.map((entry) => [entry.path, entry])); const edges = [];
  for (const relation of document.dependencies || []) { const from = byRef.get(relation.ref); for (const ref of relation.dependsOn || []) { const to = byRef.get(ref); if (from && to) edges.push({ from, to, requested: to.version }); } }
  const ecosystem = ecosystemLabel(entries.map((entry) => entry.ecosystem)); return { ecosystem, fileName, format: 'CycloneDX', lockfileVersion: 1, entries, edges, roots: entries.filter((entry) => !edges.some((edge) => edge.to === entry)).map((target) => ({ name: target.name, requested: target.version, target })) };
}

function parseSpdx(document, fileName) {
  const entries = (document.packages || []).map((pkg) => { const purlRef = (pkg.externalRefs || []).find((ref) => ref.referenceType === 'purl')?.referenceLocator || ''; const parsed = parsePurl(purlRef); return { path: pkg.SPDXID, name: pkg.name || parsed.name, version: normalizeVersion(pkg.versionInfo || parsed.version), ecosystem: parsed.ecosystem || 'unknown', dependencies: {} }; });
  const byId = new Map(entries.map((entry) => [entry.path, entry])); const edges = (document.relationships || []).filter((relation) => relation.relationshipType === 'DEPENDS_ON').map((relation) => ({ from: byId.get(relation.spdxElementId), to: byId.get(relation.relatedSpdxElement), requested: byId.get(relation.relatedSpdxElement)?.version })).filter((edge) => edge.from && edge.to); const ecosystem = ecosystemLabel(entries.map((entry) => entry.ecosystem)); return { ecosystem, fileName, format: 'SPDX', lockfileVersion: 1, entries, edges, roots: entries.filter((entry) => !edges.some((edge) => edge.to === entry)).map((target) => ({ name: target.name, requested: target.version, target })) };
}

function parseCargoLock(text, fileName) {
  const blocks = String(text).split(/\[\[package\]\]/).slice(1); const entries = blocks.map((block, index) => { const name = field(block, 'name') || `cargo-package-${index}`; const version = normalizeVersion(field(block, 'version')); const dependencies = {}; const dependencySection = block.match(/dependencies\s*=\s*\[([\s\S]*?)\]/)?.[1] || ''; for (const dependency of dependencySection.matchAll(/"([^" ]+)/g)) dependencies[dependency[1]] = '*'; return { path: `${name}@${version}`, name, version, dependencies }; }); return withTextEdges(entries, 'cargo', fileName);
}

function parsePythonTomlLock(text, fileName) {
  const blocks = String(text).split(/\[\[package\]\]/).slice(1); const entries = blocks.map((block, index) => { const name = field(block, 'name') || `python-package-${index}`; const version = normalizeVersion(field(block, 'version')); const dependencies = {}; const dependencySection = block.match(/dependencies\s*=\s*\[([\s\S]*?)\]/)?.[1] || ''; for (const dependency of dependencySection.matchAll(/name\s*=\s*"([^"]+)"/g)) dependencies[normalizePythonName(dependency[1])] = '*'; return { path: `${name}@${version}`, name: normalizePythonName(name), version, dependencies }; }); return withTextEdges(entries, 'pypi', fileName);
}

function parseGoMod(text, fileName) { const entries = []; const lines = String(text).split(/\r?\n/); let inBlock = false; for (const raw of lines) { const line = raw.trim(); if (line.startsWith('require (')) { inBlock = true; continue; } if (inBlock && line === ')') { inBlock = false; continue; } const match = (inBlock ? line : line.replace(/^require\s+/, '')).match(/^([^\s]+)\s+(v?\d[^\s]+)$/); if (match) entries.push({ path: match[1], name: match[1], version: normalizeVersion(match[2]), dependencies: {} }); } return { ecosystem: 'go', fileName, format: 'go.mod', lockfileVersion: 1, entries, edges: [], roots: entries.map((target) => ({ name: target.name, requested: target.version, target })) }; }

function parsePom(text, fileName) { const entries = []; const blocks = String(text).match(/<dependency>[\s\S]*?<\/dependency>/g) || []; for (const block of blocks) { const group = xmlField(block, 'groupId'); const artifact = xmlField(block, 'artifactId'); const version = xmlField(block, 'version'); if (artifact && version) entries.push({ path: `${group || 'maven'}:${artifact}`, name: `${group || 'maven'}:${artifact}`, version: normalizeVersion(version), dependencies: {} }); } return { ecosystem: 'maven', fileName, format: 'pom.xml', lockfileVersion: 1, entries, edges: [], roots: entries.map((target) => ({ name: target.name, requested: target.version, target })) }; }

function withTextEdges(entries, ecosystem, fileName) { const byName = new Map(entries.map((entry) => [entry.name, entry])); const edges = []; for (const entry of entries) for (const [name, requested] of Object.entries(entry.dependencies || {})) { const target = byName.get(name); if (target) edges.push({ from: entry, to: target, requested }); } return { ecosystem, fileName, format: fileName.toLowerCase().endsWith('cargo.lock') ? 'Cargo.lock' : 'python-lock', lockfileVersion: 1, entries, edges, roots: entries.filter((entry) => !edges.some((edge) => edge.to === entry)).map((target) => ({ name: target.name, requested: target.version, target })) }; }

function parsePurl(purl) { const match = String(purl).match(/^pkg:([^/]+)\/(.+?)@([^@?]+)(?:\?.*)?$/); if (!match) return {}; const ecosystem = ({ npm: 'npm', pypi: 'pypi', maven: 'maven', cargo: 'cargo', golang: 'go' })[match[1].toLowerCase()] || match[1].toLowerCase(); const rawName = decodeURIComponent(match[2]); return { ecosystem, name: ecosystem === 'pypi' ? normalizePythonName(rawName) : rawName, version: decodeURIComponent(match[3]) }; }
function field(block, name) { return block.match(new RegExp(`^${name}\\s*=\\s*["']([^"']+)["']`, 'm'))?.[1] || ''; }
function xmlField(block, name) { return block.match(new RegExp(`<${name}>([^<]+)</${name}>`))?.[1]?.trim() || ''; }
function normalizeVersion(value) { if (!value) return null; const clean = String(value).trim().replace(/^v/, '').replace(/^[=~<>!]+\s*/, '').replace(/^\^/, ''); return clean.match(versionPattern)?.[0] || clean; }
function normalizePythonName(name) { return String(name).trim().toLowerCase().replace(/[-_.]+/g, '-'); }
function tryJson(text) { try { return JSON.parse(text); } catch { return null; } }
function ecosystemLabel(values) { const unique = [...new Set(values.filter(Boolean))]; return unique.length === 1 ? unique[0] : unique.length > 1 ? 'mixed' : 'unknown'; }
