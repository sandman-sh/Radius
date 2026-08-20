import { query, rows, hydraRequired } from './hydra.js';
import { stableId, packageKey, versionKey } from './ids.js';
import { addIncident, snapshot, upsert as upsertLocal } from './local-store.js';

function nodeId(kind, key) {
  return stableId(`${kind}:${key}`);
}

function graphNode(kind, key, properties = {}) {
  return {
    id: nodeId(kind, key), label: kind, kind, key,
    name: properties.name || '', version: properties.version || '', file_name: properties.file_name || properties.fileName || '', service: properties.service || '', ecosystem: properties.ecosystem || 'npm', captured_at: properties.captured_at || properties.capturedAt || '', environment: properties.environment || '', owner: properties.owner || '', deployment_sha: properties.deployment_sha || properties.deploymentSha || '', deployed_at: properties.deployed_at || properties.deployedAt || '', resolved_at: properties.resolved_at || properties.resolvedAt || '', source_url: properties.source_url || properties.sourceUrl || '', host: properties.host || ''
  };
}

function graphEdge(from, type, to, properties = {}) {
  return {
    id: stableId(`${type}:${from.id}:${to.id}:${JSON.stringify(properties)}`), from: from.id, to: to.id, type, kind: type,
    requested: properties.requested || '', active_from: properties.active_from || '', active_to: properties.active_to || '', source: properties.source || '', observed_at: properties.observed_at || '', evidence: properties.evidence || ''
  };
}

export async function upsertGraph(records) {
  if (!hydraRequired()) await upsertLocal(records);
  try {
    const vertices = uniqueById(records.vertices || []); const edges = uniqueById(records.edges || []);
    if (vertices.length) await query(`UNWIND $rows AS row MERGE (n {id: row.id}) SET n:Entity, n.kind = row.kind, n.key = row.key, n.name = row.name, n.version = row.version, n.file_name = row.file_name, n.service = row.service, n.ecosystem = row.ecosystem, n.captured_at = row.captured_at, n.environment = row.environment, n.owner = row.owner, n.deployment_sha = row.deployment_sha, n.deployed_at = row.deployed_at, n.resolved_at = row.resolved_at, n.source_url = row.source_url, n.host = row.host`, { rows: vertices });
    for (const [type, typedEdges] of groupedEdges(edges)) await query(`UNWIND $rows AS row MATCH (s:Entity {id: row.from}), (d:Entity {id: row.to}) MERGE (s)-[r:${type} {id: row.id}]->(d) SET r.kind = row.kind, r.requested = row.requested, r.active_from = row.active_from, r.active_to = row.active_to, r.source = row.source, r.observed_at = row.observed_at, r.evidence = row.evidence`, { rows: typedEdges });
    if (hydraRequired()) await upsertLocal(records);
    return 'hydradb';
  } catch (error) {
    if (hydraRequired()) throw new Error(`HydraDB is required but unavailable: ${error.message}`);
    return 'local';
  }
}

export function recordsForLockfile(parsed, serviceName, fileName, capturedAt, metadata = {}) {
  const lock = graphNode('Lockfile', `lock:${serviceName}:${fileName}`, { name: fileName, file_name: fileName, service: serviceName, captured_at: capturedAt, ecosystem: parsed.ecosystem, ...metadata });
  const service = graphNode('Service', `service:${serviceName}`, { name: serviceName, service: serviceName, ecosystem: parsed.ecosystem, ...metadata });
  const deployment = graphNode('Deployment', `deployment:${serviceName}:${metadata.deploymentSha || capturedAt}`, { name: metadata.deploymentSha || `${serviceName} deployment`, service: serviceName, ecosystem: parsed.ecosystem, ...metadata });
  const vertices = [lock, service, deployment];
  const edges = [graphEdge(service, 'USES_LOCKFILE', lock, { source: fileName, evidence: 'service inventory' }), graphEdge(service, 'HAS_DEPLOYMENT', deployment, { source: fileName, evidence: 'deployment metadata' }), graphEdge(deployment, 'DEPLOYED_LOCKFILE', lock, { source: fileName, active_from: metadata.deployedAt || capturedAt, active_to: metadata.resolvedAt || capturedAt, evidence: 'deployment metadata' })];
  const versionNodes = new Map();
  for (const entry of parsed.entries) {
    const ecosystem = entry.ecosystem || parsed.ecosystem;
    const pkg = graphNode('Package', packageKey(entry.name, ecosystem), { name: entry.name, ecosystem });
    const ver = graphNode('PackageVersion', versionKey(entry.name, entry.version, ecosystem), { name: entry.name, version: entry.version, ecosystem });
    vertices.push(pkg, ver); versionNodes.set(entry.path, ver);
    edges.push(graphEdge(pkg, 'HAS_VERSION', ver, { source: fileName }));
    edges.push(graphEdge(lock, 'RESOLVES', ver, { source: fileName, active_from: metadata.deployedAt || capturedAt, active_to: metadata.resolvedAt || capturedAt, observed_at: capturedAt, evidence: `${serviceName} resolved ${entry.name}@${entry.version}` }));
  }
  for (const edge of parsed.edges) { const from = versionNodes.get(edge.from.path); const to = versionNodes.get(edge.to.path); if (from && to) edges.push(graphEdge(from, 'DEPENDS_ON', to, { requested: String(edge.requested || ''), source: fileName, evidence: `${edge.from.name} requires ${edge.to.name}` })); }
  return { vertices: uniqueById(vertices), edges: uniqueById(edges) };
}

export async function createIncident({ packageName, version, startsAt, endsAt, ecosystem = 'npm', metadata = {} }) {
  const incident = graphNode('Incident', `incident:${ecosystem}:${packageName}:${version}:${startsAt}`, { name: `${packageName}@${version}`, version, ecosystem });
  const target = graphNode('PackageVersion', versionKey(packageName, version, ecosystem), { name: packageName, version, ecosystem });
  await upsertGraph({ vertices: [incident, target], edges: [graphEdge(incident, 'COMPROMISED_VERSION', target, { active_from: startsAt, active_to: endsAt, evidence: 'incident declaration' })] });
  const saved = { ...incident, targetId: target.id, packageName, version, ecosystem, startsAt, endsAt, metadata }; await addIncident(saved); return saved;
}

export async function impactForIncident({ packageName, version, ecosystem = 'npm', startsAt, endsAt }) {
  const local = await localImpact({ packageName, version, ecosystem, startsAt, endsAt });
  try {
    const body = await query(`CALL algo.SSpaths({sourceNode: $root_id, relTypes: ['DEPENDS_ON', 'RESOLVES', 'USES_LOCKFILE', 'HAS_DEPLOYMENT', 'DEPLOYED_LOCKFILE'], relDirection: 'both', maxLen: 12, pathCount: 120}) YIELD path RETURN path`, { root_id: nodeId('PackageVersion', versionKey(packageName, version, ecosystem)) });
    const paths = rows(body).map((item) => item.path).filter(Boolean).map(pathToUi); if (paths.length) local.paths = paths; local.graphMode = 'hydradb';
  } catch (error) {
    if (hydraRequired()) throw new Error(`HydraDB is required but unavailable: ${error.message}`);
    local.graphMode = 'local-persistent';
  }
  return local;
}

async function localImpact({ packageName, version, ecosystem = 'npm', startsAt, endsAt }) {
  const graph = await snapshot(); const rootId = nodeId('PackageVersion', versionKey(packageName, version, ecosystem)); const nodeById = new Map(graph.nodes.map((node) => [String(node.id), node]));
  const incoming = new Map(); for (const edge of graph.edges.filter((item) => item.type === 'DEPENDS_ON')) { if (!incoming.has(String(edge.to))) incoming.set(String(edge.to), []); incoming.get(String(edge.to)).push(edge); }
  const dependentEdges = []; const seen = new Set([String(rootId)]); const queue = [{ id: String(rootId), depth: 0 }];
  while (queue.length) { const current = queue.shift(); if (current.depth >= 12) continue; for (const edge of incoming.get(current.id) || []) { if (seen.has(String(edge.from))) continue; seen.add(String(edge.from)); dependentEdges.push(edge); queue.push({ id: String(edge.from), depth: current.depth + 1 }); } }
  const dependentIds = new Set(dependentEdges.map((edge) => String(edge.from)));
  const resolves = graph.edges.filter((edge) => edge.type === 'RESOLVES' && (String(edge.to) === String(rootId) || dependentIds.has(String(edge.to))) && overlaps(edge.active_from, edge.active_to, startsAt, endsAt));
  const locks = uniqueById(resolves.map((edge) => nodeById.get(String(edge.from))).filter(Boolean)); const lockIds = new Set(locks.map((node) => String(node.id))); const uses = graph.edges.filter((edge) => edge.type === 'USES_LOCKFILE' && lockIds.has(String(edge.to))); const services = uniqueById(uses.map((edge) => nodeById.get(String(edge.from))).filter(Boolean));
  const profiles = new Map(graph.profiles.map((profile) => [`${profile.ecosystem || 'npm'}:${profile.name}`, profile])); const rootProfile = profiles.get(`${ecosystem}:${packageName}`) || null; const affectedPackageNames = [...new Set([...dependentIds].map((id) => nodeById.get(id)?.name).filter(Boolean))]; const affectedProfiles = affectedPackageNames.map((name) => profiles.get(`${ecosystem}:${name}`)).filter(Boolean);
  const sharedMaintainers = sharedValues(rootProfile?.maintainers, affectedProfiles.flatMap((profile) => profile.maintainers || [])); const sharedHosts = sharedValues(rootProfile?.hosts, affectedProfiles.flatMap((profile) => profile.hosts || []));
  const serviceEvidence = services.map((service) => { const matchingLock = locks.find((lock) => uses.some((edge) => String(edge.from) === String(service.id) && String(edge.to) === String(lock.id))); const matchingResolution = resolves.find((edge) => String(edge.from) === String(matchingLock?.id)); const resolvedVersion = nodeById.get(String(matchingResolution?.to)); const direct = String(matchingResolution?.to) === String(rootId); return { id: service.id, name: service.service || service.name, owner: service.owner || 'Unassigned', environment: service.environment || 'production', deploymentSha: service.deployment_sha || 'not recorded', observedAt: matchingResolution?.observed_at || service.captured_at || '', exposedFrom: matchingResolution?.active_from || '', exposedTo: matchingResolution?.active_to || '', version: resolvedVersion?.version || version, direct, evidence: direct ? 'lockfile resolves compromised version' : 'transitive dependency path reaches compromised version' }; });
  const paths = services.flatMap((service) => locks.filter((lock) => uses.some((edge) => String(edge.from) === String(service.id) && String(edge.to) === String(lock.id))).map((lock) => buildEvidencePath(service, lock, rootId, dependentEdges, nodeById, graph.edges)));
  return { graphMode: 'local-persistent', incident: { packageName, version, ecosystem, startsAt, endsAt }, summary: { services: services.length, lockfiles: locks.length, dependentVersions: dependentIds.size, paths: paths.length, directServices: serviceEvidence.filter((service) => service.direct).length, transitiveServices: serviceEvidence.filter((service) => !service.direct).length }, services: serviceEvidence, lockfiles: locks.map((item) => ({ id: item.id, name: item.file_name || item.name, capturedAt: item.captured_at, environment: item.environment || 'production' })), dependentVersions: [...dependentIds].map((id) => nodeById.get(id)).filter(Boolean).map((item) => ({ id: item.id, name: item.name, version: item.version, ecosystem: item.ecosystem || ecosystem, requested: dependentEdges.find((edge) => String(edge.from) === String(item.id))?.requested || '' })), timeline: buildTimeline({ startsAt, endsAt, services: serviceEvidence }), provenance: rootProfile ? { name: rootProfile.name, description: rootProfile.description, latest: rootProfile.latest, repository: rootProfile.repository, homepage: rootProfile.homepage, maintainers: rootProfile.maintainers, publisher: rootProfile.publisher, hosts: rootProfile.hosts, publishedAt: rootProfile.publishedAt, source: rootProfile.source } : null, sharedSignals: { maintainers: sharedMaintainers, infrastructure: sharedHosts }, typosquats: rootProfile?.typosquats || [], paths };
}

function buildEvidencePath(service, lock, rootId, dependentEdges, nodeById, allEdges) {
  const pathNodes = [service, lock]; const pathRelationships = allEdges.filter((edge) => edge.from === service.id && edge.to === lock.id && edge.type === 'USES_LOCKFILE'); const resolutionEdge = allEdges.find((edge) => edge.from === lock.id && edge.type === 'RESOLVES' && (edge.to === rootId || dependentEdges.some((item) => item.from === edge.to)));
  if (resolutionEdge) { pathRelationships.push(resolutionEdge); const first = nodeById.get(String(resolutionEdge.to)); if (first) pathNodes.push(first); let current = resolutionEdge.to; const visited = new Set(); while (current !== rootId) { const edge = dependentEdges.find((candidate) => candidate.from === current && !visited.has(candidate.id)); if (!edge) break; visited.add(edge.id); const dependency = nodeById.get(String(edge.to)); if (dependency) pathNodes.push(dependency); pathRelationships.push(edge); current = edge.to; } }
  const root = nodeById.get(String(rootId)); if (root && !pathNodes.some((node) => String(node.id) === String(rootId))) pathNodes.push(root);
  return { vertices: uniqueById(pathNodes).map((node) => ({ id: node.id, label: node.label || node.kind || 'Entity', properties: node })), relationships: uniqueById(pathRelationships).map((edge) => ({ id: edge.id, type: edge.type, properties: edge })) };
}

function buildTimeline({ startsAt, endsAt, services }) { return [{ label: 'Incident declared', at: startsAt, tone: 'incident' }, ...services.filter((service) => service.exposedFrom).slice(0, 8).map((service) => ({ label: `${service.name} observed`, at: service.exposedFrom, tone: 'service' })), { label: 'Window closes', at: endsAt, tone: 'close' }].sort((a, b) => String(a.at).localeCompare(String(b.at))); }
function overlaps(activeFrom, activeTo, startsAt, endsAt) { const from = Date.parse(activeFrom || startsAt || '') || 0; const to = Date.parse(activeTo || activeFrom || endsAt || '') || from; const incidentFrom = Date.parse(startsAt || '') || from; const incidentTo = Date.parse(endsAt || '') || to; return from <= incidentTo && to >= incidentFrom; }
function sharedValues(rootValues = [], affectedValues = []) { const affected = new Set(affectedValues); return [...new Set(rootValues)].filter((value) => affected.has(value)); }
function pathToUi(path) { return { vertices: (path.nodes || []).map((vertex) => ({ id: vertex.id, label: vertex.labels?.[0] || 'Entity', properties: normalizeProperties(vertex.properties) })), relationships: (path.relationships || []).map((relationship) => ({ id: relationship.id, type: relationship.edge_type, properties: normalizeProperties(relationship.properties) })) }; }
function normalizeProperties(properties = {}) { return Object.fromEntries(Object.entries(properties).map(([key, value]) => [key, normalizeProperty(value)])); }
function normalizeProperty(value) { if (!value || typeof value !== 'object') return value; const entries = Object.entries(value); return entries.length === 1 ? entries[0][1] : value; }

export async function graphStats() {
  const local = await snapshot();
  try {
    const body = await query(`MATCH (n:Entity) RETURN count(*) AS nodes`);
    const edgeQueries = ['DEPENDS_ON', 'RESOLVES', 'USES_LOCKFILE', 'HAS_DEPLOYMENT', 'DEPLOYED_LOCKFILE', 'COMPROMISED_VERSION', 'HAS_VERSION'].map((type) => query(`MATCH ()-[r:${type}]->() RETURN count(*) AS edges`));
    const edgeRows = await Promise.all(edgeQueries); const stats = { nodes: Number(rows(body)[0]?.nodes || 0), edges: edgeRows.reduce((sum, result) => sum + Number(rows(result)[0]?.edges || 0), 0) };
    return { ...stats, profiles: local.profiles.length, incidents: local.incidents.length, mode: 'hydradb' };
  } catch (error) {
    if (hydraRequired()) throw new Error(`HydraDB is required but unavailable: ${error.message}`);
    return { nodes: local.nodes.length, edges: local.edges.length, profiles: local.profiles.length, incidents: local.incidents.length, mode: 'local-persistent' };
  }
}

function groupedEdges(edges) { const groups = new Map(); for (const edge of edges) { if (!/^[A-Z_]+$/.test(edge.type)) throw new Error(`Invalid relationship type ${edge.type}`); if (!groups.has(edge.type)) groups.set(edge.type, []); groups.get(edge.type).push(edge); } return groups; }
function uniqueById(items) { return [...new Map(items.map((item) => [item.id, item])).values()]; }
