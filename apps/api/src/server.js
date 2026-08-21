import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { hydraHealth, hydraConfig, hydraRequired } from './hydra.js';
import { parseDependencyFile } from './lockfile.js';
import { recordsForLockfile, upsertGraph, createIncident, impactForIncident, graphStats } from './graph.js';
import { enrichProfile, fetchNpmPackage, fetchPackageProfile, findTyposquats } from './registry.js';
import { scanDependencies, advisoryConfig } from './advisories.js';
import { notificationConfig, notifySlack } from './notifications.js';
import { githubConfig, fetchDependencyFile, changedDependencyPaths, dispatchRemediation } from './github.js';
import { buildRemediationPlan } from './remediation.js';
import { localDataPath, snapshot } from './local-store.js';
import { rateLimit, requireApiToken, securityConfig, validateIdentifier, verifyGithubWebhook, verifyWebhook } from './security.js';

const app = express();
const maxFileSize = Number(process.env.RADIUS_MAX_FILE_SIZE || 12 * 1024 * 1024);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxFileSize } });
const allowedOrigins = String(process.env.RADIUS_CORS_ORIGINS || '').split(',').map((origin) => origin.trim()).filter(Boolean);

app.disable('x-powered-by');
app.use((request, response, next) => { response.setHeader('X-Content-Type-Options', 'nosniff'); response.setHeader('X-Frame-Options', 'DENY'); response.setHeader('Referrer-Policy', 'no-referrer'); response.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'"); next(); });
app.use(cors({ origin: (origin, callback) => { if (!origin || !allowedOrigins.length || allowedOrigins.includes(origin)) return callback(null, true); return callback(new Error('Origin not allowed.')); } }));
app.use(express.json({ limit: process.env.RADIUS_JSON_LIMIT || '2mb', verify: (request, _response, buffer) => { request.rawBody = Buffer.from(buffer); } }));
app.use(rateLimit);

app.get('/api/health', async (_req, res) => {
  const integrations = { advisories: advisoryConfig(), github: githubConfig(), notifications: notificationConfig() };
  try { await hydraHealth(); res.json({ api: 'ok', hydradb: 'ok', storage: 'hydradb', security: securityConfig(), integrations, config: hydraConfig() }); }
  catch (error) { const payload = { api: 'ok', hydradb: 'offline', storage: 'local-persistent', security: securityConfig(), integrations, error: error.message, config: hydraConfig(), dataPath: localDataPath() }; res.status(hydraRequired() ? 503 : 200).json(payload); }
});

app.get('/api/ready', async (_req, res) => { try { await hydraHealth(); res.json({ ready: true, storage: 'hydradb' }); } catch (error) { res.status(hydraRequired() ? 503 : 200).json({ ready: !hydraRequired(), storage: 'local-persistent', error: error.message }); } });

app.get('/api/stats', async (_req, res) => { try { res.json(await graphStats()); } catch (error) { res.status(hydraRequired() ? 503 : 200).json({ error: error.message }); } });

app.get('/api/metrics', async (_req, res) => { try { const stats = await graphStats(); res.type('text/plain').send([`radius_graph_nodes ${stats.nodes}`, `radius_graph_edges ${stats.edges}`, `radius_graph_profiles ${stats.profiles}`, `radius_incidents_total ${stats.incidents}`, `radius_process_uptime_seconds ${Math.round(process.uptime())}`].join('\n') + '\n'); } catch (error) { res.status(503).type('text/plain').send(`radius_ready 0\nradius_metrics_error 1\n# ${error.message}\n`); } });

app.get('/api/overview', async (_req, res) => { try { const graph = await snapshot(); const stats = await graphStats(); const services = graph.nodes.filter((node) => node.kind === 'Service').map((service) => ({ id: service.id, name: service.service || service.name, owner: service.owner || 'Unassigned', environment: service.environment || 'production', deploymentSha: service.deployment_sha || '', ecosystem: service.ecosystem || 'npm' })); res.json({ stats, incidents: graph.incidents.slice(0, 12), services: uniqueById(services), profiles: graph.profiles.length }); } catch (error) { res.status(hydraRequired() ? 503 : 200).json({ error: error.message }); } });

app.get('/api/registry/:ecosystem/:name', async (req, res) => { try { const ecosystem = normalizeEcosystem(req.params.ecosystem); const name = validateIdentifier(decodeURIComponent(req.params.name), 'package name'); const { profile } = await fetchPackageProfile(name, '', ecosystem); res.json({ profile, typosquats: await findTyposquats(name, ecosystem) }); } catch (error) { res.status(502).json({ error: error.message }); } });
app.get('/api/registry/npm/:name', async (req, res) => { try { const name = validateIdentifier(req.params.name, 'package name'); const { data, profile } = await fetchNpmPackage(name); res.json({ name: data.name, description: data.description, latest: data['dist-tags']?.latest, versions: Object.keys(data.versions || {}).slice(-20), profile, typosquats: await findTyposquats(name, 'npm') }); } catch (error) { res.status(502).json({ error: error.message }); } });
app.get('/api/integrations/status', requireApiToken, (_req, res) => res.json({ advisories: advisoryConfig(), github: githubConfig(), notifications: notificationConfig() }));

app.post('/api/advisories/scan', requireApiToken, async (req, res) => {
  try { const dependencies = Array.isArray(req.body?.dependencies) ? req.body.dependencies : []; if (!dependencies.length) return res.status(400).json({ error: 'dependencies must be a non-empty array.' }); res.json(await scanDependencies(dependencies)); }
  catch (error) { res.status(502).json({ error: error.message }); }
});

app.post('/api/advisories/scan-lockfile', requireApiToken, upload.single('lockfile'), async (req, res) => {
  try { if (!req.file) return res.status(400).json({ error: 'A dependency file is required.' }); const parsed = parseDependencyFile(req.file.buffer.toString('utf8'), req.file.originalname, normalizeEcosystem(req.body.ecosystem || 'auto', true)); res.json({ fileName: req.file.originalname, format: parsed.format, ecosystem: parsed.ecosystem, ...(await scanDependencies(parsed.entries)) }); }
  catch (error) { res.status(502).json({ error: error.message }); }
});

app.post('/api/remediation/plan', requireApiToken, async (req, res) => {
  try {
    const packageName = validateIdentifier(req.body.packageName, 'packageName'); const version = validateIdentifier(req.body.version, 'version', 80); const ecosystem = normalizeEcosystem(req.body.ecosystem); let targetVersion = String(req.body.targetVersion || req.body.fixedVersion || '').trim();
    let registry = null; if (!targetVersion) { const result = await fetchPackageProfile(packageName, '', ecosystem); registry = result.profile; targetVersion = registry.latest || ''; }
    res.json({ registry, plan: buildRemediationPlan({ packageName, version, ecosystem, targetVersion, advisoryId: String(req.body.advisoryId || ''), fileName: String(req.body.fileName || '') }) });
  } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/remediation/github', requireApiToken, async (req, res) => {
  try {
    const repository = validateIdentifier(req.body.repository, 'repository', 180); const packageName = validateIdentifier(req.body.packageName, 'packageName'); const version = validateIdentifier(req.body.version, 'version', 80); const ecosystem = normalizeEcosystem(req.body.ecosystem); const targetVersion = validateIdentifier(req.body.targetVersion || req.body.fixedVersion, 'targetVersion', 80); const advisoryId = String(req.body.advisoryId || ''); const fileName = String(req.body.fileName || '');
    const plan = buildRemediationPlan({ packageName, version, ecosystem, targetVersion, advisoryId, fileName }); if (plan.status !== 'ready-for-review') return res.status(400).json({ plan });
    const dispatch = await dispatchRemediation({ repository, packageName, version, targetVersion, ecosystem, advisoryId, fileName }); res.status(202).json({ plan, dispatch });
  } catch (error) { res.status(error.statusCode || 400).json({ error: error.message }); }
});

app.post('/api/integrations/slack/test', requireApiToken, async (_req, res) => {
  try { const result = await notifySlack({ title: 'Radius integration test', text: 'Radius can deliver live advisory notifications to this Slack channel.' }); if (result.status === 'not_configured') return res.status(503).json(result); res.json(result); }
  catch (error) { res.status(502).json({ provider: 'slack', status: 'failed', error: error.message }); }
});

app.post('/api/ingest/lockfile', requireApiToken, upload.single('lockfile'), async (req, res) => { try { if (!req.file) return res.status(400).json({ error: 'A dependency file is required.' }); const result = await ingestDependencyFile({ content: req.file.buffer.toString('utf8'), fileName: req.file.originalname, serviceName: req.body.serviceName, capturedAt: req.body.capturedAt, ecosystem: req.body.ecosystem, metadata: req.body }); res.json({ ...result, fileName: req.file.originalname }); } catch (error) { res.status(error.statusCode || 400).json({ error: error.message }); } });

app.post('/api/integrations/webhook', verifyWebhook, async (req, res) => { try { const result = await ingestWebhookPayload(req.body); res.status(202).json({ accepted: true, ...result }); } catch (error) { res.status(error.statusCode || 400).json({ error: error.message }); } });
app.post('/api/integrations/deployment', verifyWebhook, async (req, res) => { try { const result = await ingestWebhookPayload(req.body); res.status(202).json({ accepted: true, ...result }); } catch (error) { res.status(error.statusCode || 400).json({ error: error.message }); } });
app.post('/api/integrations/github', verifyGithubWebhook, async (req, res) => {
  try {
    const event = String(req.get('X-GitHub-Event') || 'unknown'); const repository = String(req.body?.repository?.full_name || ''); if (event === 'ping') return res.status(202).json({ accepted: true, event, scanned: false }); if (!repository) return res.status(400).json({ error: 'GitHub payload is missing repository.full_name.' });
    const ref = normalizeRef(event === 'push' ? req.body.ref : req.body.repository.default_branch); const dependencyFile = await fetchDependencyFile({ repository, ref, paths: changedDependencyPaths(req.body) }); if (!dependencyFile) return res.status(202).json({ accepted: true, event, repository, scanned: false, reason: 'No supported dependency file was found.' });
    const ingestion = await ingestDependencyFile({ content: dependencyFile.content, fileName: dependencyFile.name, serviceName: repository, capturedAt: new Date().toISOString(), ecosystem: 'auto', metadata: { environment: 'production', owner: req.body.repository.owner?.login || '', deploymentSha: req.body.after || req.body.workflow_run?.head_sha || '', sourceUrl: `https://github.com/${repository}/blob/${ref}/${dependencyFile.name}` } });
    const notification = ingestion.advisories.findings.length ? await safeSlack({ title: `Radius advisory alert · ${repository}`, text: `${ingestion.advisories.findings.length} live OSV finding(s) were detected during the GitHub ${event} scan.`, findings: ingestion.advisories.findings, repository }) : { provider: 'slack', status: 'not_needed' };
    res.status(202).json({ accepted: true, event, repository, ref, dependencyFile: dependencyFile.name, ingestion, notification });
  } catch (error) { res.status(error.statusCode || 502).json({ error: error.message }); }
});

app.post('/api/incidents', requireApiToken, async (req, res) => { try { const packageName = validateIdentifier(req.body.packageName, 'packageName'); const version = validateIdentifier(req.body.version, 'version', 80); const startsAt = validateIdentifier(req.body.startsAt, 'startsAt', 80); const endsAt = validateIdentifier(req.body.endsAt, 'endsAt', 80); const ecosystem = normalizeEcosystem(req.body.ecosystem); const { data, profile } = await fetchPackageProfile(packageName, version, ecosystem); profile.typosquats = await findTyposquats(packageName, ecosystem); await enrichProfile(packageName, version, true, ecosystem); const incident = await createIncident({ packageName, version, ecosystem, startsAt, endsAt, metadata: { ecosystem } }); let impact = await impactForIncident({ packageName, version, ecosystem, startsAt, endsAt }); const relatedNames = impact.dependentVersions.slice(0, 10).map((item) => item.name).filter((name) => name && name !== packageName); if (relatedNames.length) { await Promise.all(relatedNames.map((name) => enrichProfile(name, '', false, ecosystem).catch(() => null))); impact = await impactForIncident({ packageName, version, ecosystem, startsAt, endsAt }); } const notification = await safeSlack({ title: `Radius incident declared · ${packageName}@${version}`, text: `${impact.summary.services} service(s) are inside the declared exposure window.`, repository: '' }); res.json({ incident, impact, notification, registry: { ecosystem, name: data.name || profile.name, description: data.description || profile.description, versionPublishedAt: data.time?.[version] || profile.publishedAt || null, profile } }); } catch (error) { res.status(400).json({ error: error.message }); } });

app.post('/api/impact', requireApiToken, async (req, res) => { try { res.json(await impactForIncident({ ...req.body, ecosystem: normalizeEcosystem(req.body.ecosystem) })); } catch (error) { res.status(hydraRequired() ? 503 : 400).json({ error: error.message }); } });
app.get('/api/incidents/:id', async (req, res) => { const graph = await snapshot(); const incident = graph.incidents.find((item) => String(item.id) === String(req.params.id)); if (!incident) return res.status(404).json({ error: 'Incident not found.' }); try { res.json({ incident, impact: await impactForIncident(incident) }); } catch (error) { res.status(hydraRequired() ? 503 : 400).json({ error: error.message }); } });

app.use((error, _req, res, _next) => res.status(500).json({ error: process.env.NODE_ENV === 'production' ? 'Unexpected server error.' : error.message || 'Unexpected server error' }));

const port = Number(process.env.PORT || 4100); app.listen(port, () => console.log(`Radius API listening on http://localhost:${port}`));

async function ingestWebhookPayload(payload = {}) {
  const dependencyFile = payload.dependencyFile || payload.lockfile || payload.manifest || {}; const content = dependencyFile.content || (dependencyFile.base64 ? Buffer.from(dependencyFile.base64, 'base64').toString('utf8') : ''); if (!content) throw new Error('Webhook requires dependencyFile.content or dependencyFile.base64.');
  return ingestDependencyFile({ content, fileName: dependencyFile.name || 'dependencies.json', serviceName: payload.serviceName || payload.service?.name, capturedAt: payload.capturedAt || payload.deployment?.observedAt || new Date().toISOString(), ecosystem: payload.ecosystem || dependencyFile.ecosystem, metadata: { ...(payload.service || {}), ...(payload.deployment || {}), ...payload } });
}

async function ingestDependencyFile({ content, fileName, serviceName, capturedAt, ecosystem = 'auto', metadata = {} }) {
  const service = validateIdentifier(serviceName, 'serviceName'); const observed = validateIdentifier(capturedAt, 'capturedAt'); const parsed = parseDependencyFile(content, fileName, normalizeEcosystem(ecosystem, true)); const normalizedMetadata = { environment: String(metadata.environment || 'production'), owner: String(metadata.owner || 'Platform'), deploymentSha: String(metadata.deploymentSha || metadata.sha || metadata.commit || ''), deployedAt: String(metadata.deployedAt || metadata.startedAt || observed), resolvedAt: String(metadata.resolvedAt || metadata.endedAt || observed) }; const records = recordsForLockfile(parsed, service, fileName, observed, normalizedMetadata); const storage = await upsertGraph(records); const advisories = await scanDependencies(parsed.entries); return { serviceName: service, capturedAt: observed, ecosystem: parsed.ecosystem, format: parsed.format, packages: parsed.entries.length, dependencies: parsed.edges.length, roots: parsed.roots.length, storage, advisories, detectedPackages: parsed.entries.slice(0, 60).map((e) => ({ name: e.name, version: e.version, ecosystem: e.ecosystem || parsed.ecosystem })) }; }

function normalizeEcosystem(value, allowAuto = false) { const normalized = String(value || (allowAuto ? 'auto' : 'npm')).toLowerCase().trim(); const valid = ['auto', 'npm', 'pypi', 'cargo', 'go', 'maven', 'unknown']; if (!valid.includes(normalized) || (!allowAuto && normalized === 'auto')) throw new Error(`Unsupported ecosystem ${value}. Use npm, pypi, cargo, go, or maven.`); return normalized; }
function normalizeRef(value) { return String(value || '').replace(/^refs\/heads\//, '').replace(/^refs\/tags\//, '') || 'HEAD'; }
async function safeSlack(payload) { try { return await notifySlack(payload); } catch (error) { return { provider: 'slack', status: 'failed', error: error.message }; } }
function uniqueById(items) { return [...new Map(items.map((item) => [item.id, item])).values()]; }
