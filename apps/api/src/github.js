const githubApi = 'https://api.github.com';

export function githubConfig() {
  return { tokenConfigured: Boolean(process.env.RADIUS_GITHUB_TOKEN || process.env.GITHUB_TOKEN), webhookSecretConfigured: Boolean(process.env.GITHUB_WEBHOOK_SECRET || process.env.RADIUS_WEBHOOK_SECRET), provider: 'GitHub' };
}

export async function fetchDependencyFile({ repository, ref, paths = [] }) {
  const [owner, repo] = String(repository || '').split('/');
  if (!owner || !repo) throw new Error('GitHub repository must be in owner/repository format.');
  const token = process.env.RADIUS_GITHUB_TOKEN || process.env.GITHUB_TOKEN || '';
  const candidates = unique([...paths, 'package-lock.json', 'npm-shrinkwrap.json', 'requirements.txt', 'Pipfile.lock', 'poetry.lock', 'Cargo.lock', 'go.mod', 'pom.xml']);
  for (const path of candidates) {
    const url = `${githubApi}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(ref || 'HEAD')}`;
    const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'Radius/0.3' }; if (token) headers.Authorization = `Bearer ${token}`;
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(15000) });
    if (response.status === 404) continue;
    if (!response.ok) throw new Error(`GitHub contents API returned ${response.status}.`);
    const body = await response.json();
    if (body.type !== 'file' || !body.content) continue;
    return { name: path, content: Buffer.from(body.content.replace(/\s/g, ''), 'base64').toString('utf8'), repository, ref: ref || 'HEAD', sha: body.sha || '' };
  }
  return null;
}

export async function dispatchRemediation({ repository, packageName, version, targetVersion, ecosystem, advisoryId = '', fileName = '' }) {
  const [owner, repo] = String(repository || '').split('/');
  const token = process.env.RADIUS_GITHUB_TOKEN || process.env.GITHUB_TOKEN || '';
  if (!owner || !repo) throw new Error('GitHub repository must be in owner/repository format.');
  if (!token) { const error = new Error('RADIUS_GITHUB_TOKEN or GITHUB_TOKEN is required to dispatch remediation.'); error.statusCode = 503; throw error; }
  const response = await fetch(`${githubApi}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/dispatches`, {
    method: 'POST',
    headers: { Accept: 'application/vnd.github+json', Authorization: `Bearer ${token}`, 'X-GitHub-Api-Version': process.env.GITHUB_API_VERSION || '2026-03-10', 'Content-Type': 'application/json', 'User-Agent': 'Radius/0.3' },
    body: JSON.stringify({ event_type: 'radius-remediation', client_payload: { packageName, version, targetVersion, ecosystem, advisoryId, fileName } }),
    signal: AbortSignal.timeout(15000)
  });
  if (response.status !== 204) { const body = await response.json().catch(() => ({})); const error = new Error(body?.message || `GitHub dispatch returned ${response.status}.`); error.statusCode = response.status === 404 ? 404 : 502; throw error; }
  return { provider: 'github', status: 'dispatched', repository, workflow: 'radius-remediate.yml', eventType: 'radius-remediation' };
}

export function changedDependencyPaths(payload = {}) {
  const paths = [];
  for (const commit of payload.commits || []) paths.push(...(commit.added || []), ...(commit.modified || []));
  return paths.filter((path) => /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|requirements\.txt|Pipfile\.lock|poetry\.lock|Cargo\.lock|go\.mod|pom\.xml)$/.test(path));
}

function unique(values) { return [...new Set(values.filter(Boolean))]; }
