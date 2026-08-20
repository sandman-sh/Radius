import crypto from 'node:crypto';

const buckets = new Map();

export function securityConfig() {
  return { webhookSecretConfigured: Boolean(process.env.RADIUS_WEBHOOK_SECRET), apiTokenConfigured: Boolean(process.env.RADIUS_API_TOKEN), requireHydra: process.env.RADIUS_REQUIRE_HYDRA === 'true', environment: process.env.NODE_ENV || 'development' };
}

export function requireApiToken(request, response, next) {
  const configured = process.env.RADIUS_API_TOKEN;
  if (!configured) return process.env.NODE_ENV === 'production' ? response.status(503).json({ error: 'API token is not configured.' }) : next();
  const authorization = String(request.get('Authorization') || '');
  const supplied = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  const suppliedBuffer = Buffer.from(supplied); const configuredBuffer = Buffer.from(configured);
  if (suppliedBuffer.length !== configuredBuffer.length || !crypto.timingSafeEqual(suppliedBuffer, configuredBuffer)) return response.status(401).json({ error: 'Invalid API token.' });
  return next();
}

export function rateLimit(request, response, next) {
  const limit = Number(process.env.RADIUS_RATE_LIMIT || 120);
  const windowMs = Number(process.env.RADIUS_RATE_WINDOW_MS || 60_000);
  const key = request.ip || request.socket.remoteAddress || 'unknown'; const now = Date.now(); const bucket = buckets.get(key);
  if (!bucket || now - bucket.startedAt >= windowMs) buckets.set(key, { startedAt: now, count: 1 });
  else { bucket.count += 1; if (bucket.count > limit) return response.status(429).json({ error: 'Rate limit exceeded.' }); }
  response.setHeader('X-RateLimit-Limit', String(limit)); return next();
}

export function verifyWebhook(request, response, next) {
  const secret = process.env.RADIUS_WEBHOOK_SECRET;
  if (!secret) return process.env.NODE_ENV === 'production' ? response.status(503).json({ error: 'Webhook secret is not configured.' }) : next();
  const provided = String(request.get('X-Radius-Signature') || ''); const expected = `sha256=${crypto.createHmac('sha256', secret).update(request.rawBody || Buffer.from('')).digest('hex')}`;
  const providedBuffer = Buffer.from(provided); const expectedBuffer = Buffer.from(expected);
  if (providedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(providedBuffer, expectedBuffer)) return response.status(401).json({ error: 'Invalid webhook signature.' });
  return next();
}

export function verifyGithubWebhook(request, response, next) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET || process.env.RADIUS_WEBHOOK_SECRET;
  if (!secret) return process.env.NODE_ENV === 'production' || process.env.RADIUS_REQUIRE_HYDRA === 'true' ? response.status(503).json({ error: 'GitHub webhook secret is not configured.' }) : next();
  const provided = String(request.get('X-Hub-Signature-256') || '');
  const expected = `sha256=${crypto.createHmac('sha256', secret).update(request.rawBody || Buffer.from('')).digest('hex')}`;
  const providedBuffer = Buffer.from(provided); const expectedBuffer = Buffer.from(expected);
  if (providedBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(providedBuffer, expectedBuffer)) return response.status(401).json({ error: 'Invalid GitHub webhook signature.' });
  return next();
}

export function validateIdentifier(value, label, max = 180) {
  const text = String(value || '').trim(); if (!text || text.length > max || /[\u0000-\u001f\u007f]/.test(text)) throw new Error(`${label} is invalid.`); return text;
}
