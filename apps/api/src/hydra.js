const config = {
  baseUrl: process.env.HYDRA_HTTP_URL || 'http://localhost:8443',
  graphId: process.env.HYDRA_GRAPH_ID || 'default',
  namespace: process.env.HYDRA_NAMESPACE || 'default',
  cellId: process.env.HYDRA_CELL_ID || 'cell-0',
  token: process.env.HYDRA_TOKEN || 'local-development-token-32-bytes'
};

export function hydraConfig() {
  return { baseUrl: config.baseUrl, graphId: config.graphId, namespace: config.namespace, cellId: config.cellId, tokenConfigured: Boolean(config.token) };
}

export function hydraRequired() {
  return process.env.RADIUS_REQUIRE_HYDRA === 'true' || process.env.NODE_ENV === 'production';
}

export async function hydraHealth() {
  const response = await fetch(`${config.baseUrl}/healthz`, { signal: AbortSignal.timeout(2500) });
  if (!response.ok) throw new Error(`HydraDB health check failed (${response.status})`);
  return response.json();
}

export async function query(queryText, parameters = {}, consistency = 'causal') {
  const response = await fetch(`${config.baseUrl}/v1/graphs/${encodeURIComponent(config.graphId)}/query`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.token}`,
      'X-Graph-Namespace': config.namespace,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      cell_id: config.cellId,
      query: queryText,
      parameters,
      consistency,
      page_size: 512
    }),
    signal: AbortSignal.timeout(15000)
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body?.error?.message || `HydraDB query failed (${response.status})`);
  return body;
}

export function rows(body) {
  return (body.rows || []).map((row) => Object.fromEntries((body.columns || []).map((column, index) => [column, row[index]?.value ?? row[index]])));
}
