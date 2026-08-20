import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const dataDirectory = process.env.RADIUS_DATA_DIR || path.join(projectRoot, '.radius-data');
const dataFile = path.join(dataDirectory, 'radius-graph.json');

const emptyGraph = () => ({ nodes: [], edges: [], profiles: [], incidents: [] });
let cache = null;
let writeQueue = Promise.resolve();

async function readGraph() {
  if (cache) return cache;
  try {
    cache = JSON.parse(await fs.readFile(dataFile, 'utf8'));
  } catch {
    cache = emptyGraph();
  }
  cache.nodes ||= [];
  cache.edges ||= [];
  cache.profiles ||= [];
  cache.incidents ||= [];
  return cache;
}

async function persist(graph) {
  writeQueue = writeQueue.then(async () => {
    await fs.mkdir(dataDirectory, { recursive: true });
    await fs.writeFile(dataFile, JSON.stringify(graph, null, 2), 'utf8');
  });
  return writeQueue;
}

export async function upsert(records = {}) {
  const graph = await readGraph();
  for (const node of records.vertices || []) {
    const index = graph.nodes.findIndex((item) => item.id === node.id);
    if (index === -1) graph.nodes.push({ ...node });
    else graph.nodes[index] = { ...graph.nodes[index], ...node };
  }
  for (const edge of records.edges || []) {
    const index = graph.edges.findIndex((item) => item.id === edge.id);
    if (index === -1) graph.edges.push({ ...edge });
    else graph.edges[index] = { ...graph.edges[index], ...edge };
  }
  await persist(graph);
  return graph;
}

export async function upsertProfile(profile) {
  const graph = await readGraph();
  const index = graph.profiles.findIndex((item) => item.name === profile.name && (item.ecosystem || 'npm') === (profile.ecosystem || 'npm'));
  if (index === -1) graph.profiles.push(profile);
  else graph.profiles[index] = { ...graph.profiles[index], ...profile };
  await persist(graph);
  return profile;
}

export async function addIncident(incident) {
  const graph = await readGraph();
  const index = graph.incidents.findIndex((item) => item.id === incident.id);
  if (index === -1) graph.incidents.unshift(incident);
  else graph.incidents[index] = { ...graph.incidents[index], ...incident };
  await persist(graph);
  return incident;
}

export async function snapshot() {
  const graph = await readGraph();
  return {
    nodes: graph.nodes.map((node) => ({ ...node })),
    edges: graph.edges.map((edge) => ({ ...edge })),
    profiles: graph.profiles.map((profile) => ({ ...profile })),
    incidents: graph.incidents.map((incident) => ({ ...incident }))
  };
}

export async function clearLocalGraph() {
  cache = emptyGraph();
  await persist(cache);
}

export function localDataPath() {
  return dataFile;
}
