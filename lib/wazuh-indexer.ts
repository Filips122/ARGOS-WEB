const WAZUH_INDEXER_URL = process.env.WAZUH_INDEXER_URL;
const WAZUH_INDEXER_USER = process.env.WAZUH_INDEXER_USER;
const WAZUH_INDEXER_PASSWORD = process.env.WAZUH_INDEXER_PASSWORD;

function assertWazuhIndexerEnv() {
  if (!WAZUH_INDEXER_URL || !WAZUH_INDEXER_USER || !WAZUH_INDEXER_PASSWORD) {
    throw new Error(
      'Missing Wazuh Indexer environment variables: WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD'
    );
  }
}

function assertUsableSecret(value: string | undefined, name: string) {
  if (!value || value.startsWith('CAMBIAR_POR_')) {
    throw new Error(`Missing real value for ${name} in .env.local`);
  }
}

function describeFetchError(error: unknown) {
  if (!(error instanceof Error)) return 'Unknown fetch error';
  const cause = error.cause instanceof Error ? `: ${error.cause.message}` : '';
  return `${error.message}${cause}`;
}

async function wazuhIndexerRequest<T>(path: string, body: unknown, method = 'POST'): Promise<T> {
  assertWazuhIndexerEnv();
  assertUsableSecret(WAZUH_INDEXER_USER, 'WAZUH_INDEXER_USER');
  assertUsableSecret(WAZUH_INDEXER_PASSWORD, 'WAZUH_INDEXER_PASSWORD');

  const basicAuth = Buffer.from(`${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}`).toString('base64');

  const response = await fetch(`${WAZUH_INDEXER_URL}${path}`, {
    method,
    headers: {
      Authorization: `Basic ${basicAuth}`,
      'Content-Type': 'application/json',
    },
    cache: 'no-store',
    body: JSON.stringify(body),
  }).catch((error) => {
    throw new Error(`Wazuh Indexer fetch failed: ${describeFetchError(error)}`);
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(`Wazuh Indexer request failed: ${response.status} ${response.statusText} ${text}`);
  }

  return response.json() as Promise<T>;
}

export async function wazuhIndexerSearch<T>(body: unknown): Promise<T> {
  return wazuhIndexerRequest('/wazuh-alerts-*/_search', body);
}

type WazuhSearchHit = {
  _id?: string;
  _source?: Record<string, unknown>;
  sort?: unknown[];
};

type WazuhSearchResponse = {
  _scroll_id?: string;
  hits?: {
    total?: number | { value?: number; relation?: string };
    hits?: WazuhSearchHit[];
  };
};

const alertSourceFields = [
  '@timestamp',
  'timestamp',
  'rule.id',
  'rule.sid',
  'rule.level',
  'rule.description',
  'rule.mitre.tactic',
  'rule.mitre.tactics',
  'title',
  'full_log',
  'data.srcip',
  'data.src_ip',
  'data.sid',
  'data.username',
  'data.command',
  'data.srcport',
  'data.dstport',
  'decoder.name',
  'user.name',
  'process.command_line',
  'source.port',
  'destination.port',
  'GeoLocation.city_name',
  'GeoLocation.country_name',
  'GeoLocation.country_code2',
  'GeoLocation.location',
  'srcip',
  'source.ip',
  'client.ip',
  'remote_ip',
  'agent.id',
  'agent.name',
  'agent.ip',
  'host.ip',
];

function buildAlertsQuery(from: string, size: number, searchAfter?: unknown[]) {
  return {
    size,
    track_total_hits: searchAfter ? false : true,
    _source: {
      includes: alertSourceFields,
    },
    sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'date' } }, { '_id': { order: 'asc' } }],
    ...(searchAfter ? { search_after: searchAfter } : {}),
    query: {
      range: {
        '@timestamp': {
          gte: from,
          lte: 'now',
        },
      },
    },
  };
}

export async function getRecentWazuhAlerts(limit = 10000, from = 'now-30d') {
  return wazuhIndexerSearch(buildAlertsQuery(from, Math.min(Math.max(limit, 1), 10000)));
}

export async function getAllRecentWazuhAlerts(from = 'now-30d', batchSize = 10000) {
  const size = Math.min(Math.max(batchSize, 1), 10000);
  const firstPage = await wazuhIndexerRequest<WazuhSearchResponse>('/wazuh-alerts-*/_search', buildAlertsQuery(from, size));

  const hits = [...(firstPage.hits?.hits ?? [])];
  let lastSort = hits.at(-1)?.sort;

  while (lastSort) {
    const page = await wazuhIndexerRequest<WazuhSearchResponse>('/wazuh-alerts-*/_search', buildAlertsQuery(from, size, lastSort));
    const pageHits = page.hits?.hits ?? [];
    if (pageHits.length === 0) break;

    hits.push(...pageHits);
    lastSort = pageHits.at(-1)?.sort;
  }

  return {
    ...firstPage,
    hits: {
      ...firstPage.hits,
      hits,
    },
  };
}

export async function getWazuhAlertsCount(from = 'now-24h') {
  return wazuhIndexerSearch({
    size: 0,
    track_total_hits: true,
    query: {
      range: {
        '@timestamp': {
          gte: from,
          lte: 'now',
        },
      },
    },
  });
}
