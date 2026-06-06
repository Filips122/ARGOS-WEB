const WAZUH_API_URL = process.env.WAZUH_API_URL;
const WAZUH_API_USER = process.env.WAZUH_API_USER;
const WAZUH_API_PASSWORD = process.env.WAZUH_API_PASSWORD;

function assertWazuhApiEnv() {
  if (!WAZUH_API_URL || !WAZUH_API_USER || !WAZUH_API_PASSWORD) {
    throw new Error(
      'Missing Wazuh API environment variables: WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD'
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

async function getWazuhToken(): Promise<string> {
  assertWazuhApiEnv();
  assertUsableSecret(WAZUH_API_PASSWORD, 'WAZUH_API_PASSWORD');

  const basicAuth = Buffer.from(`${WAZUH_API_USER}:${WAZUH_API_PASSWORD}`).toString('base64');

  const response = await fetch(`${WAZUH_API_URL}/security/user/authenticate?raw=true`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basicAuth}`,
    },
    cache: 'no-store',
  }).catch((error) => {
    throw new Error(`Wazuh authentication fetch failed: ${describeFetchError(error)}`);
  });

  if (!response.ok) {
    throw new Error(`Wazuh authentication failed: ${response.status} ${response.statusText}`);
  }

  return response.text();
}

export async function wazuhApiGet<T>(endpoint: string): Promise<T> {
  assertWazuhApiEnv();

  const token = await getWazuhToken();

  const response = await fetch(`${WAZUH_API_URL}${endpoint}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    cache: 'no-store',
  }).catch((error) => {
    throw new Error(`Wazuh API fetch failed: ${describeFetchError(error)}`);
  });

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`Wazuh API request failed: ${response.status} ${response.statusText} ${body}`);
  }

  return response.json() as Promise<T>;
}
