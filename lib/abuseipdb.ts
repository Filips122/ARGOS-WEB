import { mkdir, readFile, writeFile } from 'fs/promises';
import { isIP } from 'net';
import path from 'path';
import type { Attack } from '@/lib/mock-data';

const ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2/check';
const CACHE_PATH = path.join(process.cwd(), '.cache', 'abuseipdb-cache.json');
const MIN_ALERTS_PER_IP = readPositiveInt(process.env.ABUSEIPDB_MIN_ALERTS_PER_IP, 10);
const CACHE_TTL_HOURS = readPositiveInt(process.env.ABUSEIPDB_CACHE_TTL_HOURS, 24);
const MAX_LOOKUPS_PER_REFRESH = readPositiveInt(process.env.ABUSEIPDB_MAX_LOOKUPS_PER_REFRESH, 5);
const MAX_AGE_DAYS = readPositiveInt(process.env.ABUSEIPDB_MAX_AGE_DAYS, 90);

type AbuseStatus = NonNullable<Attack['abuseipdb']>['status'];

type AbuseCacheEntry = {
  status: Extract<AbuseStatus, 'checked' | 'error'>;
  checkedAt: string;
  score?: number;
  totalReports?: number;
  countryCode?: string;
  isp?: string;
  domain?: string;
  lastReportedAt?: string | null;
  reason?: string;
};

type AbuseCacheFile = {
  version: 1;
  rateLimitedUntil?: string;
  entries: Record<string, AbuseCacheEntry>;
};

export type CriminalIntelligenceStats = {
  enabled: boolean;
  minAlertsPerIp: number;
  cacheTtlHours: number;
  rateLimitedUntil?: string;
  overview: {
    publicIps: number;
    eligibleIps: number;
    checkedIps: number;
    cachedIps: number;
    highRiskIps: number;
    maliciousAlerts: number;
    privateAlerts: number;
    belowThresholdAlerts: number;
    rateLimitedAlerts: number;
  };
  reputationBuckets: { label: string; value: number; color: string }[];
  topReportedIps: { label: string; value: number; meta: string }[];
  statusBreakdown: { label: string; value: number }[];
};

function readPositiveInt(value: string | undefined, fallback: number) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function isPrivateIp(ip: string) {
  if (isIP(ip) !== 4) return isIP(ip) === 0;
  const parts = ip.split('.').map((part) => Number.parseInt(part, 10));
  const [a, b] = parts;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 0) ||
    a >= 224
  );
}

function isFresh(entry: AbuseCacheEntry, now: number) {
  return now - new Date(entry.checkedAt).getTime() < CACHE_TTL_HOURS * 60 * 60 * 1000;
}

async function readCache(): Promise<AbuseCacheFile> {
  try {
    const raw = await readFile(CACHE_PATH, 'utf8');
    const parsed = JSON.parse(raw) as AbuseCacheFile;
    return {
      version: 1,
      rateLimitedUntil: parsed.rateLimitedUntil,
      entries: parsed.entries ?? {},
    };
  } catch {
    return { version: 1, entries: {} };
  }
}

async function writeCache(cache: AbuseCacheFile) {
  await mkdir(path.dirname(CACHE_PATH), { recursive: true });
  await writeFile(CACHE_PATH, JSON.stringify(cache, null, 2), 'utf8');
}

async function queryAbuseIpDb(ip: string): Promise<AbuseCacheEntry | 'rate_limited'> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return {
      status: 'error',
      checkedAt: new Date().toISOString(),
      reason: 'ABUSEIPDB_API_KEY is not configured',
    };
  }

  const url = new URL(ABUSEIPDB_API_URL);
  url.searchParams.set('ipAddress', ip);
  url.searchParams.set('maxAgeInDays', String(MAX_AGE_DAYS));

  const response = await fetch(url, {
    headers: {
      Key: apiKey,
      Accept: 'application/json',
    },
    cache: 'no-store',
  });

  if (response.status === 429) return 'rate_limited';

  if (!response.ok) {
    return {
      status: 'error',
      checkedAt: new Date().toISOString(),
      reason: `AbuseIPDB request failed: ${response.status} ${response.statusText}`,
    };
  }

  const json = await response.json() as {
    data?: {
      abuseConfidenceScore?: number;
      totalReports?: number;
      countryCode?: string;
      isp?: string;
      domain?: string;
      lastReportedAt?: string | null;
    };
  };

  return {
    status: 'checked',
    checkedAt: new Date().toISOString(),
    score: Number(json.data?.abuseConfidenceScore ?? 0),
    totalReports: Number(json.data?.totalReports ?? 0),
    countryCode: json.data?.countryCode,
    isp: json.data?.isp,
    domain: json.data?.domain,
    lastReportedAt: json.data?.lastReportedAt ?? null,
  };
}

function toAttackIntel(ip: string, seenCount: number, status: AbuseStatus, entry?: AbuseCacheEntry, reason?: string): NonNullable<Attack['abuseipdb']> {
  return {
    ip,
    status,
    seenCount,
    score: entry?.score,
    totalReports: entry?.totalReports,
    countryCode: entry?.countryCode,
    isp: entry?.isp,
    domain: entry?.domain,
    lastReportedAt: entry?.lastReportedAt,
    checkedAt: entry?.checkedAt,
    reason: reason ?? entry?.reason,
  };
}

export async function enrichAttacksWithAbuseIpDb(attacks: Attack[]) {
  if (attacks.length === 0) {
    return { attacks, criminalIntelligence: buildCriminalIntelligenceStats(attacks) };
  }

  const cache = await readCache();
  const now = Date.now();
  const apiConfigured = Boolean(process.env.ABUSEIPDB_API_KEY);
  const rateLimited = cache.rateLimitedUntil ? new Date(cache.rateLimitedUntil).getTime() > now : false;
  const ipCounts = new Map<string, number>();

  for (const attack of attacks) {
    const ip = attack.source.ip?.trim();
    if (ip) ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1);
  }

  let lookups = 0;
  let cacheChanged = false;

  for (const [ip, count] of ipCounts) {
    if (count < MIN_ALERTS_PER_IP || isPrivateIp(ip) || isIP(ip) === 0) continue;
    const cached = cache.entries[ip];
    if (cached && isFresh(cached, now)) continue;
    if (!apiConfigured || rateLimited || lookups >= MAX_LOOKUPS_PER_REFRESH) continue;

    const result = await queryAbuseIpDb(ip);
    lookups += 1;

    if (result === 'rate_limited') {
      cache.rateLimitedUntil = new Date(now + 60 * 60 * 1000).toISOString();
      cacheChanged = true;
      break;
    }

    cache.entries[ip] = result;
    cacheChanged = true;
  }

  if (cacheChanged) await writeCache(cache);

  const enriched = attacks.map((attack) => {
    const ip = attack.source.ip?.trim();
    if (!ip) return attack;
    const seenCount = ipCounts.get(ip) ?? 1;

    if (isIP(ip) === 0) {
      return { ...attack, abuseipdb: toAttackIntel(ip, seenCount, 'error', undefined, 'Invalid source IP') };
    }

    if (isPrivateIp(ip)) {
      return { ...attack, abuseipdb: toAttackIntel(ip, seenCount, 'private', undefined, 'Private/local IP is not queried') };
    }

    if (seenCount < MIN_ALERTS_PER_IP) {
      return { ...attack, abuseipdb: toAttackIntel(ip, seenCount, 'below_threshold', undefined, `Requires ${MIN_ALERTS_PER_IP} alerts for lookup`) };
    }

    const cached = cache.entries[ip];
    if (cached && isFresh(cached, now)) {
      return { ...attack, abuseipdb: toAttackIntel(ip, seenCount, cached.status === 'checked' ? 'cached' : 'error', cached) };
    }

    if (!apiConfigured) {
      return { ...attack, abuseipdb: toAttackIntel(ip, seenCount, 'not_configured', undefined, 'ABUSEIPDB_API_KEY is not configured') };
    }

    if (cache.rateLimitedUntil && new Date(cache.rateLimitedUntil).getTime() > now) {
      return { ...attack, abuseipdb: toAttackIntel(ip, seenCount, 'rate_limited', undefined, 'AbuseIPDB API limit reached') };
    }

    return { ...attack, abuseipdb: toAttackIntel(ip, seenCount, 'below_threshold', undefined, 'Queued for a later lookup refresh') };
  });

  return {
    attacks: enriched,
    criminalIntelligence: buildCriminalIntelligenceStats(enriched, cache.rateLimitedUntil),
  };
}

export function buildCriminalIntelligenceStats(attacks: Attack[], rateLimitedUntil?: string): CriminalIntelligenceStats {
  const intel = attacks.map((attack) => attack.abuseipdb).filter(Boolean) as NonNullable<Attack['abuseipdb']>[];
  const uniquePublic = new Map<string, NonNullable<Attack['abuseipdb']>>();
  const uniqueEligible = new Map<string, NonNullable<Attack['abuseipdb']>>();
  const uniqueChecked = new Map<string, NonNullable<Attack['abuseipdb']>>();

  for (const item of intel) {
    if (item.status !== 'private' && item.status !== 'error') uniquePublic.set(item.ip, item);
    if (item.seenCount >= MIN_ALERTS_PER_IP && item.status !== 'private') uniqueEligible.set(item.ip, item);
    if (item.status === 'cached' || item.status === 'checked') uniqueChecked.set(item.ip, item);
  }

  const highRiskIps = Array.from(uniqueChecked.values()).filter((item) => (item.score ?? 0) >= 80).length;
  const maliciousAlerts = intel.filter((item) => (item.score ?? 0) >= 80).length;
  const privateAlerts = intel.filter((item) => item.status === 'private').length;
  const belowThresholdAlerts = intel.filter((item) => item.status === 'below_threshold').length;
  const rateLimitedAlerts = intel.filter((item) => item.status === 'rate_limited').length;

  const bucketCounts = [
    { label: '0-39', value: 0, color: '#38f8d4' },
    { label: '40-79', value: 0, color: '#ffd166' },
    { label: '80-100', value: 0, color: '#ff2f5f' },
    { label: 'Unknown', value: 0, color: '#7ea8b8' },
  ];

  for (const item of uniqueChecked.values()) {
    const score = item.score;
    if (score === undefined) bucketCounts[3].value += 1;
    else if (score >= 80) bucketCounts[2].value += 1;
    else if (score >= 40) bucketCounts[1].value += 1;
    else bucketCounts[0].value += 1;
  }

  const statusLabels: Record<AbuseStatus, string> = {
    checked: 'Checked now',
    cached: 'Cached',
    below_threshold: 'Below threshold',
    private: 'Private IP',
    not_configured: 'Not configured',
    rate_limited: 'Rate limited',
    error: 'Error',
  };

  const statusCounts = new Map<string, number>();
  for (const item of intel) {
    const label = statusLabels[item.status];
    statusCounts.set(label, (statusCounts.get(label) ?? 0) + 1);
  }

  return {
    enabled: Boolean(process.env.ABUSEIPDB_API_KEY),
    minAlertsPerIp: MIN_ALERTS_PER_IP,
    cacheTtlHours: CACHE_TTL_HOURS,
    rateLimitedUntil,
    overview: {
      publicIps: uniquePublic.size,
      eligibleIps: uniqueEligible.size,
      checkedIps: uniqueChecked.size,
      cachedIps: Array.from(uniqueChecked.values()).filter((item) => item.status === 'cached').length,
      highRiskIps,
      maliciousAlerts,
      privateAlerts,
      belowThresholdAlerts,
      rateLimitedAlerts,
    },
    reputationBuckets: bucketCounts,
    topReportedIps: Array.from(uniqueChecked.values())
      .sort((a, b) => (b.score ?? 0) - (a.score ?? 0) || (b.totalReports ?? 0) - (a.totalReports ?? 0))
      .slice(0, 5)
      .map((item) => ({
        label: item.ip,
        value: item.score ?? 0,
        meta: `${item.totalReports ?? 0} reports${item.countryCode ? ` · ${item.countryCode}` : ''}`,
      })),
    statusBreakdown: Array.from(statusCounts.entries()).map(([label, value]) => ({ label, value })),
  };
}
