import { wazuhIndexerSearch } from '@/lib/wazuh-indexer';

type WazuhHit = {
  _id?: string;
  _source?: Record<string, any>;
  sort?: unknown[];
};

type WazuhSearchResponse = {
  hits?: {
    total?: number | { value?: number; relation?: string };
    hits?: WazuhHit[];
  };
};

export type WeakLabel = 'ATTACK' | 'BENIGN' | 'UNKNOWN';

export type TaxonomyLabel =
  | 'CredentialAccess'
  | 'LateralMovement'
  | 'AuthenticationFailure'
  | 'ServiceFailure'
  | 'SystemAlert'
  | 'OtherAlert';

export type DatasetRecord = {
  alert_id: string;
  timestamp: string;
  window_start: string;
  rule_id: string;
  rule_level: number;
  rule_description: string;
  rule_firedtimes: number;
  rule_groups: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  agent_id: string;
  agent_name: string;
  agent_ip: string;
  src_ip: string;
  src_port: string;
  src_user: string;
  dst_user: string;
  dst_port: string;
  decoder_name: string;
  program_name: string;
  location: string;
  full_log: string;
  geo_country: string;
  geo_city: string;
  geo_lat: number | null;
  geo_lon: number | null;
  has_src_ip: number;
  has_src_port: number;
  is_simulated: number;
  weak_label: WeakLabel;
  weak_label_reason: string;
  taxonomy_label: TaxonomyLabel;
};

export type DatasetManifest = {
  dataset: string;
  generated_at: string;
  range: { from: string; to: string };
  window_size: string;
  group_key: string;
  record_count: number;
  window_count: number;
  weak_label_policy: string;
  weak_label_distribution: Record<WeakLabel, number>;
  weak_label_reason_distribution: Record<string, number>;
  taxonomy_distribution: Record<string, number>;
  window_label_distribution: Record<WeakLabel, number>;
  agent_distribution: Record<string, number>;
  top_rules: { rule_id: string; rule_description: string; count: number }[];
  trainability: {
    supervised_binary_viable: boolean;
    minority_class_ratio: number;
    window_minority_class_ratio: number;
    notes: string[];
  };
};

// Superset of the fields the LAB-ALERTS feature contract and the labelling policy
// need. Deliberately wider than alertSourceFields in lib/wazuh-indexer.ts, which is
// tuned for the live dashboard and drops rule.groups, location and program_name.
export const DATASET_SOURCE_FIELDS = [
  '@timestamp',
  'timestamp',
  'rule.id',
  'rule.level',
  'rule.description',
  'rule.groups',
  'rule.firedtimes',
  'rule.mitre.tactic',
  'rule.mitre.tactics',
  'rule.mitre.technique',
  'rule.mitre.id',
  'agent.id',
  'agent.name',
  'agent.ip',
  'decoder.name',
  'predecoder.program_name',
  'location',
  'full_log',
  'data.srcip',
  'data.src_ip',
  'data.srcport',
  'data.src_port',
  'data.dstport',
  'data.dst_port',
  'data.srcuser',
  'data.dstuser',
  'data.username',
  'data.command',
  'srcip',
  'source.ip',
  'source.port',
  'destination.port',
  'user.name',
  'GeoLocation.country_name',
  'GeoLocation.country_code2',
  'GeoLocation.city_name',
  'GeoLocation.location',
  'labels.argos_local_simulation',
  'argos.localSimulation',
];

const WINDOW_MS = 60_000;

// Weak-label policy mirrored from LAB_ALERTS_REFACTOR/docs/STRATEGY_LAB-ALERTS.md
// section 4.1. Kept as an explicit, auditable list so the exported dataset can be
// re-labelled offline without re-exporting.
const ATTACK_GROUPS = new Set([
  'authentication_failed',
  'authentication_failures',
  'invalid_login',
  'multiple_authentication_failures',
  'brute_force',
  'attack',
  'attacks',
  'exploit',
  'ids',
  'intrusion_detection',
  'recon',
  'web_scan',
  'sql_injection',
  'xss',
  'shellshock',
  'rootkit',
  'rootcheck',
  'virus',
  'malware',
  'privilege_escalation',
]);

const BENIGN_GROUPS = new Set([
  'systemd',
  'dpkg',
  'docker',
  'cron',
  'syslog',
  'service_availability',
  'ossec',
  'agent_started',
  'maintenance',
  'backup',
]);

// Posture / inventory findings. They are not an attack in progress, but they are
// also not ordinary operational noise, so they get their own reason prefix and can
// be dropped in one line: df[~df.weak_label_reason.str.startswith('posture_group')].
const POSTURE_GROUPS = new Set([
  'trivy',
  'vulnerability-detector',
  'sca',
  'syscheck',
  'agent_flooding',
  'netstat',
]);

const ATTACK_TACTICS = new Set([
  'credential access',
  'lateral movement',
  'initial access',
  'privilege escalation',
  'discovery',
  'command and control',
  'exfiltration',
  'impact',
  'execution',
  'persistence',
  'defense evasion',
]);

const AUTH_FAILURE_PATTERN = /failed password|invalid user|authentication failure|brute/;

function text(value: unknown, fallback = ''): string {
  if (value === null || value === undefined) return fallback;
  const raw = String(value).trim();
  if (!raw || ['nan', 'none', 'null', 'undefined'].includes(raw.toLowerCase())) return fallback;
  return raw;
}

function toList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((item) => text(item)).filter(Boolean);
  const single = text(value);
  return single ? [single] : [];
}

function toInt(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : fallback;
}

function readGeoPoint(value: unknown): { lat: number | null; lon: number | null } {
  if (Array.isArray(value) && value.length >= 2) {
    const lon = Number(value[0]);
    const lat = Number(value[1]);
    if (Number.isFinite(lat) && Number.isFinite(lon)) return { lat, lon };
  }

  if (value && typeof value === 'object') {
    const point = value as Record<string, unknown>;
    const lat = Number(point.lat ?? point.latitude);
    const lon = Number(point.lon ?? point.longitude);
    if (Number.isFinite(lat) && Number.isFinite(lon)) return { lat, lon };
  }

  return { lat: null, lon: null };
}

function floorToWindow(timestamp: string): string {
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) return '';
  return new Date(Math.floor(parsed / WINDOW_MS) * WINDOW_MS).toISOString();
}

function classifyWeakLabel(input: {
  rule_groups: string[];
  mitre_tactics: string[];
  rule_level: number;
  rule_description: string;
}): { label: WeakLabel; reason: string } {
  const groups = input.rule_groups.map((group) => group.toLowerCase());
  const tactics = input.mitre_tactics.map((tactic) => tactic.toLowerCase());
  const description = input.rule_description.toLowerCase();

  const attackGroup = groups.find((group) => ATTACK_GROUPS.has(group));
  if (attackGroup) return { label: 'ATTACK', reason: 'attack_group:' + attackGroup };

  const attackTactic = tactics.find((tactic) => ATTACK_TACTICS.has(tactic));
  if (attackTactic) return { label: 'ATTACK', reason: 'mitre_tactic:' + attackTactic };

  if (AUTH_FAILURE_PATTERN.test(description)) {
    return { label: 'ATTACK', reason: 'description_auth_failure' };
  }

  const postureGroup = groups.find((group) => POSTURE_GROUPS.has(group));
  if (postureGroup) return { label: 'BENIGN', reason: 'posture_group:' + postureGroup };

  const benignGroup = groups.find((group) => BENIGN_GROUPS.has(group));
  if (benignGroup && input.rule_level < 7) {
    return { label: 'BENIGN', reason: 'operational_group:' + benignGroup };
  }

  if (input.rule_level <= 3) return { label: 'BENIGN', reason: 'low_severity_no_attack_signal' };

  return { label: 'UNKNOWN', reason: 'no_policy_match' };
}

function classifyTaxonomy(input: {
  rule_groups: string[];
  mitre_tactics: string[];
  weak_label: WeakLabel;
}): TaxonomyLabel {
  const tactics = input.mitre_tactics.map((tactic) => tactic.toLowerCase());
  const groups = input.rule_groups.map((group) => group.toLowerCase());

  if (tactics.includes('credential access')) return 'CredentialAccess';
  if (tactics.includes('lateral movement')) return 'LateralMovement';
  if (groups.some((group) => group.includes('authentication') || group === 'invalid_login')) {
    return 'AuthenticationFailure';
  }
  if (groups.some((group) => group === 'systemd' || group === 'service_availability')) return 'ServiceFailure';
  if (groups.some((group) => BENIGN_GROUPS.has(group) || POSTURE_GROUPS.has(group))) return 'SystemAlert';
  return input.weak_label === 'ATTACK' ? 'CredentialAccess' : 'OtherAlert';
}

export function toDatasetRecord(hit: WazuhHit): DatasetRecord | null {
  const source = hit._source ?? {};
  const rule = (source.rule ?? {}) as Record<string, any>;
  const agent = (source.agent ?? {}) as Record<string, any>;
  const decoder = (source.decoder ?? {}) as Record<string, any>;
  const predecoder = (source.predecoder ?? {}) as Record<string, any>;
  const geo = (source.GeoLocation ?? {}) as Record<string, any>;
  const data = (source.data && typeof source.data === 'object' ? source.data : {}) as Record<string, any>;
  const mitre = (rule.mitre ?? {}) as Record<string, any>;

  const timestamp = text(source['@timestamp'] ?? source.timestamp);
  const window_start = floorToWindow(timestamp);
  if (!window_start) return null;

  const src_ip = text(data.srcip ?? data.src_ip ?? source.srcip ?? source.source?.ip);
  const src_port = text(data.srcport ?? data.src_port ?? source.source?.port);
  const geoPoint = readGeoPoint(geo.location);

  const base = {
    rule_groups: toList(rule.groups),
    mitre_tactics: toList(mitre.tactic ?? mitre.tactics),
    rule_level: toInt(rule.level),
    rule_description: text(rule.description),
  };

  const { label, reason } = classifyWeakLabel(base);

  return {
    alert_id: text(hit._id),
    timestamp,
    window_start,
    rule_id: text(rule.id, 'Unknown'),
    rule_level: base.rule_level,
    rule_description: base.rule_description,
    rule_firedtimes: toInt(rule.firedtimes, 1),
    rule_groups: base.rule_groups,
    mitre_tactics: base.mitre_tactics,
    mitre_techniques: toList(mitre.technique),
    agent_id: text(agent.id, 'Unknown'),
    agent_name: text(agent.name, 'Unknown'),
    agent_ip: text(agent.ip),
    src_ip,
    src_port,
    src_user: text(data.srcuser ?? data.username ?? source.user?.name),
    dst_user: text(data.dstuser),
    dst_port: text(data.dstport ?? data.dst_port ?? source.destination?.port),
    decoder_name: text(decoder.name, 'Unknown'),
    program_name: text(predecoder.program_name),
    location: text(source.location, 'Unknown'),
    full_log: text(source.full_log),
    geo_country: text(geo.country_name ?? geo.country_code2),
    geo_city: text(geo.city_name),
    geo_lat: geoPoint.lat,
    geo_lon: geoPoint.lon,
    has_src_ip: src_ip ? 1 : 0,
    has_src_port: src_port ? 1 : 0,
    is_simulated: source.argos?.localSimulation || source.labels?.argos_local_simulation === 'true' ? 1 : 0,
    weak_label: label,
    weak_label_reason: reason,
    taxonomy_label: classifyTaxonomy({ ...base, weak_label: label }),
  };
}

function buildDatasetQuery(from: string, to: string, size: number, searchAfter?: unknown[]) {
  return {
    size,
    track_total_hits: false,
    _source: { includes: DATASET_SOURCE_FIELDS },
    sort: [{ '@timestamp': { order: 'asc', unmapped_type: 'date' } }, { _id: { order: 'asc' } }],
    ...(searchAfter ? { search_after: searchAfter } : {}),
    query: {
      range: {
        '@timestamp': { gte: from, lte: to },
      },
    },
  };
}

export type DatasetQueryOptions = {
  from: string;
  to: string;
  limit: number;
  batchSize?: number;
};

// Paged with search_after so a full 30-day export (>1M alerts here) never has to
// materialise in memory. Callers stream to the response or fold into counters.
export async function* streamDatasetRecords(options: DatasetQueryOptions): AsyncGenerator<DatasetRecord> {
  const batchSize = Math.min(Math.max(options.batchSize ?? 5000, 1), 10000);
  let emitted = 0;
  let searchAfter: unknown[] | undefined;

  while (emitted < options.limit) {
    const size = Math.min(batchSize, options.limit - emitted);
    const page = await wazuhIndexerSearch<WazuhSearchResponse>(
      buildDatasetQuery(options.from, options.to, size, searchAfter)
    );

    const hits = page.hits?.hits ?? [];
    if (hits.length === 0) return;

    for (const hit of hits) {
      const record = toDatasetRecord(hit);
      if (record) {
        yield record;
        emitted += 1;
      }
    }

    searchAfter = hits.at(-1)?.sort;
    if (!searchAfter || hits.length < size) return;
  }
}

export async function fetchDatasetRecords(options: DatasetQueryOptions): Promise<DatasetRecord[]> {
  const records: DatasetRecord[] = [];
  for await (const record of streamDatasetRecords(options)) records.push(record);
  return records;
}

// Folds records one at a time so the manifest can be built over a streamed export
// without ever holding the full result set.
export class DatasetStats {
  private records = 0;
  private labels: Record<WeakLabel, number> = { ATTACK: 0, BENIGN: 0, UNKNOWN: 0 };
  private reasons = new Map<string, number>();
  private taxonomy = new Map<string, number>();
  private agents = new Map<string, number>();
  private rules = new Map<string, { rule_id: string; rule_description: string; count: number }>();
  private windows = new Map<string, { attack: number; benign: number }>();
  private postureBenign = 0;

  add(record: DatasetRecord) {
    this.records += 1;
    this.labels[record.weak_label] += 1;
    bump(this.reasons, record.weak_label_reason);
    bump(this.taxonomy, record.taxonomy_label);
    bump(this.agents, record.agent_id);

    if (record.weak_label === 'BENIGN' && record.weak_label_reason.startsWith('posture_group:')) {
      this.postureBenign += 1;
    }

    const rule = this.rules.get(record.rule_id);
    if (rule) rule.count += 1;
    else
      this.rules.set(record.rule_id, {
        rule_id: record.rule_id,
        rule_description: record.rule_description,
        count: 1,
      });

    const windowKey = record.window_start + '|' + record.agent_id;
    const window = this.windows.get(windowKey) ?? { attack: 0, benign: 0 };
    if (record.weak_label === 'ATTACK') window.attack += 1;
    else if (record.weak_label === 'BENIGN') window.benign += 1;
    this.windows.set(windowKey, window);
  }

  private windowLabels(): Record<WeakLabel, number> {
    const distribution: Record<WeakLabel, number> = { ATTACK: 0, BENIGN: 0, UNKNOWN: 0 };
    for (const window of this.windows.values()) {
      if (window.attack === 0 && window.benign === 0) distribution.UNKNOWN += 1;
      else if (window.attack >= window.benign) distribution.ATTACK += 1;
      else distribution.BENIGN += 1;
    }
    return distribution;
  }

  manifest(range: { from: string; to: string }, generatedAt: string): DatasetManifest {
    const { ATTACK: attack, BENIGN: benign, UNKNOWN: unknown } = this.labels;
    const labelled = attack + benign;
    const rowRatio = labelled > 0 ? Math.min(attack, benign) / labelled : 0;

    const windowLabels = this.windowLabels();
    const windowLabelled = windowLabels.ATTACK + windowLabels.BENIGN;
    const windowRatio =
      windowLabelled > 0 ? Math.min(windowLabels.ATTACK, windowLabels.BENIGN) / windowLabelled : 0;

    const notes: string[] = [];
    if (this.records === 0) notes.push('No alerts in range: nothing to train on.');
    if (attack === 0 && this.records > 0) notes.push('No ATTACK rows under the weak-label policy.');
    if (benign === 0 && this.records > 0) {
      notes.push(
        'No BENIGN rows: a supervised binary classifier is not identifiable from this export alone. Use PU learning, one-class/anomaly detection, or add a benign source (wazuh-archives-*, a lower log_alert_level, or the ARGOS local benign simulator).'
      );
    }
    if (rowRatio > 0 && rowRatio < 0.05) {
      notes.push('Severe row-level class imbalance: minority class is ' + pct(rowRatio) + ' of labelled rows.');
    }
    if (unknown > this.records * 0.3) {
      notes.push('More than 30% of rows are UNKNOWN: treat them as the unlabelled set for PU learning, not as BENIGN.');
    }
    if (windowLabelled > 0 && windowRatio < 0.05) {
      notes.push(
        'The active model classifies 1min x agent_id windows, and at that granularity the minority class is only ' +
          pct(windowRatio) +
          ' (' +
          windowLabels.ATTACK +
          ' ATTACK vs ' +
          windowLabels.BENIGN +
          ' BENIGN windows). Row-level balance can look healthy while the training unit stays single-class, because bursty scanners collapse thousands of rows into a couple of windows.'
      );
    }
    if (benign > 0 && this.postureBenign / benign > 0.5) {
      notes.push(
        'Label-proxy risk: ' +
          pct(this.postureBenign / benign) +
          ' of BENIGN rows are posture findings (Trivy/SCA/syscheck). They are trivially separable from sshd/pam alerts by decoder and rule family, so a classifier can reach near-perfect scores by learning the alert source instead of the behaviour. Report metrics with and without posture_group rows.'
      );
    }

    return {
      dataset: 'ARGOS-LAB-ALERTS',
      generated_at: generatedAt,
      range,
      window_size: '1min',
      group_key: 'agent_id',
      record_count: this.records,
      window_count: this.windows.size,
      weak_label_policy:
        'lab_alerts_weak_label_v1 (rule.groups > rule.mitre.tactic > description regex > posture groups > operational groups > severity floor)',
      weak_label_distribution: { ATTACK: attack, BENIGN: benign, UNKNOWN: unknown },
      weak_label_reason_distribution: fromMap(this.reasons),
      taxonomy_distribution: fromMap(this.taxonomy),
      window_label_distribution: windowLabels,
      agent_distribution: fromMap(this.agents),
      top_rules: [...this.rules.values()].sort((a, b) => b.count - a.count).slice(0, 20),
      trainability: {
        supervised_binary_viable: windowLabels.ATTACK > 0 && windowLabels.BENIGN > 0 && windowRatio >= 0.05,
        minority_class_ratio: Number(rowRatio.toFixed(4)),
        window_minority_class_ratio: Number(windowRatio.toFixed(4)),
        notes,
      },
    };
  }
}

function bump(counts: Map<string, number>, key: string) {
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

function fromMap(counts: Map<string, number>): Record<string, number> {
  return Object.fromEntries([...counts.entries()].sort((a, b) => b[1] - a[1]));
}

function pct(ratio: number) {
  return (ratio * 100).toFixed(2) + '%';
}

export function buildDatasetManifest(
  records: DatasetRecord[],
  range: { from: string; to: string },
  generatedAt: string
): DatasetManifest {
  const stats = new DatasetStats();
  for (const record of records) stats.add(record);
  return stats.manifest(range, generatedAt);
}
