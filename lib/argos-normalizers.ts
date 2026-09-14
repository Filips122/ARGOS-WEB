import {
  agentHealth as mockAgentHealth,
  attackTypeStats as mockAttackTypeStats,
  attacks as mockAttacks,
  kpis as mockKpis,
  mitreStats as mockMitreStats,
  severityColors,
  severityStats as mockSeverityStats,
  timelineStats as mockTimelineStats,
  topCountries as mockTopCountries,
  type AgentHealthItem,
  type Attack,
  type SecondOpinionView,
  type Severity,
} from '@/lib/mock-data';
import type { CriminalIntelligenceStats } from '@/lib/abuseipdb';
import { extractCve, lookupCve, type VulnerabilityContext } from '@/lib/kev-epss';

type WazuhHit = {
  _id?: string;
  _source?: Record<string, any>;
};

type WazuhSearchResponse = {
  hits?: {
    total?: number | { value?: number };
    hits?: WazuhHit[];
  };
};

type WazuhAgentsResponse = {
  data?: {
    affected_items?: Array<Record<string, any>>;
    total_affected_items?: number;
  };
};

type RiskBucket = {
  label: string;
  min: number;
  max: number;
  count: number;
  tone: 'low' | 'medium' | 'high' | 'critical';
  scores: { score: number; count: number }[];
};

type SourceGeo = {
  name: string;
  country: string;
  city?: string;
  lat: number;
  lon: number;
};

const fallbackGeo = [
  { name: 'Unknown relay', country: 'UN', lat: 40.4168, lon: -3.7038 },
  { name: 'Europe relay', country: 'EU', lat: 48.8566, lon: 2.3522 },
  { name: 'Atlantic relay', country: 'US', lat: 40.7128, lon: -74.006 },
  { name: 'South America relay', country: 'BR', lat: -23.5558, lon: -46.6396 },
  { name: 'Asia relay', country: 'SG', lat: 1.3521, lon: 103.8198 },
];

const fallbackTargets = [
  { name: 'wazuh-agent', country: 'ES', lat: 40.4168, lon: -3.7038 },
  { name: 'dmz-web', country: 'ES', lat: 41.3874, lon: 2.1686 },
  { name: 'soc-sensor', country: 'ES', lat: 39.4699, lon: -0.3763 },
  { name: 'vpn-gateway', country: 'ES', lat: 37.3891, lon: -5.9845 },
];

function getTargetGeo(agentName: string) {
  if (agentName.toLowerCase().includes('tpot')) {
    return { name: 'tpot-honeypot', country: 'ES', lat: 37.9922, lon: -1.1307 };
  }

  return fallbackTargets[hashIndex(agentName, fallbackTargets.length)];
}

export type ArgosServiceStatus = {
  manager: 'online' | 'offline' | 'unknown';
  agents: 'online' | 'offline' | 'unknown';
  indexer: 'online' | 'offline' | 'unknown';
  mode: 'live' | 'partial' | 'demo';
};

export type ArgosLiveData = {
  ok: true;
  updatedAt: string;
  mode: 'live' | 'partial' | 'demo';
  serviceStatus: ArgosServiceStatus;
  manager: unknown;
  agents: unknown[];
  attacks: Attack[];
  kpis: typeof mockKpis;
  agentHealth: AgentHealthItem[];
  summary: {
    events24h: number;
    alertsLast30d: number;
    loadedAlertsLast30d: number;
  };
  charts: {
    attacksByType: typeof mockAttackTypeStats;
    severityDistribution: typeof mockSeverityStats;
    alertsTimeline: typeof mockTimelineStats;
    topCountries: typeof mockTopCountries;
    mitreTactics: typeof mockMitreStats;
    riskDistribution: RiskBucket[];
    correlationSources: { label: string; value: number }[];
    criminalIntelligence?: CriminalIntelligenceStats;
    vulnerabilityIntelligence: VulnerabilityIntelligence;
  };
  errors: {
    manager: string | null;
    agents: string | null;
    alerts: string | null;
  };
};

export type VulnerabilityIntelligence = {
  /** false cuando no se pudo cargar el indice KEV/EPSS (sin red, por ejemplo). */
  available: boolean;
  kevVersion: string | null;
  alertsWithCve: number;
  distinctCves: number;
  exploitedCves: number;
  actionableCves: number;
  alertsOnExploited: number;
  noiseReductionFactor: number;
  /** El contraste que da sentido al panel: cuantas CRITICAL son inventario. */
  contrast: {
    criticalAlerts: number;
    criticalFromVulnScan: number;
    criticalActuallyExploited: number;
  };
  topExploited: { cve: string; epss: number | null; inKev: boolean; alerts: number }[];
  severityVsExploitation: { label: string; value: number }[];
};

function buildVulnerabilityIntelligence(
  attacks: Attack[],
  kevVersion: string | null,
  available: boolean
): VulnerabilityIntelligence {
  const perCve = new Map<string, { alerts: number; inKev: boolean; epss: number | null; actionable: boolean }>();
  let alertsWithCve = 0;
  let criticalAlerts = 0;
  let criticalFromVulnScan = 0;
  let criticalActuallyExploited = 0;

  for (const attack of attacks) {
    const vuln = attack.vulnerability;
    if (attack.severity === 'critical') criticalAlerts += 1;
    if (!vuln) continue;

    alertsWithCve += 1;
    if (attack.severity === 'critical') {
      criticalFromVulnScan += 1;
      if (vuln.actionable) criticalActuallyExploited += 1;
    }

    const entry = perCve.get(vuln.cve);
    if (entry) entry.alerts += 1;
    else perCve.set(vuln.cve, { alerts: 1, inKev: vuln.inKev, epss: vuln.epss, actionable: vuln.actionable });
  }

  const rows = [...perCve.entries()];
  const exploited = rows.filter(([, v]) => v.inKev);
  const actionable = rows.filter(([, v]) => v.actionable);

  return {
    available,
    kevVersion,
    alertsWithCve,
    distinctCves: rows.length,
    exploitedCves: exploited.length,
    actionableCves: actionable.length,
    alertsOnExploited: exploited.reduce((sum, [, v]) => sum + v.alerts, 0),
    noiseReductionFactor: actionable.length > 0 ? Math.round(rows.length / actionable.length) : 0,
    contrast: { criticalAlerts, criticalFromVulnScan, criticalActuallyExploited },
    topExploited: actionable
      .sort((a, b) => (b[1].epss ?? 0) - (a[1].epss ?? 0))
      .slice(0, 6)
      .map(([cve, v]) => ({ cve, epss: v.epss, inKev: v.inKev, alerts: v.alerts })),
    severityVsExploitation: [
      { label: 'Explotados (KEV)', value: exploited.length },
      { label: 'Probables (EPSS>=0,1)', value: actionable.length - exploited.length },
      { label: 'Sin explotacion conocida', value: rows.length - actionable.length },
    ],
  };
}

export function mapWazuhLevelToSeverity(level?: number): Severity {
  if (level === undefined || Number.isNaN(level)) return 'low';
  if (level >= 12) return 'critical';
  if (level >= 9) return 'high';
  if (level >= 6) return 'medium';
  return 'low';
}

export function estimateAiScoreFromWazuhLevel(level?: number): number {
  if (level === undefined || Number.isNaN(level)) return 20;
  return Math.min(100, Math.max(5, Math.round(level * 7.5)));
}

export function inferAttackType(description?: string): string {
  const text = description?.toLowerCase() ?? '';

  if (text.includes('brute') || text.includes('authentication failure') || text.includes('multiple failed')) {
    return 'SSH brute force';
  }

  if (text.includes('scan') || text.includes('nmap')) {
    return 'Port scan';
  }

  if (text.includes('sql')) {
    return 'SQLi probe';
  }

  if (text.includes('malware') || text.includes('trojan') || text.includes('virus')) {
    return 'Malware callback';
  }

  if (text.includes('privilege') || text.includes('sudo')) {
    return 'Privilege escalation';
  }

  if (text.includes('authentication') || text.includes('login') || text.includes('credential')) {
    return 'Suspicious auth burst';
  }

  return 'Suspicious activity';
}

function inferMitreTactic(source: Record<string, any>, attackType: string): string {
  const tactic = source.rule?.mitre?.tactic?.[0] ?? source.rule?.mitre?.tactics?.[0];
  if (typeof tactic === 'string') return tactic;
  if (attackType.toLowerCase().includes('brute') || attackType.toLowerCase().includes('auth')) return 'Credential Access';
  if (attackType.toLowerCase().includes('scan')) return 'Discovery';
  if (attackType.toLowerCase().includes('malware')) return 'Command and Control';
  return 'Initial Access';
}

function pickString(...values: unknown[]): string | undefined {
  return values.find((value): value is string => typeof value === 'string' && value.length > 0);
}

function readNumber(value: unknown): number | undefined {
  const numeric = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(numeric) ? numeric : undefined;
}

/**
 * Traduce la anotacion del sidecar a la forma que consume la interfaz.
 *
 * Se conserva el caso "no disponible" con su motivo en vez de devolver
 * undefined: el primer aviso no tiene segunda opinion por diseno del paquete
 * (K=1 excluido), y la pantalla debe decirlo, no mostrar un cero ni callarlo.
 */
function normalizeSecondOpinion(raw: unknown): SecondOpinionView | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const value = raw as Record<string, unknown>;
  if (value.available !== true) {
    const reason = value.reason === 'out_of_budget' ? 'out_of_budget' : 'first_notice';
    return { available: false, reason };
  }
  const agreements = ['both', 'hgb_only', 'attention_only', 'none'] as const;
  const agreement = agreements.find((item) => item === value.agreement) ?? 'none';
  return {
    available: true,
    score: readNumber(value.score) ?? 0,
    threshold: readNumber(value.threshold) ?? 0,
    fired: Boolean(value.fired),
    agreement,
    atAlert: readNumber(value.at_alert) ?? 0,
    decisiveNotices: Array.isArray(value.avisos_decisivos)
      ? value.avisos_decisivos.map((item) => readNumber(item) ?? 0)
      : [],
    attentionPerNotice: Array.isArray(value.atencion_por_aviso)
      ? value.atencion_por_aviso.map((item) => readNumber(item) ?? 0)
      : [],
  };
}

function readGeoLocation(value: unknown): { lat: number; lon: number } | undefined {
  if (Array.isArray(value)) {
    const [lon, lat] = value;
    const parsedLat = readNumber(lat);
    const parsedLon = readNumber(lon);
    return parsedLat !== undefined && parsedLon !== undefined ? { lat: parsedLat, lon: parsedLon } : undefined;
  }

  if (value && typeof value === 'object') {
    const location = value as Record<string, unknown>;
    const lat = readNumber(location.lat);
    const lon = readNumber(location.lon ?? location.lng);
    return lat !== undefined && lon !== undefined ? { lat, lon } : undefined;
  }

  if (typeof value === 'string') {
    const [latText, lonText] = value.split(',').map((part) => part.trim());
    const lat = readNumber(latText);
    const lon = readNumber(lonText);
    return lat !== undefined && lon !== undefined ? { lat, lon } : undefined;
  }

  return undefined;
}

/** Devuelve tambien si las coordenadas son reales o de la lista de reserva. */
function getSourceGeo(source: Record<string, any>, fallback: (typeof fallbackGeo)[number]): SourceGeo {
  const geoLocation = source.GeoLocation ?? source.geoip ?? source.source?.geo ?? source.client?.geo ?? source.data?.geoip;
  const coordinates = readGeoLocation(geoLocation?.location);
  const country = pickString(
    geoLocation?.country_name,
    geoLocation?.country_code2,
    geoLocation?.country_iso_code
  );
  const city = pickString(geoLocation?.city_name);

  if (!coordinates && !country && !city) return fallback;

  const locationName = city ?? country ?? fallback.name;

  return {
    name: locationName,
    country: country ?? fallback.country,
    city,
    lat: coordinates?.lat ?? fallback.lat,
    lon: coordinates?.lon ?? fallback.lon,
  };
}

function hashIndex(value: string, modulo: number) {
  const sum = value.split('').reduce((total, char) => total + char.charCodeAt(0), 0);
  return sum % modulo;
}

function getAlertHits(alerts: unknown): WazuhHit[] {
  const response = alerts as WazuhSearchResponse | null;
  return response?.hits?.hits ?? [];
}

function getTotalAlerts(alerts: unknown, fallback: number) {
  const total = (alerts as WazuhSearchResponse | null)?.hits?.total;
  if (typeof total === 'number') return total;
  if (typeof total?.value === 'number') return total.value;
  return fallback;
}

function normalizeAgents(agents: unknown): Record<string, any>[] {
  return ((agents as WazuhAgentsResponse | null)?.data?.affected_items ?? []) as Record<string, any>[];
}

export function normalizeWazuhAlerts(
  alerts: unknown,
  agents: unknown,
  vulnIndex: Parameters<typeof lookupCve>[0] = null
): Attack[] {
  const hits = getAlertHits(alerts);
  const agentItems = normalizeAgents(agents);

  return hits.map((hit, index) => {
    const source = hit._source ?? {};
    const level = readNumber(source.rule?.level);
    const severity = mapWazuhLevelToSeverity(level);
    const ai = source.ml?.argos;
    const aiRiskScore = readNumber(ai?.risk_score);
    const isLocalSimulation = source.argos?.localSimulation === true || source.labels?.argos_local_simulation === 'true';
    const simulationKind = pickString(source.argos?.simulationKind, source.labels?.argos_simulation_kind);
    const simulationScenario = pickString(source.argos?.scenario, source.labels?.argos_simulation_scenario);
    const description = pickString(source.rule?.description, source.title, source.full_log) ?? 'Wazuh alert';
    const simulationLabel = simulationKind === 'benign' ? 'benigna' : simulationKind ?? 'local';
    const attackType = isLocalSimulation
      ? `Simulacion ${simulationLabel}${simulationScenario ? ` - ${simulationScenario}` : ''}`
      : inferAttackType(description);
    const sourceIp = pickString(
      source.data?.srcip,
      source.data?.src_ip,
      source.srcip,
      source.source?.ip,
      source.client?.ip,
      source.remote_ip
    );
    const agentName = pickString(source.agent?.name, source.agent?.id, agentItems[index % Math.max(agentItems.length, 1)]?.name) ?? 'unknown-agent';
    const fallbackSrcGeo = fallbackGeo[hashIndex(sourceIp ?? hit._id ?? `${index}`, fallbackGeo.length)];
    const srcGeo = getSourceGeo(source, fallbackSrcGeo);
    const targetGeo = getTargetGeo(agentName);
    const timestamp = pickString(source['@timestamp'], source.timestamp) ?? new Date().toISOString();

    return {
      id: hit._id ?? `WAZUH-${index + 1}`,
      zone: srcGeo.city ?? srcGeo.country ?? srcGeo.name.replace(' relay', ''),
      source: {
        ...srcGeo,
        ip: sourceIp ?? 'unknown',
      },
      target: {
        ...targetGeo,
        name: agentName,
        ip: pickString(source.agent?.ip, source.host?.ip),
      },
      // El globo dibuja igual las coordenadas reales y las de reserva; sin esta
      // marca no habia forma de distinguir un origen geolocalizado de uno
      // colocado por hash de la IP.
      geoApproximate: !readGeoLocation(
        (source.GeoLocation ?? source.geoip ?? source.source?.geo ?? source.client?.geo ?? source.data?.geoip)?.location
      ),
      type: attackType,
      tactic: inferMitreTactic(source, attackType),
      severity,
      score: aiRiskScore ?? estimateAiScoreFromWazuhLevel(level),
      agent: agentName,
      wazuhRule: pickString(source.rule?.id) ?? 'N/A',
      suricataSid: pickString(source.rule?.sid, source.data?.sid) ?? 'N/A',
      mcpTool: isLocalSimulation ? 'argos.local-simulator' : attackType.toLowerCase().includes('auth') || attackType.toLowerCase().includes('brute') ? 'auth.window' : 'wazuh.triage',
      sensorSources: ['Wazuh', 'AI Engine'],
      timestamp: formatRelativeTimestamp(timestamp),
      receivedAt: timestamp,
      vulnerability: lookupCve(vulnIndex, extractCve(description)) ?? undefined,
      ipRisk: source.ml?.ip_risk && typeof source.ml.ip_risk === 'object' ? {
        score: readNumber(source.ml.ip_risk.score) ?? 0,
        blocked: Boolean(source.ml.ip_risk.blocked),
        decidedAtAlert: readNumber(source.ml.ip_risk.decided_at_alert) ?? null,
        alertsSeen: readNumber(source.ml.ip_risk.alerts_seen) ?? 0,
        evidenceKind: source.ml.ip_risk.evidence_kind ?? 'volumen',
        usersTried: readNumber(source.ml.ip_risk.evidence?.usuarios_probados) ?? 0,
        agentsReached: readNumber(source.ml.ip_risk.evidence?.maquinas_alcanzadas) ?? 0,
        subnetHostileRatio: readNumber(source.ml.ip_risk.evidence?.reputacion_subred_24) ?? 0,
        // Segunda opinion del Transformer. Anotacion: no cambia `blocked` ni
        // `decidedAtAlert`, que siguen siendo los del HGB. Cuando no esta
        // disponible se conserva el motivo para poder decirlo en pantalla en
        // vez de mostrar un 0 o callarlo.
        secondOpinion: normalizeSecondOpinion(source.ml.ip_risk.second_opinion),
      } : undefined,
      ai: ai && typeof ai === 'object' ? {
        modelId: pickString(ai.model_id) ?? 'argos-ai',
        modelVersion: pickString(ai.model_version),
        score: readNumber(ai.score) ?? ((aiRiskScore ?? estimateAiScoreFromWazuhLevel(level)) / 100),
        threshold: readNumber(ai.threshold) ?? 0,
        prediction: pickString(ai.prediction) === 'benign' ? 'benign' : 'attack',
        confidence: readNumber(ai.confidence) ?? 0,
        source: pickString(ai.source) === 'fallback' ? 'fallback' : 'model',
        taxonomy: ai.taxonomy && typeof ai.taxonomy === 'object' ? {
          modelId: pickString(ai.taxonomy.model_id) ?? 'cowrie-taxonomy',
          label: pickString(ai.taxonomy.label) ?? 'unknown',
          confidence: readNumber(ai.taxonomy.confidence) ?? 0,
        } : undefined,
        csrLanl: ai.csr_lanl && typeof ai.csr_lanl === 'object' ? {
          supervisedScore: readNumber(ai.csr_lanl.supervised_score) ?? 0,
          entityAnomalyScore: readNumber(ai.csr_lanl.entity_anomaly_score) ?? 0,
          contextNoveltyScore: readNumber(ai.csr_lanl.context_novelty_score) ?? 0,
          classification: pickString(ai.csr_lanl.classification) === 'high_risk_entity'
            ? 'high_risk_entity'
            : pickString(ai.csr_lanl.classification) === 'suspicious_entity'
              ? 'suspicious_entity'
              : 'low_signal',
          entity: pickString(ai.csr_lanl.entity) ?? 'unknown',
          windowStart: pickString(ai.csr_lanl.window_start),
          windowEnd: pickString(ai.csr_lanl.window_end),
          model: pickString(ai.csr_lanl.model) ?? 'csr_lanl_identity_hgb',
          auxiliaryModel: pickString(ai.csr_lanl.auxiliary_model) ?? 'csr_lanl_identity_isoforest',
          source: pickString(ai.csr_lanl.source) ?? 'wazuh_sparse_adapter',
          warning: pickString(ai.csr_lanl.warning),
        } : undefined,
      } : undefined,
    };
  });
}

function formatRelativeTimestamp(timestamp: string) {
  const date = new Date(timestamp);
  const diffMs = Date.now() - date.getTime();

  if (!Number.isFinite(diffMs) || diffMs < 0) return timestamp;
  const diffSeconds = Math.floor(diffMs / 1000);
  if (diffSeconds < 60) return `hace ${diffSeconds}s`;
  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) return `hace ${diffMinutes}m`;
  const diffHours = Math.floor(diffMinutes / 60);
  return `hace ${diffHours}h`;
}

function countBy<T extends string>(items: T[]) {
  return items.reduce((counts, item) => {
    counts.set(item, (counts.get(item) ?? 0) + 1);
    return counts;
  }, new Map<T, number>());
}

function toChartRows(map: Map<string, number>, fallback: { label: string; value: number }[], limit = 6) {
  const rows = Array.from(map, ([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
  return rows.length > 0 ? rows : fallback;
}

function buildSeverityStats(attacks: Attack[]) {
  const counts = countBy(attacks.map((attack) => attack.severity));
  return (['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) => ({
    label: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: counts.get(severity) ?? 0,
    color: severityColors[severity],
  }));
}

function buildEmptySeverityStats() {
  return (['critical', 'high', 'medium', 'low'] as Severity[]).map((severity) => ({
    label: severity.charAt(0).toUpperCase() + severity.slice(1),
    value: 0,
    color: severityColors[severity],
  }));
}

function buildEmptyTimeline() {
  return ['00h', '03h', '06h', '09h', '12h', '15h', '18h', '21h'].map((label) => ({
    label,
    alerts: 0,
    ai: 0,
    ips: 0,
  }));
}

/**
 * Reparte las alertas por su HORA REAL, en tramos de tres horas.
 *
 * Antes agrupaba por la posicion en la lista (`index % 8`), lo que producia
 * ocho barras casi identicas que no tenian nada que ver con la hora: era una
 * grafica con forma de distribucion horaria que no lo era.
 */
function buildTimeline(attacks: Attack[]) {
  if (attacks.length === 0) return mockTimelineStats;

  const buckets = Array.from({ length: 8 }, (_, index) => ({
    label: `${String(index * 3).padStart(2, '0')}h`,
    alerts: 0,
    ai: 0,
    ips: 0,
  }));
  const ipsPorTramo = Array.from({ length: 8 }, () => new Set<string>());

  let placed = 0;
  for (const attack of attacks) {
    const moment = attack.receivedAt ? new Date(attack.receivedAt) : null;
    if (!moment || Number.isNaN(moment.getTime())) continue;
    const index = Math.floor(moment.getHours() / 3);
    const bucket = buckets[index];
    bucket.alerts += 1;
    // `ai` conserva el nombre por compatibilidad con el tipo, pero ya NO cuenta
    // el score de ventana: contaba las alertas con score >= 70 y eso era el
    // 100 % de ellas, asi que las dos series salian identicas y la grafica no
    // decia nada. Ahora cuenta las alertas cuya IP tiene riesgo >= 0,9, que si
    // varia entre tramos (medido: del 53 % al 91 %) y separa un pico de volumen
    // de un pico de peligro.
    if ((attack.ipRisk?.score ?? 0) >= 0.9) bucket.ai += 1;
    if (attack.source.ip) ipsPorTramo[index].add(attack.source.ip);
    placed += 1;
  }

  for (const [index, bucket] of buckets.entries()) bucket.ips = ipsPorTramo[index].size;

  // Sin marcas de tiempo utilizables no hay distribucion horaria que enseñar.
  return placed === 0 ? buildEmptyTimeline() : buckets;
}

function buildKpis(
  attacks: Attack[],
  agents: Record<string, any>[],
  totalEvents24h: number,
  totalAlerts30d: number,
  loadedAlerts30d: number
) {
  if (attacks.length === 0 && agents.length === 0) return mockKpis;
  const critical = attacks.filter((attack) => attack.severity === 'critical').length;
  const activeAgents = agents.filter((agent) => agent.status === 'active').length;
  const disconnectedAgents = agents.filter((agent) => agent.status !== 'active').length;
  const { mean: meanScore } = meanIpScore(attacks);
  // Por DIRECCION, no por alerta: hay unas decenas de IPs generando miles de
  // alertas, asi que contar alertas aqui daria un numero enorme bajo una
  // etiqueta que dice "IPs". Seria la misma clase de metrica enganyosa que el
  // panel ha ido retirando.
  const ips = new Map<string, number>();
  for (const attack of attacks) {
    const score = ipScore(attack);
    if (attack.source.ip && score !== null) ips.set(attack.source.ip, score);
  }
  const highRisk = [...ips.values()].filter((score) => score >= 90).length;

  return [
    { label: 'Eventos 24h', value: totalEvents24h.toLocaleString('es-ES'), trend: 'Wazuh', tone: 'info' },
    { label: 'Alertas correladas', value: totalAlerts30d.toLocaleString('es-ES'), trend: `${loadedAlerts30d.toLocaleString('es-ES')} cargadas`, tone: 'info' },
    // Contaba alertas con score de ventana >= 70, que lo cruzaba el 100 % de
    // ellas: el KPI no filtraba nada. Ahora cuenta las de IPs con riesgo >= 90.
    { label: 'IPs de riesgo alto', value: highRisk.toLocaleString('es-ES'), trend: `de ${ips.size.toLocaleString('es-ES')} direcciones`, tone: 'ai' },
    { label: 'Criticas', value: critical.toString(), trend: critical > 0 ? 'prioridad' : 'estable', tone: 'critical' },
    { label: 'Agentes activos', value: activeAgents.toString(), trend: `${disconnectedAgents} off`, tone: activeAgents > 0 ? 'ok' : 'high' },
    { label: 'Riesgo IP medio', value: meanScore.toString(), trend: meanScore >= 80 ? 'high' : 'guarded', tone: meanScore >= 80 ? 'high' : 'info' },
  ];
}

/**
 * Puntuacion por alerta que se usa en KPIs, medias y reparto de riesgo: la del
 * RIESGO DE LA IP, no la del modelo de ventana.
 *
 * El de ventana puntua un minuto de un agente y reparte el mismo numero entre
 * todas las alertas de dentro; medido, satura: 13 valores distintos sobre
 * 10.001 alertas, el 96,8 % exactamente 100, media 99,6. Promediarlo daba un
 * numero que no describia a ninguna alerta.
 *
 * El de IP puntua la conducta de la direccion: 49 valores distintos y media
 * 91,4 sobre la misma muestra. Solo existe donde hay IP de origen (medido:
 * 98,0 % de las alertas); el resto se EXCLUYE del promedio en vez de contar
 * como cero, que hundiria la media con alertas que no tienen a quien puntuar.
 */
function ipScore(attack: Attack): number | null {
  return attack.ipRisk ? Math.round(attack.ipRisk.score * 100) : null;
}

function meanIpScore(attacks: Attack[]): { mean: number; scored: number } {
  const scores = attacks.map(ipScore).filter((value): value is number => value !== null);
  if (scores.length === 0) return { mean: 0, scored: 0 };
  return {
    mean: Math.round(scores.reduce((sum, value) => sum + value, 0) / scores.length),
    scored: scores.length,
  };
}

function getRiskTone(max: number): RiskBucket['tone'] {
  if (max > 87.5) return 'critical';
  if (max > 75) return 'high';
  if (max > 50) return 'medium';
  return 'low';
}

function buildRiskDistribution(attacks: Attack[]): RiskBucket[] {
  const ranges = Array.from({ length: 8 }, (_, index) => {
    const min = index * 12.5;
    const max = min + 12.5;
    return { min, max };
  });

  return ranges.map(({ min, max }, index) => {
    // Reparto del riesgo de IP. Con el score de ventana este histograma tenia
    // forma de U (todo en el primer y el ultimo tramo) porque el modelo decide
    // si o no, no "cuanto".
    const inRange = attacks.filter((attack) => {
      const score = ipScore(attack);
      if (score === null) return false;
      const isLastRange = index === ranges.length - 1;
      return score >= min && (isLastRange ? score <= max : score < max);
    });
    const scoreCounts = Array.from(
      inRange.reduce((counts, attack) => {
        const score = ipScore(attack) as number;
        counts.set(score, (counts.get(score) ?? 0) + 1);
        return counts;
      }, new Map<number, number>()),
      ([score, count]) => ({ score, count })
    ).sort((a, b) => a.score - b.score);

    return {
      label: `${min}-${max}`,
      min,
      max,
      count: inRange.length,
      tone: getRiskTone(max),
      scores: scoreCounts,
    };
  });
}

function buildAgentHealth(manager: unknown, agents: Record<string, any>[], errors: ArgosLiveData['errors']) {
  const activeAgents = agents.filter((agent) => agent.status === 'active').length;
  const disconnectedAgents = agents.filter((agent) => agent.status !== 'active').length;

  return [
    {
      name: 'Wazuh Manager',
      status: errors.manager ? 'offline' : manager ? 'online' : 'learning',
      metric: errors.manager ? 'sin conexion' : 'manager API',
    },
    {
      name: 'Wazuh Agents',
      status: errors.agents ? 'offline' : activeAgents > 0 ? 'online' : 'learning',
      metric: `${activeAgents} activos · ${disconnectedAgents} desconectados`,
    },
    ...mockAgentHealth.slice(1),
  ];
}

function buildLiveAgentHealth(
  manager: unknown,
  agents: Record<string, any>[],
  errors: ArgosLiveData['errors'],
  attacks: Attack[],
  totalEvents24h: number
): AgentHealthItem[] {
  const activeAgents = agents.filter((agent) => agent.status === 'active').length;
  const disconnectedAgents = agents.filter((agent) => agent.status !== 'active').length;
  // Solo las que traen coordenadas de verdad. Las de reserva tambien tienen
  // lat/lon finitas, asi que contarlas inflaba esta cifra al total.
  const geoLocatedAttacks = attacks.filter(
    (attack) => !attack.geoApproximate && Number.isFinite(attack.source.lat) && Number.isFinite(attack.source.lon)
  ).length;
  const approximateGeo = attacks.filter((attack) => attack.geoApproximate).length;
  const flowsPerMinute = Math.round(totalEvents24h / (24 * 60));
  const { mean: meanScore } = meanIpScore(attacks);

  return [
    {
      name: 'Wazuh Manager',
      status: errors.manager ? 'offline' : manager ? 'online' : 'learning',
      metric: errors.manager ? 'sin conexion' : 'manager API',
    },
    {
      name: 'Wazuh Agents',
      status: errors.agents ? 'offline' : activeAgents > 0 ? 'online' : 'learning',
      metric: `${activeAgents} activos - ${disconnectedAgents} desconectados`,
    },
    {
      name: 'Wazuh Indexer',
      status: errors.alerts ? 'offline' : attacks.length > 0 ? 'online' : 'learning',
      metric: errors.alerts ? 'sin alertas live' : `${attacks.length.toLocaleString('es-ES')} alertas cargadas`,
    },
    {
      name: 'GeoIP Enrichment',
      status: geoLocatedAttacks > 0 ? 'online' : 'learning',
      metric: approximateGeo > 0
        ? `${geoLocatedAttacks.toLocaleString('es-ES')} reales · ${approximateGeo.toLocaleString('es-ES')} aprox.`
        : `${geoLocatedAttacks.toLocaleString('es-ES')} origenes geolocalizados`,
    },
    {
      name: 'Risk Scoring',
      status: attacks.length > 0 ? 'online' : 'learning',
      metric: attacks.some((attack) => attack.ai?.source === 'model') ? `modelo IA activo - media ${meanScore}` : `score medio ${meanScore}`,
    },
    {
      name: 'Flow Average',
      status: totalEvents24h > 0 ? 'online' : 'learning',
      metric: `${flowsPerMinute.toLocaleString('es-ES')} flows/min media`,
    },
  ];
}

export function buildArgosLiveData(input: {
  manager: unknown;
  agents: unknown;
  alerts: unknown;
  events24h?: unknown;
  errors: ArgosLiveData['errors'];
  vulnIndex?: Parameters<typeof lookupCve>[0];
  kevVersion?: string | null;
}): ArgosLiveData {
  const agentItems = normalizeAgents(input.agents);
  const normalizedAttacks = normalizeWazuhAlerts(input.alerts, input.agents, input.vulnIndex ?? null);
  const hasLiveContext = Boolean(input.manager || input.agents || input.events24h);
  const shouldUseMock = normalizedAttacks.length === 0 && (Boolean(input.errors.alerts) || !hasLiveContext);
  const attacks = normalizedAttacks.length > 0 ? normalizedAttacks : shouldUseMock ? mockAttacks : [];
  const totalAlerts30d = getTotalAlerts(input.alerts, normalizedAttacks.length);
  const totalEvents24h = getTotalAlerts(input.events24h, normalizedAttacks.length);
  const livePieces = [input.manager, input.agents, input.alerts].filter(Boolean).length;
  const mode = livePieces === 3 ? 'live' : livePieces > 0 ? 'partial' : 'demo';

  return {
    ok: true,
    updatedAt: new Date().toISOString(),
    mode,
    serviceStatus: {
      manager: input.errors.manager ? 'offline' : input.manager ? 'online' : 'unknown',
      agents: input.errors.agents ? 'offline' : input.agents ? 'online' : 'unknown',
      indexer: input.errors.alerts ? 'offline' : input.alerts ? 'online' : 'unknown',
      mode,
    },
    manager: input.manager,
    agents: agentItems,
    attacks,
    kpis: shouldUseMock
      ? mockKpis
      : hasLiveContext
      ? buildKpis(normalizedAttacks, agentItems, totalEvents24h, totalAlerts30d, normalizedAttacks.length)
      : mockKpis,
    agentHealth: buildLiveAgentHealth(input.manager, agentItems, input.errors, normalizedAttacks, totalEvents24h),
    summary: {
      events24h: totalEvents24h,
      alertsLast30d: totalAlerts30d,
      loadedAlertsLast30d: normalizedAttacks.length,
    },
    charts: {
      attacksByType: hasLiveContext && attacks.length === 0 ? [] : toChartRows(countBy(attacks.map((attack) => attack.type)), mockAttackTypeStats),
      severityDistribution: shouldUseMock ? mockSeverityStats : normalizedAttacks.length > 0 ? buildSeverityStats(attacks) : hasLiveContext ? buildEmptySeverityStats() : mockSeverityStats,
      alertsTimeline: shouldUseMock ? mockTimelineStats : normalizedAttacks.length > 0 ? buildTimeline(attacks) : hasLiveContext ? buildEmptyTimeline() : mockTimelineStats,
      topCountries: hasLiveContext && attacks.length === 0 ? [] : toChartRows(countBy(attacks.map((attack) => attack.source.country)), mockTopCountries, 5),
      mitreTactics: hasLiveContext && attacks.length === 0 ? [] : toChartRows(countBy(attacks.map((attack) => attack.tactic)), mockMitreStats, 6),
      riskDistribution: buildRiskDistribution(attacks),
      vulnerabilityIntelligence: buildVulnerabilityIntelligence(
        attacks,
        input.kevVersion ?? null,
        Boolean(input.vulnIndex)
      ),
      // Enriquecimientos que de verdad se aplican. Antes listaba Suricata y
      // Zeek, que no estan integrados, asi que esas dos filas valian siempre 0.
      correlationSources: [
        { label: 'Modelo de ventana', value: attacks.filter((attack) => attack.ai?.source === 'model').length },
        { label: 'Riesgo por IP', value: attacks.filter((attack) => attack.ipRisk).length },
        // 'cached' cuenta igual que 'checked': la alerta lleva reputacion real,
        // solo que servida desde el disco. Contar solo 'checked' hacia que la
        // fila marcase 0 con 4.447 alertas efectivamente enriquecidas.
        {
          label: 'Reputacion AbuseIPDB',
          value: attacks.filter(
            (attack) => attack.abuseipdb?.status === 'checked' || attack.abuseipdb?.status === 'cached'
          ).length,
        },
        { label: 'Explotacion real (CVE)', value: attacks.filter((attack) => attack.vulnerability).length },
      ],
    },
    errors: input.errors,
  };
}
