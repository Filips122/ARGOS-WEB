export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type SensorSource = 'Wazuh' | 'Suricata' | 'Zeek' | 'MCP' | 'AI Engine';

export type GeoPoint = {
  name: string;
  country: string;
  ip?: string;
  lat: number;
  lon: number;
};

export type Attack = {
  id: string;
  zone: string;
  source: GeoPoint;
  target: GeoPoint;
  type: string;
  tactic: string;
  severity: Severity;
  score: number;
  agent: string;
  wazuhRule: string;
  suricataSid: string;
  mcpTool: string;
  sensorSources: SensorSource[];
  timestamp: string;
  receivedAt?: string;
};

export const severityColors: Record<Severity, string> = {
  low: '#38f8d4',
  medium: '#ffd166',
  high: '#ff8a3d',
  critical: '#ff2f5f',
};

export const attacks: Attack[] = [
  {
    id: 'ARG-1001',
    zone: 'Europa Occidental',
    source: { name: 'Paris edge', country: 'FR', ip: '45.155.91.22', lat: 48.8566, lon: 2.3522 },
    target: { name: 'dmz-web-01', country: 'ES', lat: 40.4168, lon: -3.7038 },
    type: 'SSH brute force',
    tactic: 'Credential Access',
    severity: 'high',
    score: 88,
    agent: 'wazuh-agent-web01',
    wazuhRule: '5710',
    suricataSid: '2024364',
    mcpTool: 'triage.ssh',
    sensorSources: ['Wazuh', 'Suricata', 'MCP', 'AI Engine'],
    timestamp: 'hace 21s',
  },
  {
    id: 'ARG-1002',
    zone: 'Europa Oriental',
    source: { name: 'Kyiv relay', country: 'UA', ip: '91.240.118.41', lat: 50.4501, lon: 30.5234 },
    target: { name: 'vpn-gateway', country: 'ES', lat: 41.3874, lon: 2.1686 },
    type: 'Credential stuffing',
    tactic: 'Initial Access',
    severity: 'critical',
    score: 96,
    agent: 'wazuh-agent-vpn01',
    wazuhRule: '5503',
    suricataSid: '2031042',
    mcpTool: 'identity.risk',
    sensorSources: ['Wazuh', 'MCP', 'AI Engine'],
    timestamp: 'hace 43s',
  },
  {
    id: 'ARG-1003',
    zone: 'Norteamérica',
    source: { name: 'New York proxy', country: 'US', ip: '185.220.101.17', lat: 40.7128, lon: -74.006 },
    target: { name: 'api-prod-02', country: 'ES', lat: 40.4168, lon: -3.7038 },
    type: 'SQLi probe',
    tactic: 'Execution',
    severity: 'medium',
    score: 67,
    agent: 'wazuh-agent-api02',
    wazuhRule: '31151',
    suricataSid: '2010935',
    mcpTool: 'http.inspect',
    sensorSources: ['Wazuh', 'Suricata'],
    timestamp: 'hace 1m',
  },
  {
    id: 'ARG-1004',
    zone: 'Asia Oriental',
    source: { name: 'Shanghai node', country: 'CN', ip: '103.145.13.9', lat: 31.2304, lon: 121.4737 },
    target: { name: 'ids-sensor-01', country: 'ES', lat: 39.4699, lon: -0.3763 },
    type: 'Port scan',
    tactic: 'Discovery',
    severity: 'high',
    score: 81,
    agent: 'suricata-edge-01',
    wazuhRule: '86601',
    suricataSid: '2001219',
    mcpTool: 'network.scan',
    sensorSources: ['Suricata', 'Zeek', 'AI Engine'],
    timestamp: 'hace 2m',
  },
  {
    id: 'ARG-1005',
    zone: 'Sudamérica',
    source: { name: 'São Paulo host', country: 'BR', ip: '177.54.12.88', lat: -23.5558, lon: -46.6396 },
    target: { name: 'mail-relay', country: 'ES', lat: 37.3891, lon: -5.9845 },
    type: 'Malware callback',
    tactic: 'Command and Control',
    severity: 'critical',
    score: 93,
    agent: 'wazuh-agent-mail01',
    wazuhRule: '100201',
    suricataSid: '2034211',
    mcpTool: 'ioc.enrich',
    sensorSources: ['Wazuh', 'Suricata', 'MCP', 'AI Engine'],
    timestamp: 'hace 4m',
  },
  {
    id: 'ARG-1006',
    zone: 'Oriente Medio',
    source: { name: 'Istanbul ASN', country: 'TR', ip: '5.188.10.11', lat: 41.0082, lon: 28.9784 },
    target: { name: 'fw-border-01', country: 'ES', lat: 40.4168, lon: -3.7038 },
    type: 'Low-and-slow DoS',
    tactic: 'Impact',
    severity: 'high',
    score: 85,
    agent: 'suricata-border-01',
    wazuhRule: '86602',
    suricataSid: '2024218',
    mcpTool: 'flow.anomaly',
    sensorSources: ['Suricata', 'Zeek', 'AI Engine'],
    timestamp: 'hace 6m',
  },
  {
    id: 'ARG-1007',
    zone: 'África Norte',
    source: { name: 'Casablanca relay', country: 'MA', ip: '196.64.22.10', lat: 33.5731, lon: -7.5898 },
    target: { name: 'ad-auth-02', country: 'ES', lat: 40.4168, lon: -3.7038 },
    type: 'Suspicious auth burst',
    tactic: 'Credential Access',
    severity: 'medium',
    score: 73,
    agent: 'wazuh-agent-ad02',
    wazuhRule: '5760',
    suricataSid: 'N/A',
    mcpTool: 'auth.window',
    sensorSources: ['Wazuh', 'MCP', 'AI Engine'],
    timestamp: 'hace 8m',
  },
  {
    id: 'ARG-1008',
    zone: 'Oceanía',
    source: { name: 'Sydney proxy', country: 'AU', ip: '103.27.91.66', lat: -33.8688, lon: 151.2093 },
    target: { name: 'backup-node-01', country: 'ES', lat: 43.263, lon: -2.935 },
    type: 'Anomalous data transfer',
    tactic: 'Exfiltration',
    severity: 'low',
    score: 54,
    agent: 'zeek-backup-01',
    wazuhRule: '90021',
    suricataSid: 'N/A',
    mcpTool: 'flow.bytes',
    sensorSources: ['Zeek', 'AI Engine'],
    timestamp: 'hace 11m',
  }
];

export const kpis = [
  { label: 'Eventos 24h', value: '128.432', trend: '+12.4%', tone: 'info' },
  { label: 'Alertas correladas', value: '1.245', trend: '+8.1%', tone: 'info' },
  { label: 'Anomalías IA', value: '84', trend: '+18', tone: 'ai' },
  { label: 'Críticas', value: '12', trend: '+3', tone: 'critical' },
  { label: 'Agentes activos', value: '37', trend: '100%', tone: 'ok' },
  { label: 'IPS blocks', value: '9', trend: 'guarded', tone: 'high' },
];

export const attackTypeStats = [
  { label: 'Brute force', value: 31 },
  { label: 'Port scan', value: 24 },
  { label: 'SQLi', value: 17 },
  { label: 'Malware', value: 14 },
  { label: 'Auth burst', value: 11 },
  { label: 'Exfil', value: 7 },
];

export const severityStats = [
  { label: 'Critical', value: 12, color: '#ff2f5f' },
  { label: 'High', value: 35, color: '#ff8a3d' },
  { label: 'Medium', value: 49, color: '#ffd166' },
  { label: 'Low', value: 22, color: '#38f8d4' },
];

export const timelineStats = [
  { label: '00h', alerts: 42, ai: 11 },
  { label: '03h', alerts: 61, ai: 17 },
  { label: '06h', alerts: 54, ai: 14 },
  { label: '09h', alerts: 88, ai: 29 },
  { label: '12h', alerts: 123, ai: 37 },
  { label: '15h', alerts: 97, ai: 31 },
  { label: '18h', alerts: 141, ai: 44 },
  { label: '21h', alerts: 109, ai: 33 },
];

export const topCountries = [
  { label: 'CN', value: 28 },
  { label: 'RU/UA', value: 22 },
  { label: 'US', value: 18 },
  { label: 'BR', value: 16 },
  { label: 'TR', value: 10 },
];

export const mitreStats = [
  { label: 'Initial Access', value: 21 },
  { label: 'Credential Access', value: 19 },
  { label: 'Discovery', value: 16 },
  { label: 'C2', value: 11 },
  { label: 'Impact', value: 9 },
  { label: 'Exfiltration', value: 5 },
];

export const agentHealth = [
  { name: 'Wazuh Manager', status: 'online', metric: '18.421 eventos/min' },
  { name: 'MCP Agents', status: 'online', metric: '12 agents · 6 tools' },
  { name: 'Suricata IDS/IPS', status: 'online', metric: '1.204 flows/min' },
  { name: 'Zeek Sensor', status: 'online', metric: '481 conn/min' },
  { name: 'AI Risk Engine', status: 'learning', metric: 'score medio 78' },
];
