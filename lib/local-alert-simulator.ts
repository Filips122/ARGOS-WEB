type WazuhHit = {
  _id?: string;
  _source?: Record<string, any>;
  sort?: unknown[];
};

type WazuhSearchResponse = {
  hits?: {
    total?: WazuhTotal;
    hits?: WazuhHit[];
  };
};

type WazuhTotal = number | { value?: number; relation?: string };

const SIMULATION_INTERVAL_MS = 60_000;

type BenignScenario = {
  key: string;
  title: string;
  description: string;
  ruleId: string;
  level: number;
  groups: string[];
  decoder: string;
  programName?: string;
  location: string;
  agent: {
    id: string;
    name: string;
    ip: string;
  };
  sourceIp?: string;
  data?: Record<string, unknown>;
  expectedProfile: 'known-benign' | 'unseen-benign-generalization';
};

const benignScenarios: BenignScenario[] = [
    {
      key: 'known-systemd-journald-web',
      title: 'ARGOS local benign test 1/5 - known systemd service failure',
      description: 'Systemd: Service exited due to a failure.',
      ruleId: '40704',
      level: 5,
      groups: ['local', 'systemd'],
      decoder: 'systemd',
      programName: 'systemd',
      location: 'journald',
      agent: { id: '025', name: 'Server-Web-Top-Secret', ip: '172.31.36.115' },
      expectedProfile: 'known-benign',
    },
    {
      key: 'known-systemd-syslog-server',
      title: 'ARGOS local benign test 2/5 - known systemd syslog failure',
      description: 'Systemd: Service exited due to a failure.',
      ruleId: '40704',
      level: 5,
      groups: ['local', 'systemd'],
      decoder: 'systemd',
      programName: 'systemd',
      location: '/var/log/syslog',
      agent: { id: '018', name: 'server1-principal', ip: '167.86.95.135' },
      sourceIp: '10.10.18.45',
      expectedProfile: 'known-benign',
    },
    {
      key: 'known-systemd-wazuh-node',
      title: 'ARGOS local benign test 3/5 - known systemd Wazuh node event',
      description: 'Systemd: Service exited due to a failure.',
      ruleId: '40704',
      level: 5,
      groups: ['local', 'systemd'],
      decoder: 'systemd',
      programName: 'systemd',
      location: 'journald',
      agent: { id: '022', name: 'wazuh', ip: '10.0.0.22' },
      sourceIp: '10.10.0.12',
      expectedProfile: 'known-benign',
    },
    {
      key: 'known-systemd-journald-container',
      title: 'ARGOS local benign test 4/5 - known systemd container service failure',
      description: 'Systemd: Service exited due to a failure.',
      ruleId: '40704',
      level: 5,
      groups: ['local', 'systemd'],
      decoder: 'systemd',
      programName: 'systemd',
      location: 'journald',
      agent: { id: '023', name: 'clockworksolution.es', ip: '10.0.0.23' },
      sourceIp: '10.10.23.70',
      expectedProfile: 'known-benign',
    },
    {
      key: 'unseen-admin-backup-saas',
      title: 'ARGOS local benign test 5/5 - unseen benign administrator workflow',
      description: 'Administrator exported a scheduled backup report to an internal SaaS console after change approval.',
      ruleId: 'ARGOS-SIM-UNSEEN-5001',
      level: 2,
      groups: ['maintenance', 'backup', 'admin_activity'],
      decoder: 'argos-admin-audit',
      programName: 'backup-agent',
      location: '/var/log/argos/admin-audit.log',
      agent: { id: 'SIM-NEW-01', name: 'new-backup-admin-node', ip: '10.250.77.12' },
      data: { srcip: '10.250.77.12', srcport: 54432, dstport: 443, username: 'backup-admin' },
      expectedProfile: 'unseen-benign-generalization',
    },
    {
      key: 'known-systemd-journald-listener',
      title: 'ARGOS local benign test 1/5 - known wazuh-listener service failure',
      description: 'Systemd: Service exited due to a failure.',
      ruleId: '40704',
      level: 5,
      groups: ['local', 'systemd'],
      decoder: 'systemd',
      programName: 'systemd',
      location: 'journald',
      agent: { id: '018', name: 'server1-principal', ip: '167.86.95.135' },
      expectedProfile: 'known-benign',
    },
    {
      key: 'known-systemd-syslog-docker-events',
      title: 'ARGOS local benign test 2/5 - known docker-events service failure',
      description: 'Systemd: Service exited due to a failure.',
      ruleId: '40704',
      level: 5,
      groups: ['local', 'systemd'],
      decoder: 'systemd',
      programName: 'systemd',
      location: '/var/log/syslog',
      agent: { id: '025', name: 'Server-Web-Top-Secret', ip: '172.31.36.115' },
      sourceIp: '10.20.25.44',
      expectedProfile: 'known-benign',
    },
    {
      key: 'known-docker-json-log',
      title: 'ARGOS local benign test 3/5 - known docker json log',
      description: 'Docker operational container log processed normally.',
      ruleId: '87901',
      level: 3,
      groups: ['docker'],
      decoder: 'json',
      programName: 'dockerd',
      location: '/var/lib/docker/containers/6f7ec43a820d0c0be4e6ce3d35bccc2b4837a6897d53b5ad9adcb7b0e0981826/6f7ec43a820d0c0be4e6ce3d35bccc2b4837a6897d53b5ad9adcb7b0e0981826-json.log',
      agent: { id: '022', name: 'wazuh', ip: '10.0.0.22' },
      sourceIp: '10.20.22.64',
      expectedProfile: 'known-benign',
    },
    {
      key: 'known-systemd-syslog-runtime',
      title: 'ARGOS local benign test 4/5 - known systemd runtime service failure',
      description: 'Systemd: Service exited due to a failure.',
      ruleId: '40704',
      level: 5,
      groups: ['local', 'systemd'],
      decoder: 'systemd',
      programName: 'systemd',
      location: '/var/log/syslog',
      agent: { id: '026', name: 'clockworksolution.es', ip: '10.0.0.26' },
      sourceIp: '10.20.26.80',
      expectedProfile: 'known-benign',
    },
    {
      key: 'unseen-helpdesk-mfa-reset',
      title: 'ARGOS local benign test 5/5 - unseen benign helpdesk workflow',
      description: 'Helpdesk operator completed a supervised MFA reset for a locked employee account.',
      ruleId: 'ARGOS-SIM-UNSEEN-5002',
      level: 2,
      groups: ['helpdesk', 'identity_admin', 'mfa'],
      decoder: 'argos-identity-audit',
      programName: 'identity-console',
      location: '/var/log/argos/identity-audit.log',
      agent: { id: 'SIM-NEW-02', name: 'identity-admin-console', ip: '10.250.88.20' },
      data: { srcip: '10.250.88.20', srcport: 53888, dstport: 443, username: 'helpdesk-operator' },
      expectedProfile: 'unseen-benign-generalization',
    },
];

function simulationEnabled() {
  return process.env.ARGOS_LOCAL_BENIGN_SIMULATION !== 'false';
}

function getCurrentScenario(now = Date.now()) {
  const windowIndex = Math.floor(now / SIMULATION_INTERVAL_MS);
  const scenarioIndex = (windowIndex * 7 + 3) % benignScenarios.length;
  return {
    scenario: benignScenarios[scenarioIndex],
    scenarioIndex,
    windowIndex,
  };
}

function buildSimulatedBenignHit(now = new Date()): WazuhHit {
  const { scenario, scenarioIndex, windowIndex } = getCurrentScenario(now.getTime());

  return {
    _id: `ARGOS-LOCAL-BENIGN-${scenarioIndex + 1}-${scenario.key}-${windowIndex}`,
    _source: {
      '@timestamp': now.toISOString(),
      timestamp: now.toISOString(),
      title: scenario.title,
      full_log: scenario.description,
      rule: {
        id: scenario.ruleId,
        level: scenario.level,
        description: scenario.description,
        groups: scenario.groups,
        mitre: {
          tactic: ['Benign Simulation'],
          tactics: ['Benign Simulation'],
        },
      },
      agent: scenario.agent,
      decoder: {
        name: scenario.decoder,
      },
      predecoder: scenario.programName
        ? {
            program_name: scenario.programName,
          }
        : undefined,
      location: scenario.location,
      data: scenario.data ?? {},
      source: {
        ip: scenario.sourceIp ?? scenario.data?.srcip,
      },
      event: {
        kind: 'event',
        category: ['authentication'],
        type: ['info'],
        outcome: 'success',
      },
      labels: {
        argos_local_simulation: 'true',
        argos_simulation_kind: 'benign',
        argos_simulation_scenario: scenario.key,
        argos_simulation_profile: scenario.expectedProfile,
        argos_simulation_position: String(scenarioIndex + 1),
      },
      argos: {
        localSimulation: true,
        simulationKind: 'benign',
        scenario: scenario.key,
        scenarioPosition: scenarioIndex + 1,
        expectedProfile: scenario.expectedProfile,
        note: 'Generated inside ARGOS only; never written to Wazuh API or Indexer.',
      },
    },
  };
}

function incrementTotal(total: WazuhTotal | undefined, amount: number) {
  if (typeof total === 'number') return total + amount;
  if (total && typeof total === 'object' && 'value' in total && typeof total.value === 'number') {
    return { ...total, value: total.value + amount };
  }
  return total;
}

export function injectLocalBenignSimulation(alerts: unknown): unknown {
  if (!simulationEnabled() || !alerts || typeof alerts !== 'object') return alerts;

  const response = alerts as WazuhSearchResponse;
  const hits = response.hits?.hits ?? [];
  const simulatedHit = buildSimulatedBenignHit();

  return {
    ...response,
    hits: {
      ...response.hits,
      total: incrementTotal(response.hits?.total, 1),
      hits: [simulatedHit, ...hits],
    },
  };
}
