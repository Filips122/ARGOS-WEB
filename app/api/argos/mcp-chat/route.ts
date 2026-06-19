import { NextResponse } from 'next/server';
import { enrichWazuhAlertsWithAi } from '@/lib/ai-scoring';
import { buildArgosLiveData, type ArgosLiveData } from '@/lib/argos-normalizers';
import { injectLocalBenignSimulation } from '@/lib/local-alert-simulator';
import { wazuhApiGet } from '@/lib/wazuh';
import { getRecentWazuhAlerts, getWazuhAlertsCount } from '@/lib/wazuh-indexer';
import type { Attack, Severity } from '@/lib/mock-data';

export const runtime = 'nodejs';

type ChatRequest = {
  message?: string;
};

const severities: Severity[] = ['critical', 'high', 'medium', 'low'];

function getReason(error: unknown) {
  return error instanceof Error ? error.message : 'Unknown error';
}

async function getMonthlyAlerts() {
  try {
    return {
      data: await getRecentWazuhAlerts(10000, 'now-30d'),
      error: null,
    };
  } catch (error) {
    return {
      data: null,
      error: getReason(error),
    };
  }
}

async function getArgosLiveData(): Promise<ArgosLiveData> {
  const [agents, manager, alerts, events24h] = await Promise.allSettled([
    wazuhApiGet('/agents?limit=100'),
    wazuhApiGet('/manager/info'),
    getMonthlyAlerts(),
    getWazuhAlertsCount('now-24h'),
  ]);

  const rawAlerts = alerts.status === 'fulfilled' ? alerts.value.data : null;
  const localAlerts = injectLocalBenignSimulation(rawAlerts);
  const scoredAlerts = await enrichWazuhAlertsWithAi(localAlerts);

  return buildArgosLiveData({
    manager: manager.status === 'fulfilled' ? manager.value : null,
    agents: agents.status === 'fulfilled' ? agents.value : null,
    alerts: scoredAlerts,
    events24h: events24h.status === 'fulfilled' ? events24h.value : null,
    errors: {
      manager: manager.status === 'rejected' ? getReason(manager.reason) : null,
      agents: agents.status === 'rejected' ? getReason(agents.reason) : null,
      alerts: alerts.status === 'rejected' ? getReason(alerts.reason) : alerts.value.error,
    },
  });
}

function normalizeMessage(message: string) {
  return message
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();
}

function extractLimit(message: string) {
  const match = message.match(/\b(\d{1,3})\b/);
  if (!match) return 5;
  return Math.min(25, Math.max(1, Number(match[1])));
}

function extractSeverity(message: string): Severity | null {
  return severities.find((severity) => message.includes(severity)) ?? null;
}

function compareRecent(a: Attack, b: Attack) {
  const aTime = a.receivedAt ? new Date(a.receivedAt).getTime() : 0;
  const bTime = b.receivedAt ? new Date(b.receivedAt).getTime() : 0;
  return bTime - aTime;
}

function formatAttackLine(attack: Attack, index: number) {
  const classification = attack.ai?.prediction ?? 'unknown';
  const csr = attack.ai?.csrLanl?.classification ? `, CSR ${attack.ai.csrLanl.classification}` : '';
  return `${index + 1}. ${attack.severity.toUpperCase()} | ${attack.type} | ${attack.target.name} | regla ${attack.wazuhRule} | AI ${attack.score} | ${classification}${csr}`;
}

function summarizeAttacks(attacks: Attack[], limit: number, severity: Severity | null) {
  const filtered = attacks
    .filter((attack) => (severity ? attack.severity === severity : true))
    .sort(compareRecent)
    .slice(0, limit);

  if (filtered.length === 0) {
    return severity
      ? `No encuentro alertas recientes con severidad ${severity.toUpperCase()} en el estado actual de ARGOS.`
      : 'No encuentro alertas recientes en el estado actual de ARGOS.';
  }

  const title = severity
    ? `Ultimas ${filtered.length} alertas con severidad ${severity.toUpperCase()}:`
    : `Ultimas ${filtered.length} alertas:`;

  return `${title}\n${filtered.map(formatAttackLine).join('\n')}`;
}

function summarizeSeverity(data: ArgosLiveData) {
  const rows = data.charts.severityDistribution
    .map((row) => `${row.label}: ${row.value}`)
    .join(', ');
  return `Distribucion de severidad actual: ${rows}.`;
}

function summarizeAi(data: ArgosLiveData) {
  const attacks = data.attacks ?? [];
  const attackCount = attacks.filter((attack) => attack.ai?.prediction === 'attack').length;
  const benignCount = attacks.filter((attack) => attack.ai?.prediction === 'benign').length;
  const unknownCount = Math.max(0, attacks.length - attackCount - benignCount);
  return `Clasificacion IA actual: attack=${attackCount}, benign=${benignCount}, unknown=${unknownCount}. Total analizado: ${attacks.length}.`;
}

function answerQuestion(message: string, data: ArgosLiveData) {
  const normalized = normalizeMessage(message);
  const limit = extractLimit(normalized);
  const severity = extractSeverity(normalized);

  if (normalized.includes('severidad') || normalized.includes('severity')) {
    if (normalized.includes('distribucion') || normalized.includes('resumen') || !normalized.includes('ultimo')) {
      if (!severity) return summarizeSeverity(data);
    }
  }

  if (normalized.includes('clasificacion') || normalized.includes('class') || normalized.includes('benign') || normalized.includes('attack')) {
    if (!normalized.includes('ultimo')) return summarizeAi(data);
  }

  if (
    normalized.includes('ultimo') ||
    normalized.includes('reciente') ||
    normalized.includes('alerta') ||
    normalized.includes('ataque')
  ) {
    return summarizeAttacks(data.attacks ?? [], limit, severity);
  }

  return [
    'Puedo consultar las alertas actuales de ARGOS. Prueba con preguntas como:',
    '- dime los ultimos 5 ataques de severidad critical',
    '- resumen de severidad',
    '- cuantas alertas attack y benign hay',
    '- ultimas 10 alertas high',
  ].join('\n');
}

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as ChatRequest;
    const message = body.message?.trim();

    if (!message) {
      return NextResponse.json({ ok: false, error: 'Message is required' }, { status: 400 });
    }

    const data = await getArgosLiveData();
    const answer = answerQuestion(message, data);

    return NextResponse.json({
      ok: true,
      answer,
      mode: data.mode,
      totalAlerts: data.attacks.length,
      errors: data.errors,
    });
  } catch (error) {
    return NextResponse.json({ ok: false, error: getReason(error) }, { status: 500 });
  }
}
