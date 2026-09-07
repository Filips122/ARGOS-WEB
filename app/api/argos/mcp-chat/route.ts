/**
 * Chat del panel ARGOS. Tres motores, el mismo endpoint y la misma forma de
 * respuesta, para que el widget no tenga que distinguirlos.
 *
 *  - "cli": usa el CLI de Claude Code en modo no interactivo, es decir, la
 *    SUSCRIPCION del usuario. No necesita clave de API. Preferido si el CLI
 *    esta instalado, porque no factura aparte. Ver lib/claude-cli.ts.
 *  - "api": bucle propio de uso de herramientas con ANTHROPIC_API_KEY. La web
 *    hace de HOST MCP (ver lib/mcp-host.ts).
 *  - "keywords": comparador determinista de palabras clave. Es el respaldo
 *    final: si el MCP o el modelo fallan, la pantalla se degrada, no se rompe.
 *
 * Los tres consultan el MISMO servidor MCP (deploy/argos_mcp/server.ts), asi
 * que no hay dos implementaciones de las herramientas que puedan divergir.
 *
 * Es de SOLO LECTURA. Ninguna herramienta escribe en Wazuh ni bloquea nada.
 *
 * Con el motor "cli" este endpoint lanza un agente en la maquina, acotado a
 * siete herramientas de solo lectura. No expongas la aplicacion fuera de
 * localhost con ese motor activo.
 */

import Anthropic from '@anthropic-ai/sdk';
import { NextResponse } from 'next/server';
import { enrichWazuhAlertsWithAi } from '@/lib/ai-scoring';
import { buildArgosLiveData, type ArgosLiveData } from '@/lib/argos-normalizers';
import { injectLocalBenignSimulation } from '@/lib/local-alert-simulator';
import { askClaudeCli, findClaudeCli } from '@/lib/claude-cli';
import { callMcpTool, getMcpSession } from '@/lib/mcp-host';
import { wazuhApiGet } from '@/lib/wazuh';
import { getRecentWazuhAlerts, getWazuhAlertsCount } from '@/lib/wazuh-indexer';
import type { Attack, Severity } from '@/lib/mock-data';

export const runtime = 'nodejs';
export const maxDuration = 300;

type ChatTurn = { role: 'user' | 'assistant'; content: string };

type ChatRequest = {
  message?: string;
  history?: ChatTurn[];
  /** Sesion del CLI, para que las preguntas de seguimiento tengan contexto. */
  sessionId?: string | null;
};

type Engine = 'cli' | 'api' | 'keywords';

/**
 * Que motor manda. Se prefiere la suscripcion (CLI) porque no factura aparte;
 * ARGOS_CHAT_ENGINE permite forzar uno concreto para comparar o depurar.
 */
function pickEngine(): Engine {
  const forced = process.env.ARGOS_CHAT_ENGINE as Engine | undefined;
  if (forced === 'cli' || forced === 'api' || forced === 'keywords') return forced;
  if (findClaudeCli()) return 'cli';
  if (process.env.ANTHROPIC_API_KEY) return 'api';
  return 'keywords';
}

const severities: Severity[] = ['critical', 'high', 'medium', 'low'];

/** Tope de iteraciones del bucle: acota coste y evita bucles de herramientas. */
const MAX_TURNS = 6;
/** Turnos previos que se reenvian para que el modelo entienda "y de esa IP?". */
const MAX_HISTORY = 8;

function getReason(error: unknown) {
  return error instanceof Error ? error.message : 'Unknown error';
}

// ---------------------------------------------------------------------------
// Motores de lenguaje natural sobre las herramientas MCP
// ---------------------------------------------------------------------------

/**
 * Las advertencias metodologicas van aqui y no solo en las descripciones de las
 * herramientas porque son propiedades del trabajo, no de una llamada concreta:
 * si el modelo las olvida, el panel miente. Cada una esta medida y documentada
 * en METRICAS.md.
 */
const SYSTEM_PROMPT = [
  'Eres el analista de guardia de ARGOS-SOC IA, un panel de operaciones de seguridad montado sobre Wazuh.',
  'Respondes en espanol, en tono profesional y directo, sin florituras. Prefiere frases cortas y cifras concretas.',
  '',
  'COMO TRABAJAS',
  '- Nunca respondas de memoria: consulta las herramientas antes de dar cifras. Todo dato numerico debe salir de una llamada de esta conversacion.',
  '- Si no sabes si los datos son fiables, empieza por estado_plataforma.',
  '- Si una herramienta no devuelve lo que hace falta, dilo. No rellenes huecos con suposiciones ni inventes IPs, reglas o CVEs.',
  '- Encadena varias herramientas cuando la pregunta lo pida (por ejemplo: buscar_alertas para localizar una IP y luego riesgo_de_ip sobre ella).',
  '- Cierra con una recomendacion accionable solo si los datos la sostienen.',
  '',
  'LIMITES QUE NO PUEDES OMITIR (estan medidos, no son cautelas de cortesia)',
  '1. Eres de SOLO LECTURA. No bloqueas IPs, no escribes en Wazuh, no lanzas acciones activas. simular_bloqueo es una reproduccion en seco: si alguien pide bloquear, explica que la decision es humana y que el bloqueo automatico no esta aprobado.',
  '2. El "AI Score" de la tabla es el score de una VENTANA de un minuto de un agente, no de la alerta concreta ni de la IP. No lo presentes como la probabilidad de que esa alerta sea un ataque. Para valorar una IP usa riesgo_de_ip.',
  '3. El dominio de validez de los modelos son atacantes RUIDOSOS: fuerza bruta, escaneo y spraying de credenciales. No afirmes que ARGOS detecta APTs, atacantes sigilosos ni amenazas avanzadas, y corrige al usuario si lo da por hecho.',
  '4. El modelo se valido en este laboratorio; se midio que NO transfiere a maquinas nuevas. Cualquier extrapolacion a otra red es una hipotesis, no un resultado.',
  '5. La severidad CRITICAL del panel viene casi toda de hallazgos de vulnerabilidades del escaner (Trivy), no de ataques en curso; mientras tanto la fuerza bruta real vive en LOW. No equipares severidad alta con ataque activo.',
  '6. El bloque CSR-LANL es una capa experimental fuera de su dominio: su adaptador rellena con ceros las familias de datos que Wazuh no produce. Si aparece, adviertelo y no lo uses como evidencia.',
  '7. Los porcentajes agregados del simulacro suelen venir de unas pocas IPs muy ruidosas. Si citas uno, cita tambien el desglose de concentracion que devuelve la herramienta.',
  '8. El Transformer de atencion es una SEGUNDA OPINION en modo sombra: NO decide, el bloqueo lo decide siempre el modelo principal. En test interno EMPATA con el; no digas que detecta mejor, que es mas preciso ni que generaliza mejor. No tiene validacion externa. No puntua el primer aviso: ahi di que no hay segunda opinion, nunca que vale cero. Lo unico que aporta de nuevo es que avisos pesaron.',
].join('\n');

type ToolTrace = { name: string; args: Record<string, unknown>; ms: number; chars: number; isError: boolean };

async function answerWithClaude(
  message: string,
  history: ChatTurn[]
): Promise<{ answer: string; toolCalls: ToolTrace[]; turns: number; usage: { input: number; output: number } }> {
  const { tools } = await getMcpSession();
  const client = new Anthropic();

  // La API exige que el primer turno sea del usuario: se descarta el saludo
  // inicial del asistente y cualquier turno vacio del historial del navegador.
  const prior = history
    .filter((turn) => (turn.role === 'user' || turn.role === 'assistant') && turn.content?.trim())
    .slice(-MAX_HISTORY);
  while (prior.length > 0 && prior[0].role === 'assistant') prior.shift();

  const messages: Anthropic.MessageParam[] = [
    ...prior.map((turn) => ({ role: turn.role, content: turn.content })),
    { role: 'user' as const, content: message },
  ];

  const toolCalls: ToolTrace[] = [];
  const usage = { input: 0, output: 0 };
  let turns = 0;

  while (turns < MAX_TURNS) {
    turns += 1;

    const stream = client.messages.stream({
      model: 'claude-opus-5',
      max_tokens: 8000,
      thinking: { type: 'adaptive' },
      system: SYSTEM_PROMPT,
      tools: tools as Anthropic.Tool[],
      messages,
    });
    const response = await stream.finalMessage();

    usage.input += response.usage.input_tokens;
    usage.output += response.usage.output_tokens;

    const toolUses = response.content.filter(
      (block): block is Anthropic.ToolUseBlock => block.type === 'tool_use'
    );

    if (response.stop_reason !== 'tool_use' || toolUses.length === 0) {
      const answer = response.content
        .filter((block): block is Anthropic.TextBlock => block.type === 'text')
        .map((block) => block.text)
        .join('\n')
        .trim();
      return { answer, toolCalls, turns, usage };
    }

    messages.push({ role: 'assistant', content: response.content });

    const results: Anthropic.ToolResultBlockParam[] = [];
    for (const use of toolUses) {
      const started = Date.now();
      const args = (use.input ?? {}) as Record<string, unknown>;
      const outcome = await callMcpTool(use.name, args);
      toolCalls.push({
        name: use.name,
        args,
        ms: Date.now() - started,
        chars: outcome.text.length,
        isError: outcome.isError,
      });
      results.push({
        type: 'tool_result',
        tool_use_id: use.id,
        content: outcome.text,
        is_error: outcome.isError,
      });
    }

    messages.push({ role: 'user', content: results });
  }

  return {
    answer:
      'He alcanzado el limite de consultas encadenadas sin cerrar la respuesta. ' +
      'Concreta un poco mas la pregunta (por ejemplo, una IP o una severidad).',
    toolCalls,
    turns,
    usage,
  };
}

// ---------------------------------------------------------------------------
// Motor de respaldo: comparador de palabras clave
// ---------------------------------------------------------------------------

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
    .replace(/[̀-ͯ]/g, '')
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

async function answerWithKeywords(message: string) {
  const data = await getArgosLiveData();
  return {
    answer: answerQuestion(message, data),
    mode: data.mode,
    totalAlerts: data.attacks.length,
    errors: data.errors,
  };
}

// ---------------------------------------------------------------------------

export async function POST(request: Request) {
  try {
    const body = (await request.json()) as ChatRequest;
    const message = body.message?.trim();
    const history = Array.isArray(body.history) ? body.history : [];

    if (!message) {
      return NextResponse.json({ ok: false, error: 'Message is required' }, { status: 400 });
    }

    const engine = pickEngine();
    // Por que fallo cada motor antes de caer al siguiente. Se devuelve al
    // navegador: un fallo silencioso que responde peor es indistinguible de
    // que el modelo simplemente sepa menos.
    const degraded: string[] = [];

    if (engine === 'cli') {
      try {
        const result = await askClaudeCli(message, SYSTEM_PROMPT, body.sessionId);
        return NextResponse.json({
          ok: true,
          engine: 'cli',
          model: result.model,
          auth: 'suscripcion',
          answer: result.answer,
          toolCalls: result.toolCalls,
          turns: result.turns,
          sessionId: result.sessionId,
          listCostUsd: result.listCostUsd,
        });
      } catch (error) {
        degraded.push(`cli: ${getReason(error)}`);
      }
    }

    if (engine === 'api' || (engine === 'cli' && process.env.ANTHROPIC_API_KEY)) {
      try {
        const result = await answerWithClaude(message, history);
        return NextResponse.json({
          ok: true,
          engine: 'api',
          model: 'claude-opus-5',
          auth: 'clave de API',
          answer: result.answer,
          toolCalls: result.toolCalls,
          turns: result.turns,
          usage: result.usage,
          degraded: degraded.length ? degraded.join(' | ') : undefined,
        });
      } catch (error) {
        degraded.push(`api: ${getReason(error)}`);
      }
    }

    // Respaldo final: siempre responde algo, con datos reales.
    const fallback = await answerWithKeywords(message);
    return NextResponse.json({
      ok: true,
      engine: 'keywords',
      degraded: degraded.length ? degraded.join(' | ') : undefined,
      ...fallback,
    });
  } catch (error) {
    return NextResponse.json({ ok: false, error: getReason(error) }, { status: 500 });
  }
}

/** Sonda de estado para que el widget sepa que motor va a contestar. */
export async function GET() {
  const engine = pickEngine();

  if (engine === 'cli') {
    return NextResponse.json({
      ok: true,
      engine: 'cli',
      auth: 'suscripcion',
      model: process.env.ARGOS_CLAUDE_MODEL ?? 'sonnet',
      cli: findClaudeCli(),
      tools: 7,
    });
  }

  if (engine === 'api') {
    try {
      const { tools } = await getMcpSession();
      return NextResponse.json({
        ok: true,
        engine: 'api',
        auth: 'clave de API',
        model: 'claude-opus-5',
        tools: tools.length,
      });
    } catch (error) {
      return NextResponse.json({ ok: true, engine: 'keywords', tools: 0, reason: getReason(error) });
    }
  }

  return NextResponse.json({
    ok: true,
    engine: 'keywords',
    tools: 0,
    reason: 'Ni el CLI de Claude Code ni ANTHROPIC_API_KEY estan disponibles',
  });
}
