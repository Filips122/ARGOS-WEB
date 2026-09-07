/**
 * Servidor MCP de ARGOS-SOC IA.
 *
 * Expone la plataforma como herramientas del Model Context Protocol, para que
 * cualquier cliente MCP —Claude Desktop, por ejemplo— pueda consultar el SOC en
 * lenguaje natural.
 *
 * Es de SOLO LECTURA: consulta y simula, nunca escribe en Wazuh ni ejecuta
 * acciones de bloqueo. El simulacro es el mismo que la pantalla /simulacro.
 *
 * Transporte stdio. Arranque:
 *   node deploy/argos_mcp/server.ts
 *
 * Configuracion en Claude Desktop (claude_desktop_config.json):
 *   {
 *     "mcpServers": {
 *       "argos": {
 *         "command": "node",
 *         "args": ["<ruta absoluta>/deploy/argos_mcp/server.ts"],
 *         "env": { "ARGOS_WEB_URL": "http://localhost:3000" }
 *       }
 *     }
 *   }
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const WEB_URL = process.env.ARGOS_WEB_URL ?? 'http://localhost:3000';
const SIDECAR_URL = process.env.ARGOS_SCORER_URL ?? 'http://127.0.0.1:8973';
const TIMEOUT_MS = Number(process.env.ARGOS_MCP_TIMEOUT_MS ?? 120_000);

type Attack = {
  id: string;
  severity: string;
  type: string;
  score: number;
  agent: string;
  wazuhRule: string;
  timestamp: string;
  receivedAt?: string;
  source: { ip?: string; city?: string; country: string };
  target: { name: string };
  tactic: string;
  geoApproximate?: boolean;
  ai?: { prediction?: string; confidence?: number; source?: string };
  ipRisk?: {
    score: number;
    blocked: boolean;
    decidedAtAlert: number | null;
    usersTried: number;
    agentsReached: number;
    subnetHostileRatio: number;
    evidenceKind: string;
    secondOpinion?:
      | { available: false; reason: 'first_notice' | 'out_of_budget' }
      | {
          available: true;
          score: number;
          threshold: number;
          fired: boolean;
          agreement: 'both' | 'hgb_only' | 'attention_only' | 'none';
          atAlert: number;
          decisiveNotices: number[];
          attentionPerNotice: number[];
        };
  };
  vulnerability?: { cve: string; inKev: boolean; epss: number | null; actionable: boolean };
};

type LiveData = {
  ok: boolean;
  mode: 'live' | 'partial' | 'demo';
  updatedAt: string;
  attacks: Attack[];
  agentHealth: { name: string; status: string; metric: string }[];
  summary: { events24h: number; alertsLast30d: number; loadedAlertsLast30d: number };
  charts: Record<string, any>;
  errors: Record<string, string | null>;
};

/** Texto plano: los clientes MCP lo muestran tal cual al modelo. */
function text(body: string) {
  return { content: [{ type: 'text' as const, text: body }] };
}

function fail(message: string) {
  return { content: [{ type: 'text' as const, text: message }], isError: true };
}

async function getJson<T>(url: string): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status} en ${url}`);
    return (await response.json()) as T;
  } finally {
    clearTimeout(timer);
  }
}

let cached: { at: number; data: LiveData } | null = null;

/**
 * Una peticion a /api/argos/live tarda unos 4 s y abre consultas al indexer.
 * Se cachea 30 s para que varias herramientas seguidas en una misma
 * conversacion no multipliquen esa carga.
 */
async function live(): Promise<LiveData> {
  if (cached && Date.now() - cached.at < 30_000) return cached.data;
  const data = await getJson<LiveData>(`${WEB_URL}/api/argos/live`);
  cached = { at: Date.now(), data };
  return data;
}

/**
 * Segunda opinion del Transformer de atencion (R13). Se redacta aqui, y no se
 * deja al modelo de lenguaje, para que las cautelas viajen siempre pegadas al
 * dato: empata con el modelo principal, no tiene validacion externa, no decide
 * y no puntua el primer aviso.
 */
function segundaOpinion(second: NonNullable<Attack['ipRisk']>['secondOpinion']): string {
  if (!second) return '';
  if (!second.available) {
    return second.reason === 'first_notice'
      ? 'Segunda opinion (Transformer): sin segunda opinion hasta el 2o aviso; ese modelo no puntua el primero.'
      : 'Segunda opinion (Transformer): no disponible; el numero de avisos no es uno de sus presupuestos (2, 3, 5, 10, 20).';
  }
  const acuerdo = second.agreement === 'both' || second.agreement === 'none' ? 'coincide' : 'discrepa';
  return [
    `Segunda opinion (Transformer): ${(second.score * 100).toFixed(0)} sobre 100, ${acuerdo} con el modelo principal.`,
    `  avisos decisivos: ${second.decisiveNotices.join(', ') || '-'} (evaluado en K=${second.atAlert})`,
    '  Anotacion en sombra: no decide, empata con el modelo principal en test interno y no tiene validacion externa.',
  ].join('\n');
}

function modeNote(data: LiveData): string {
  if (data.mode === 'live') return '';
  if (data.mode === 'demo') {
    return '\n\nAVISO: la plataforma esta en modo DEMO. Wazuh no responde y estos datos son de ejemplo, no reales.';
  }
  const broken = Object.entries(data.errors)
    .filter(([, value]) => value)
    .map(([key]) => key)
    .join(', ');
  return `\n\nAVISO: modo PARCIAL. Fuentes con problemas: ${broken || 'desconocidas'}.`;
}

const server = new McpServer({ name: 'argos-soc', version: '1.0.0' });

// ---------------------------------------------------------------------------

server.registerTool(
  'estado_plataforma',
  {
    title: 'Estado de la plataforma',
    description:
      'Estado de salud de ARGOS: Wazuh manager, indexer, agentes, scoring de IA, ' +
      'volumen de eventos y si la plataforma esta sirviendo datos reales o de ejemplo. ' +
      'Empieza por aqui si no sabes si los datos son fiables.',
    inputSchema: {},
  },
  async () => {
    try {
      const data = await live();
      const lines = [
        `Modo: ${data.mode.toUpperCase()}`,
        `Actualizado: ${data.updatedAt}`,
        `Eventos ultimas 24 h: ${data.summary.events24h.toLocaleString('es-ES')}`,
        `Alertas ultimos 30 dias: ${data.summary.alertsLast30d.toLocaleString('es-ES')}`,
        `Alertas cargadas ahora: ${data.summary.loadedAlertsLast30d.toLocaleString('es-ES')}`,
        '',
        'Salud de componentes:',
        ...data.agentHealth.map((h) => `  ${h.name}: ${h.status} (${h.metric})`),
      ];
      return text(lines.join('\n') + modeNote(data));
    } catch (error) {
      return fail(
        `No se pudo consultar ARGOS en ${WEB_URL}. ¿Esta la web levantada? ` +
          `Detalle: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }
);

server.registerTool(
  'buscar_alertas',
  {
    title: 'Buscar alertas',
    description:
      'Alertas recientes de Wazuh, con filtros opcionales por severidad, agente destino ' +
      'o IP de origen. Devuelve tipo, origen, destino, regla, score de IA y riesgo de la IP.',
    inputSchema: {
      severidad: z.enum(['critical', 'high', 'medium', 'low']).optional()
        .describe('Filtrar por severidad de Wazuh'),
      agente: z.string().optional().describe('Nombre del agente destino'),
      ip: z.string().optional().describe('IP de origen exacta'),
      limite: z.number().int().min(1).max(50).default(10)
        .describe('Cuantas devolver, maximo 50'),
    },
  },
  async ({ severidad, agente, ip, limite }) => {
    try {
      const data = await live();
      let rows = data.attacks;
      if (severidad) rows = rows.filter((a) => a.severity === severidad);
      if (agente) rows = rows.filter((a) => a.target.name.toLowerCase().includes(agente.toLowerCase()));
      if (ip) rows = rows.filter((a) => a.source.ip === ip);

      if (rows.length === 0) {
        return text('Ninguna alerta coincide con esos filtros.' + modeNote(data));
      }

      const shown = rows.slice(0, limite).map((a, index) => {
        const origen = [a.source.city, a.source.country].filter(Boolean).join(', ');
        const riesgo = a.ipRisk
          ? ` | riesgo IP ${(a.ipRisk.score * 100).toFixed(0)} (${a.ipRisk.usersTried} cuentas, ${a.ipRisk.agentsReached} maquinas)`
          : '';
        const cve = a.vulnerability
          ? ` | ${a.vulnerability.cve}${a.vulnerability.inKev ? ' EXPLOTADO' : ''}`
          : '';
        return (
          `${index + 1}. [${a.severity.toUpperCase()}] ${a.type}\n` +
          `   ${origen}${a.geoApproximate ? ' (geo aprox.)' : ''} ${a.source.ip ?? '?'} -> ${a.target.name}\n` +
          `   regla ${a.wazuhRule} | tactica ${a.tactic} | IA ventana ${a.score}${riesgo}${cve}\n` +
          `   ${a.timestamp}`
        );
      });

      return text(
        `${rows.length} alertas coinciden; mostrando ${shown.length}.\n\n${shown.join('\n\n')}` +
          modeNote(data)
      );
    } catch (error) {
      return fail(`Error consultando alertas: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
);

server.registerTool(
  'riesgo_de_ip',
  {
    title: 'Riesgo de una IP',
    description:
      'Que probabilidad da el modelo a que una direccion IP merezca bloqueo, segun su ' +
      'conducta observada: cuentas probadas, maquinas alcanzadas y reputacion de su subred /24. ' +
      'Distinto del score de ventana, que puntua un minuto de un agente y no distingue entre atacantes.',
    inputSchema: {
      ip: z.string().describe('Direccion IPv4 a consultar'),
    },
  },
  async ({ ip }) => {
    try {
      const data = await live();
      const matches = data.attacks.filter((a) => a.source.ip === ip);
      if (matches.length === 0) {
        return text(`La IP ${ip} no aparece en las alertas cargadas.` + modeNote(data));
      }

      const risk = matches.find((a) => a.ipRisk)?.ipRisk;
      const agents = [...new Set(matches.map((a) => a.target.name))];
      const origen = [matches[0].source.city, matches[0].source.country].filter(Boolean).join(', ');

      if (!risk) {
        return text(
          `${ip} (${origen}): ${matches.length} alertas contra ${agents.join(', ')}.\n` +
            'Sin puntuacion de riesgo por IP disponible (el sidecar puede no estar levantado).' +
            modeNote(data)
        );
      }

      return text(
        [
          `IP ${ip} (${origen})`,
          `Riesgo de bloqueo: ${(risk.score * 100).toFixed(0)} sobre 100`,
          risk.blocked
            ? `El modelo la habria bloqueado en su aviso numero ${risk.decidedAtAlert}.`
            : 'No cruza el umbral de bloqueo con la evidencia actual.',
          '',
          'Evidencia:',
          `  cuentas distintas probadas : ${risk.usersTried}`,
          `  maquinas alcanzadas        : ${risk.agentsReached}`,
          `  reputacion hostil de su /24: ${(risk.subnetHostileRatio * 100).toFixed(0)} %`,
          `  tipo de evidencia dominante: ${risk.evidenceKind}`,
          '',
          `Alertas en la ventana cargada: ${matches.length}, contra ${agents.join(', ')}.`,
          '',
          segundaOpinion(risk.secondOpinion),
        ]
          .filter(Boolean)
          .join('\n') + modeNote(data)
      );
    } catch (error) {
      return fail(`Error consultando la IP: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
);

server.registerTool(
  'resumen_amenazas',
  {
    title: 'Resumen de amenazas',
    description:
      'Panorama agregado: reparto por severidad, tipos de ataque mas frecuentes, ' +
      'paises de origen, tacticas MITRE y clasificacion de la IA.',
    inputSchema: {},
  },
  async () => {
    try {
      const data = await live();
      const c = data.charts;
      const rows = (key: string) =>
        (c[key] ?? []).map((r: any) => `  ${r.label}: ${r.value.toLocaleString('es-ES')}`).join('\n');

      const ia = data.attacks.reduce(
        (acc, a) => {
          const p = a.ai?.prediction;
          if (p === 'attack') acc.attack += 1;
          else if (p === 'benign') acc.benign += 1;
          else acc.unknown += 1;
          return acc;
        },
        { attack: 0, benign: 0, unknown: 0 }
      );

      return text(
        [
          `Sobre ${data.attacks.length.toLocaleString('es-ES')} alertas cargadas:`,
          '',
          'Severidad:',
          rows('severityDistribution'),
          '',
          'Tipos de ataque:',
          rows('attacksByType'),
          '',
          'Paises de origen:',
          rows('topCountries'),
          '',
          'Tacticas MITRE:',
          rows('mitreTactics'),
          '',
          `Clasificacion IA: ataque ${ia.attack}, benigno ${ia.benign}, sin clasificar ${ia.unknown}`,
        ].join('\n') + modeNote(data)
      );
    } catch (error) {
      return fail(`Error generando el resumen: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
);

server.registerTool(
  'vulnerabilidades_explotadas',
  {
    title: 'Vulnerabilidades realmente explotadas',
    description:
      'De todos los CVE que reporta el escaner, cuales se estan explotando de verdad segun ' +
      'el catalogo KEV de CISA y las puntuaciones EPSS. Contrasta la severidad declarada con ' +
      'la explotacion observada: son cosas distintas.',
    inputSchema: {},
  },
  async () => {
    try {
      const data = await live();
      const v = data.charts.vulnerabilityIntelligence;
      if (!v) return text('El panel de vulnerabilidades no esta disponible en esta respuesta.');
      if (!v.available) {
        return text('Catalogos KEV/EPSS no disponibles: sin conexion para descargarlos.');
      }

      const top = (v.topExploited ?? [])
        .map((t: any) => `  ${t.cve}${t.inKev ? '  [KEV]' : ''}  EPSS ${t.epss ?? '<0,02'}  (${t.alerts} alertas)`)
        .join('\n');

      return text(
        [
          `Catalogo KEV version ${v.kevVersion}.`,
          '',
          `CVE distintos detectados : ${v.distinctCves}`,
          `Explotados (en KEV)      : ${v.exploitedCves}`,
          `Accionables (KEV o EPSS>=0,1): ${v.actionableCves}`,
          `Ruido de inventario      : ${v.distinctCves - v.actionableCves}` +
            (v.noiseReductionFactor ? `  (cola reducida ${v.noiseReductionFactor} veces)` : ''),
          '',
          'Contraste con la severidad declarada:',
          `  ${v.contrast.criticalAlerts} alertas marcadas CRITICAL por el nivel de regla`,
          `  ${v.contrast.criticalFromVulnScan} de ellas son hallazgos de escaner, no ataques en curso`,
          `  ${v.contrast.criticalActuallyExploited} corresponden a CVE con explotacion real conocida`,
          top ? `\nPrioridad real de parcheo:\n${top}` : '',
        ].join('\n') + modeNote(data)
      );
    } catch (error) {
      return fail(`Error consultando vulnerabilidades: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
);

server.registerTool(
  'simular_bloqueo',
  {
    title: 'Simular bloqueo temprano',
    description:
      'Reproduce alertas reales contra el modelo de bloqueo y devuelve a quien habria ' +
      'bloqueado, en que aviso y con que evidencia. NO ejecuta ninguna accion: ni firewall ' +
      'ni escritura en Wazuh. Incluye el desglose de concentracion, porque el porcentaje ' +
      'agregado suele venir de unas pocas IPs muy ruidosas.',
    inputSchema: {
      minutos: z.number().int().min(15).max(1440).default(60)
        .describe('Ventana temporal a reproducir, en minutos'),
      limite: z.number().int().min(100).max(10000).default(3000)
        .describe('Maximo de alertas a reproducir'),
      politica: z.enum(['hgb', 'attention', 'or', 'and']).default('hgb')
        .describe(
          'Que modelo decide DENTRO del simulacro. "hgb" es el modelo principal y el unico ' +
          'con validacion externa; "attention" es el Transformer de segunda opinion; "or" y ' +
          '"and" son consensos. Cambiarlo aqui no cambia quien decide en la plataforma real.'
        ),
    },
  },
  async ({ minutos, limite, politica }) => {
    try {
      const r = await getJson<any>(
        `${WEB_URL}/api/argos/simulation?minutes=${minutos}&limit=${limite}&policy=${politica}`
      );
      if (!r.ok) return fail(`El simulacro fallo en la fase '${r.stage}': ${r.error}`);

      const s = r.stats;
      const c = s.concentration;
      const excluidos = r.verdicts.filter((v: any) => v.excluded);

      return text(
        [
          `Fuente: ${r.source === 'live' ? 'datos frescos de Wazuh' : 'fichero exportado de 30 dias'}.`,
          r.illustrativeOnly
            ? 'AVISO: ese fichero es el periodo de entrenamiento de los modelos, asi que estas cifras ilustran el mecanismo pero no miden rendimiento.'
            : '',
          r.range ? `Ventana: ${r.range.from} a ${r.range.to}` : '',
          '',
          `Alertas reproducidas : ${s.total_alerts.toLocaleString('es-ES')}`,
          `IPs con origen de red: ${s.ips_with_network_origin}`,
          `Bloqueadas           : ${s.blocked}  (${(s.block_rate * 100).toFixed(1)} %)`,
          `Mediana de corte     : aviso ${s.median_cut ?? '-'}`,
          `Alertas suprimidas   : ${s.prevented_alerts.toLocaleString('es-ES')} (${(s.prevented_ratio * 100).toFixed(0)} % del volumen)`,
          '',
          'Desglose, porque el agregado esconde concentracion:',
          `  ${(c.top3_share * 100).toFixed(0)} % de lo suprimido lo aportan solo 3 IPs`,
          `  mediana por IP: ${c.median_prevented_per_ip} (maximo ${c.max_prevented})`,
          `  bloqueos sin efecto medible: ${c.zero_effect_blocks}`,
          '',
          'Calidad de las decisiones:',
          `  evidencia: ${JSON.stringify(s.evidence_kinds)}`,
          `  ${s.margins.tight_count} de ${s.blocked} con margen ajustado (<${s.margins.tight_threshold}) sobre el umbral`,
          '',
          `Sesgo de ventana: ${s.censoring.censored} de ${s.censoring.unblocked} IPs sin bloquear no llegaron a ` +
            `${s.censoring.last_budget} avisos, asi que no puede afirmarse que sean benignas.`,
          '',
          `Decidio: ${r.policy === 'hgb' ? 'el modelo principal (HGB)' :
            r.policy === 'attention' ? 'el Transformer solo' : `consenso ${r.policy.toUpperCase()}`}.`,
          s.agreement && s.agreement.evaluated_ips > 0
            ? [
                `Acuerdo entre los dos modelos sobre ${s.agreement.evaluated_ips} IPs con 2 o mas avisos:`,
                `  ambos bloquearian    : ${s.agreement.matrix.both}`,
                `  solo el principal    : ${s.agreement.matrix.hgb_only}`,
                `  solo el Transformer  : ${s.agreement.matrix.attention_only}`,
                `  ninguno              : ${s.agreement.matrix.none}`,
                `  desglose por agente destino: ${Object.entries(s.agreement.by_agent ?? {})
                  .map(([agente, fila]: [string, any]) =>
                    `${agente} (${fila.both} ambos, ${fila.hgb_only} solo principal, ${fila.attention_only} solo Transformer)`)
                  .join('; ') || 'sin datos'}`,
                '  Una IP que alcanza varias maquinas cuenta en cada una: las filas suman mas que el total.',
              ].join('\n')
            : 'Ninguna IP alcanzo dos avisos: el Transformer no llega a opinar en esta ventana.',
          '',
          excluidos.length === 0
            ? `Ningun veredicto sobre infraestructura propia (${r.exclusions.confirmedRules} reglas comprobadas).`
            : `FALLO GRAVE: ${excluidos.length} veredictos sobre infraestructura propia: ${excluidos.map((v: any) => v.ip).join(', ')}`,
        ]
          .filter(Boolean)
          .join('\n')
      );
    } catch (error) {
      return fail(`Error ejecutando el simulacro: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
);

server.registerTool(
  'estado_modelos',
  {
    title: 'Estado de los modelos',
    description:
      'Estado del sidecar que aloja los modelos: si esta levantado, cuantas IPs tiene ' +
      'perfiladas y cuantas ha decidido bloquear.',
    inputSchema: {},
  },
  async () => {
    try {
      const h = await getJson<any>(`${SIDECAR_URL}/health`);
      return text(
        [
          'Sidecar de modelos: LEVANTADO',
          `  arrancado: ${h.started_at}`,
          `  estado: ${h.state_origin} (generacion ${h.state_generation})`,
          `  IPs perfiladas: ${h.tracked_ips}`,
          `  IPs con decision de bloqueo: ${h.blocked_ips}`,
          `  eventos deduplicados en memoria: ${h.lru_size}`,
          '',
          `Contadores: ${JSON.stringify(h.counters)}`,
          '',
          h.attention?.loaded
            ? [
                'Segunda opinion (Transformer de atencion): CARGADA',
                `  presupuestos: K = ${h.attention.budgets.join(', ')} (K=1 excluido a proposito)`,
                `  ${h.attention.n_models} modelos, ${h.attention.n_params_por_modelo} parametros cada uno, inferencia en numpy`,
                `  papel: ${h.attention.role}`,
                `  validacion: ${h.attention.validacion}`,
                `  acuerdo acumulado con el modelo principal: ${JSON.stringify(h.attention.agreement)}`,
              ].join('\n')
            : 'Segunda opinion (Transformer): NO cargada. El modelo principal decide igual.',
        ].join('\n')
      );
    } catch {
      return text(
        `Sidecar de modelos: NO DISPONIBLE en ${SIDECAR_URL}.\n` +
          'La web sigue funcionando: se repliega a lanzar subprocesos, mas lento, ' +
          'y el riesgo por IP no aparece.\n' +
          'Arrancar con: .venv/Scripts/python.exe deploy/argos_scorer/service.py'
      );
    }
  }
);

// ---------------------------------------------------------------------------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stdout es el canal del protocolo: cualquier traza va por stderr.
  console.error(`[argos-mcp] servidor listo. Web: ${WEB_URL} · Sidecar: ${SIDECAR_URL}`);
}

main().catch((error) => {
  console.error('[argos-mcp] fallo fatal:', error);
  process.exit(1);
});
