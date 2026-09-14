import { NextResponse } from 'next/server';
import type { ScorerAlert } from '@/lib/argos-scorer-client';
import { Exclusions } from '@/lib/scorer-exclusions';
import { getSimulationBatch, type SimulationSource } from '@/lib/simulation-source';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const SIDECAR = process.env.ARGOS_SCORER_URL ?? 'http://127.0.0.1:8973';

export type EvidenceKind = 'enumeracion' | 'lateral' | 'reputacion' | 'volumen';

/**
 * Quien decide DENTRO del simulacro, que es un banco de pruebas. 'hgb' es el
 * modelo principal y el unico con validacion externa; cambiar esto aqui no
 * cambia quien decide en la ingesta real, que siempre es el HGB.
 */
export type SimPolicy = 'hgb' | 'attention' | 'or' | 'and';

export type AgreementCell = 'both' | 'hgb_only' | 'attention_only' | 'none';

export type AgreementReport = {
  matrix: Record<AgreementCell, number>;
  evaluated_ips: number;
  budgets: number[];
  /** Desglose obligatorio. Una IP que alcanza varias maquinas cuenta en cada una. */
  by_agent: Record<string, Record<AgreementCell, number>>;
  disagreements: { ip: string; at_budget: number; agreement: AgreementCell; hgb: number; attention: number }[];
  note: string;
};

type SimVerdict = {
  ip: string;
  score: number;
  threshold: number;
  margin: number;
  evidence_kind: EvidenceKind;
  decided_at_alert: number;
  alert_index: number;
  timestamp: string;
  prevented_alerts: number;
  evidence: {
    usuarios_probados: number;
    maquinas_alcanzadas: number;
    avisos: number;
    reputacion_subred_24: number;
    avisos_decisivos?: number[];
    atencion_por_aviso?: number[];
  };
  /** Avisos que mas pesaron, enlazados con su alerta en el lote reproducido. */
  avisos_decisivos?: { aviso: number; alert_index: number | null }[];
};

type SimResponse = {
  total_alerts: number;
  ips_with_network_origin: number;
  blocked: number;
  block_rate: number;
  median_cut: number | null;
  prevented_alerts: number;
  prevented_ratio: number;
  concentration: {
    top3_prevented: number;
    top3_share: number;
    median_prevented_per_ip: number;
    max_prevented: number;
    zero_effect_blocks: number;
    top_contributors: { ip: string; prevented_alerts: number; decided_at_alert: number }[];
  };
  margins: { min: number | null; median: number | null; tight_count: number; tight_threshold: number };
  evidence_kinds: Record<string, number>;
  censoring: { unblocked: number; censored: number; last_budget: number; note: string };
  verdicts: SimVerdict[];
  policy: SimPolicy;
  agreement: AgreementReport;
};

export type SimulationPayload = {
  ok: true;
  source: SimulationSource;
  fallbackReason: string | null;
  range: { from: string; to: string } | null;
  /** El fichero de 30 dias es el periodo de entrenamiento del paquete. */
  illustrativeOnly: boolean;
  policy: SimPolicy;
  stats: Omit<SimResponse, 'verdicts'>;
  verdicts: (SimVerdict & {
    excluded: boolean;
    exclusionStatus?: 'confirmed' | 'candidate';
    exclusionSeverity?: string;
    exclusionReason?: string;
  })[];
  exclusions: {
    summary: string;
    complete: boolean;
    confirmedRules: number;
    candidateRules: number;
    /** Cero es el primer criterio de promocion: se afirma, no se deduce del silencio. */
    hits: number;
  };
};

function reason(error: unknown) {
  return error instanceof Error ? error.message : 'Error desconocido';
}

async function simulate(alerts: ScorerAlert[], policy: SimPolicy): Promise<SimResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120_000);
  try {
    const response = await fetch(`${SIDECAR}/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alerts, policy }),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`Sidecar ${response.status}: ${(await response.text().catch(() => '')).slice(0, 200)}`);
    }
    return (await response.json()) as SimResponse;
  } finally {
    clearTimeout(timer);
  }
}

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const minutes = Number(params.get('minutes') ?? 60);
  const limit = Number(params.get('limit') ?? 3000);
  const preferParam = params.get('source');
  const prefer = preferParam === 'live' || preferParam === 'file' ? preferParam : 'auto';
  const policyParam = params.get('policy');
  const policy: SimPolicy =
    policyParam === 'attention' || policyParam === 'or' || policyParam === 'and' ? policyParam : 'hgb';

  let batch;
  try {
    batch = await getSimulationBatch({ minutes, limit, prefer });
  } catch (error) {
    return NextResponse.json({ ok: false, stage: 'datos', error: reason(error) }, { status: 502 });
  }

  if (batch.alerts.length === 0) {
    return NextResponse.json(
      { ok: false, stage: 'datos', error: 'No hay alertas en la ventana pedida ni respaldo disponible.' },
      { status: 404 }
    );
  }

  let result: SimResponse;
  try {
    result = await simulate(batch.alerts, policy);
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        stage: 'sidecar',
        error: reason(error),
        hint: 'Arranca el sidecar: .venv/Scripts/python.exe deploy/argos_scorer/service.py',
      },
      { status: 502 }
    );
  }

  // Un sidecar mas antiguo no devuelve el desglose. Se normaliza aqui, en la
  // frontera, para que la interfaz nunca lea campos ausentes y se quede en blanco.
  result.concentration ??= {
    top3_prevented: 0, top3_share: 0, median_prevented_per_ip: 0,
    max_prevented: 0, zero_effect_blocks: 0, top_contributors: [],
  };
  result.margins ??= { min: null, median: null, tight_count: 0, tight_threshold: 0.05 };
  result.evidence_kinds ??= {};
  result.censoring ??= { unblocked: 0, censored: 0, last_budget: 20, note: '' };
  // Un sidecar sin el Transformer no devuelve nada de esto.
  result.policy ??= policy;
  result.agreement ??= {
    matrix: { both: 0, hgb_only: 0, attention_only: 0, none: 0 },
    evaluated_ips: 0, budgets: [], by_agent: {}, disagreements: [],
    note: 'Sidecar sin segunda opinion.',
  };
  for (const verdict of result.verdicts) {
    verdict.margin ??= Number((verdict.score - verdict.threshold).toFixed(4));
    verdict.evidence_kind ??= 'volumen';
  }

  const exclusions = Exclusions.load();
  const { verdicts, ...stats } = result;

  const payload: SimulationPayload = {
    ok: true,
    source: batch.source,
    fallbackReason: batch.fallbackReason,
    range: batch.range,
    illustrativeOnly: batch.source === 'file',
    policy,
    stats,
    verdicts: verdicts.map((verdict) => {
      const hit = exclusions.match(verdict.ip);
      return {
        ...verdict,
        excluded: Boolean(hit),
        ...(hit
          ? {
              exclusionStatus: hit.status,
              exclusionSeverity: hit.entry.severity,
              exclusionReason: hit.entry.reason,
            }
          : {}),
      };
    }),
    exclusions: {
      summary: exclusions.summary(),
      complete: exclusions.config.complete,
      confirmedRules: exclusions.config.confirmed.length,
      candidateRules: exclusions.config.candidates.length,
      hits: 0,
    },
  };

  payload.exclusions.hits = payload.verdicts.filter((verdict) => verdict.excluded).length;

  return NextResponse.json(payload, { headers: { 'Cache-Control': 'no-store' } });
}
