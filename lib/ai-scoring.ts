import { spawnSync } from 'node:child_process';
import path from 'node:path';
import type { SecondOpinion } from '@/lib/argos-scorer-client';

type WazuhHit = {
  _id?: string;
  _source?: Record<string, any>;
};

type WazuhSearchResponse = {
  hits?: {
    hits?: WazuhHit[];
  };
};

type ArgosMlResult = {
  id?: string;
  model_id: string;
  model_version: string;
  model_type: string;
  score: number;
  threshold: number;
  prediction: 'attack' | 'benign';
  risk_score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  source: 'model' | 'fallback';
  taxonomy?: {
    model_id: string;
    model_version: string;
    label: string;
    confidence: number;
  };
  csr_lanl?: CsrLanlResult['csr_lanl'];
};

type CsrLanlResult = {
  id?: string;
  csr_lanl?: {
    supervised_score: number;
    entity_anomaly_score: number;
    context_novelty_score: number;
    classification: 'low_signal' | 'suspicious_entity' | 'high_risk_entity';
    entity: string;
    window_start?: string;
    window_end?: string;
    model: string;
    auxiliary_model: string;
    source: string;
    warning?: string;
  } | null;
};

const SCORE_SCRIPT = path.join(process.cwd(), 'models_examples', 'score_wazuh_alerts.py');
const CSR_SCORE_SCRIPT = path.join(process.cwd(), 'models_future', 'csr_lanl_identity', 'score_wazuh_csr_lanl.py');
const PYTHON_BIN = process.env.ARGOS_AI_PYTHON ?? process.env.PYTHON ?? 'python';

function cloneAlerts(alerts: WazuhSearchResponse): WazuhSearchResponse {
  return {
    ...alerts,
    hits: {
      ...alerts.hits,
      hits: (alerts.hits?.hits ?? []).map((hit) => ({
        ...hit,
        _source: { ...(hit._source ?? {}) },
      })),
    },
  };
}

function runPythonScorer<T>(scriptPath: string, hits: WazuhHit[], label: string) {
  const result = spawnSync(PYTHON_BIN, [scriptPath], {
    input: JSON.stringify({ hits }),
    encoding: 'utf8',
    maxBuffer: 20 * 1024 * 1024,
    timeout: 60_000,
    windowsHide: true,
  });

  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr || `${label} scoring exited with status ${result.status}`);
  }

  const parsed = JSON.parse(result.stdout) as { results?: T[] };
  return parsed.results ?? [];
}

function scoreWithPython(hits: WazuhHit[]) {
  return runPythonScorer<ArgosMlResult>(SCORE_SCRIPT, hits, 'ARGOS AI');
}

function scoreCsrLanlWithPython(hits: WazuhHit[]) {
  return runPythonScorer<CsrLanlResult>(CSR_SCORE_SCRIPT, hits, 'CSR-LANL');
}

const SIDECAR_URL = process.env.ARGOS_SCORER_URL ?? 'http://127.0.0.1:8973';
const SIDECAR_TIMEOUT_MS = Number(process.env.ARGOS_SCORER_TIMEOUT_MS ?? 60_000);

export type IpRisk = {
  score: number;
  blocked: boolean;
  decided_at_alert: number | null;
  threshold: number | null;
  alerts_seen: number;
  evidence_kind: 'enumeracion' | 'lateral' | 'reputacion' | 'volumen';
  evidence: {
    usuarios_probados: number;
    maquinas_alcanzadas: number;
    avisos: number;
    reputacion_subred_24: number;
  };
  /** Segunda opinion del Transformer. Anota; el bloqueo lo decide el HGB. */
  second_opinion?: SecondOpinion;
};

type SidecarScoreResponse = {
  argos: ArgosMlResult[] | null;
  csr_lanl: CsrLanlResult[] | null;
  ip_risk: Record<string, IpRisk> | null;
  errors: Record<string, string>;
};

/** Misma precedencia que toDatasetRecord en lib/dataset-export.ts. */
function readSourceIp(source: Record<string, any>): string {
  const data = source.data && typeof source.data === 'object' ? source.data : {};
  for (const value of [data.srcip, data.src_ip, source.srcip, source.source?.ip]) {
    const text = typeof value === 'string' ? value.trim() : '';
    if (text) return text;
  }
  return '';
}

/**
 * Riesgo por IP: complemento al score de ventana, no sustituto.
 *
 * El de ventana puntua un minuto de un agente y reparte el mismo numero entre
 * todas sus alertas; medido, el 100 % de las ventanas contienen mas de una IP,
 * asi que no distingue entre atacantes. Este responde a la conducta acumulada
 * de cada direccion: 148 valores distintos frente a 15 sobre las mismas 10.000
 * alertas.
 */
function attachIpRisk(hits: WazuhHit[], byIp: Record<string, IpRisk>) {
  for (const hit of hits) {
    const source = hit._source ?? {};
    const risk = byIp[readSourceIp(source)];
    if (!risk) continue;
    source.ml = { ...(source.ml ?? {}), ip_risk: risk };
    hit._source = source;
  }
}

/**
 * Puntua en el sidecar, que tiene los modelos ya cargados en memoria.
 *
 * Medido sobre 10.000 alertas: por subproceso 9,34 s + 6,60 s en CADA peticion;
 * en el proceso vivo del sidecar, 1,53 s + 2,36 s. Con el panel sondeando cada
 * 5 s, la diferencia es que las peticiones dejen de solaparse.
 *
 * Devuelve null si el sidecar no responde, y entonces se cae al subproceso: el
 * panel nunca depende de que el sidecar este levantado.
 */
async function scoreViaSidecar(hits: WazuhHit[]): Promise<SidecarScoreResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SIDECAR_TIMEOUT_MS);
  try {
    const response = await fetch(`${SIDECAR_URL}/score`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hits }),
      signal: controller.signal,
    });
    if (!response.ok) return null;
    return (await response.json()) as SidecarScoreResponse;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function attachArgos(hits: WazuhHit[], scores: ArgosMlResult[]) {
  scores.forEach((score, index) => {
    if (!hits[index]) return;
    const source = hits[index]._source ?? {};
    source.ml = { ...(source.ml ?? {}), argos: score };
    hits[index]._source = source;
  });
}

function attachCsrLanl(hits: WazuhHit[], scores: CsrLanlResult[]) {
  scores.forEach((score, index) => {
    if (!score?.csr_lanl || !hits[index]) return;
    const source = hits[index]._source ?? {};
    source.ml = {
      ...(source.ml ?? {}),
      argos: {
        ...((source.ml?.argos && typeof source.ml.argos === 'object') ? source.ml.argos : {}),
        csr_lanl: score.csr_lanl,
      },
    };
    hits[index]._source = source;
  });
}

export async function enrichWazuhAlertsWithAi(alerts: unknown): Promise<unknown> {
  if (!alerts || typeof alerts !== 'object') return alerts;

  const cloned = cloneAlerts(alerts as WazuhSearchResponse);
  const hits = cloned.hits?.hits ?? [];
  if (hits.length === 0) return cloned;

  const sidecar = await scoreViaSidecar(hits);

  if (sidecar?.argos) {
    attachArgos(hits, sidecar.argos);
  } else {
    try {
      attachArgos(hits, scoreWithPython(hits));
    } catch (error) {
      console.error('ARGOS AI scoring failed; falling back to Wazuh level heuristic.', error);
    }
  }

  if (sidecar?.ip_risk) attachIpRisk(hits, sidecar.ip_risk);

  if (sidecar?.csr_lanl) {
    attachCsrLanl(hits, sidecar.csr_lanl);
  } else {
    try {
      attachCsrLanl(hits, scoreCsrLanlWithPython(hits));
    } catch (error) {
      console.error('ARGOS CSR-LANL scoring failed; continuing without entity-behavior enrichment.', error);
    }
  }

  return cloned;
}
