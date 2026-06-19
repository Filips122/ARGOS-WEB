import { spawnSync } from 'node:child_process';
import path from 'node:path';

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

export async function enrichWazuhAlertsWithAi(alerts: unknown): Promise<unknown> {
  if (!alerts || typeof alerts !== 'object') return alerts;

  const cloned = cloneAlerts(alerts as WazuhSearchResponse);
  const hits = cloned.hits?.hits ?? [];
  if (hits.length === 0) return cloned;

  try {
    const scores = scoreWithPython(hits);
    scores.forEach((score, index) => {
      const source = hits[index]._source ?? {};
      source.ml = {
        ...(source.ml ?? {}),
        argos: score,
      };
      hits[index]._source = source;
    });
  } catch (error) {
    console.error('ARGOS AI scoring failed; falling back to Wazuh level heuristic.', error);
  }

  try {
    const csrScores = scoreCsrLanlWithPython(hits);
    csrScores.forEach((score, index) => {
      if (!score?.csr_lanl) return;
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
  } catch (error) {
    console.error('ARGOS CSR-LANL scoring failed; continuing without entity-behavior enrichment.', error);
  }

  return cloned;
}
