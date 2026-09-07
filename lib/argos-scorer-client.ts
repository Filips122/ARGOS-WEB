import type { DatasetRecord } from '@/lib/dataset-export';

// Cliente del sidecar. Su responsabilidad critica no es el transporte, es la
// PROYECCION: el registro plano lleva rule_*, mitre_* y decoder_name, y el
// paquete los prohibe (README §4.1, circularidad). La lista blanca lo garantiza
// aqui y la guarda de tipos de abajo impide que crezca por descuido.

export const SCORER_FIELDS = [
  'timestamp',
  'window_start',
  'agent_id',
  'src_ip',
  'src_port',
  'src_user',
  'dst_user',
  'geo_country',
  'geo_city',
  'geo_lat',
  'geo_lon',
] as const;

export type ScorerField = (typeof SCORER_FIELDS)[number];

// Falla en compilacion si alguien cuela un campo del motor de reglas.
type Forbidden = Extract<ScorerField, `rule_${string}` | `mitre_${string}` | 'decoder_name'>;
const _noRuleEngineFields: Forbidden extends never ? true : never = true;
void _noRuleEngineFields;

export type ScorerAlert = Pick<DatasetRecord, ScorerField>;

/** alert_id y sort viajan en el sobre: transporte, nunca vector de modelo. */
export type ScorerEnvelope = {
  alert_id: string;
  sort: unknown[];
  alert: ScorerAlert;
};

/**
 * Anotacion del Transformer de atencion. Es una SEGUNDA OPINION en sombra:
 * no decide, no altera `action`, `score`, `threshold` ni `decided_at_alert`,
 * que siguen siendo siempre los del HGB.
 *
 * `available: false` cubre dos casos que hay que distinguir en la interfaz en
 * vez de mostrar un cero: `first_notice` (K=1 esta excluido a proposito del
 * paquete, su umbral no trasladaba de validacion a test) y `out_of_budget`
 * (el numero de avisos no es uno de los presupuestos del modelo).
 */
export type SecondOpinion =
  | {
      model: 'attention';
      available: false;
      reason: 'first_notice' | 'out_of_budget';
      budgets?: number[];
    }
  | {
      model: 'attention';
      available: true;
      score: number;
      threshold: number;
      fired: boolean;
      agreement: 'both' | 'hgb_only' | 'attention_only' | 'none';
      at_alert: number;
      /** Que avisos pesaron. Es lo unico que el HGB no puede dar. */
      avisos_decisivos: number[];
      atencion_por_aviso: number[];
    };

export type Verdict = {
  action: 'BLOCK';
  ip: string;
  score: number;
  decided_at_alert: number;
  threshold: number;
  evidence: {
    usuarios_probados: number;
    maquinas_alcanzadas: number;
    avisos: number;
    reputacion_subred_24: number;
  };
  alert_id: string;
  state_generation: number;
  /** Anotacion, no decision. Ver SecondOpinion. */
  second_opinion?: SecondOpinion;
};

export type IngestResult = {
  accepted: number;
  duplicates: number;
  late_behind_cursor: number;
  verdicts: Verdict[];
  cursor: unknown[] | null;
  state_generation: number;
  /** Sombra: anotaciones, no decisiones. Nada de esto entra en `verdicts`. */
  second_opinions?: ({ alert_id: string; ip: string } & SecondOpinion)[];
  /** IPs donde SOLO cruza el Transformer. Son discrepancias, no bloqueos. */
  attention_only?: { ip: string; alert_id: string; score: number; threshold: number; at_alert: number }[];
  agreement?: Record<'both' | 'hgb_only' | 'attention_only' | 'none', number>;
};

export type ScorerHealth = {
  ok: boolean;
  started_at: string;
  state_origin: 'seed' | 'runtime';
  state_generation: number;
  cursor: unknown[] | null;
  lru_size: number;
  tracked_ips: number;
  blocked_ips: number;
  counters: Record<string, number>;
  /** Estado del Transformer de segunda opinion. No decide nada. */
  attention?: {
    loaded: boolean;
    budgets: number[];
    n_models: number;
    n_params_por_modelo: number;
    role: string;
    validacion: string;
    agreement: Record<'both' | 'hgb_only' | 'attention_only' | 'none', number>;
  };
};

export function toScorerEnvelope(record: DatasetRecord, sort: unknown[]): ScorerEnvelope {
  const alert = {} as Record<ScorerField, unknown>;
  for (const field of SCORER_FIELDS) alert[field] = record[field];
  return { alert_id: record.alert_id, sort, alert: alert as ScorerAlert };
}

export class ScorerClient {
  private consecutiveFailures = 0;
  private openUntil = 0;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly maxFailures: number;
  private readonly cooldownMs: number;

  // Campos explicitos, no propiedades de parametro: Node ejecuta TypeScript en
  // modo strip-only y las propiedades de parametro emiten codigo, no solo tipos.
  constructor(
    baseUrl = process.env.ARGOS_SCORER_URL ?? 'http://127.0.0.1:8973',
    timeoutMs = 30_000,
    maxFailures = 5,
    cooldownMs = 60_000
  ) {
    this.baseUrl = baseUrl;
    this.timeoutMs = timeoutMs;
    this.maxFailures = maxFailures;
    this.cooldownMs = cooldownMs;
  }

  private assertClosed() {
    if (Date.now() < this.openUntil) {
      const seconds = Math.ceil((this.openUntil - Date.now()) / 1000);
      throw new Error(`Circuito abierto tras ${this.consecutiveFailures} fallos; reintento en ${seconds}s`);
    }
  }

  private async request<T>(path: string, body?: unknown): Promise<T> {
    this.assertClosed();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(this.baseUrl + path, {
        method: body === undefined ? 'GET' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        const detail = await response.text().catch(() => '');
        throw new Error(`Sidecar ${response.status} en ${path}: ${detail.slice(0, 300)}`);
      }

      this.consecutiveFailures = 0;
      return (await response.json()) as T;
    } catch (error) {
      this.consecutiveFailures += 1;
      if (this.consecutiveFailures >= this.maxFailures) {
        this.openUntil = Date.now() + this.cooldownMs;
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  health(): Promise<ScorerHealth> {
    return this.request<ScorerHealth>('/health');
  }

  cursor(): Promise<{ cursor: unknown[] | null; state_generation: number }> {
    return this.request<{ cursor: unknown[] | null; state_generation: number }>('/cursor');
  }

  ingest(batch: ScorerEnvelope[]): Promise<IngestResult> {
    return this.request<IngestResult>('/ingest', { batch });
  }
}
