import { appendFileSync, mkdirSync, readFileSync, existsSync } from 'fs';
import path from 'path';
import {
  ScorerClient,
  toScorerEnvelope,
  type SecondOpinion,
  type Verdict,
} from '@/lib/argos-scorer-client';
import { DATASET_SOURCE_FIELDS, toDatasetRecord } from '@/lib/dataset-export';
import { Exclusions, type ExclusionHit } from '@/lib/scorer-exclusions';
import { wazuhIndexerSearch } from '@/lib/wazuh-indexer';

type Hit = { _id?: string; _source?: Record<string, any>; sort?: unknown[] };
type SearchResponse = { hits?: { hits?: Hit[] } };

/** Retroceso al arrancar, por documentos indexados tarde. El sidecar los
 *  distingue de un reenvio con su cola persistida de alert_id. */
const ROLLBACK_MS = 60_000;

export type LedgerRecord = {
  ts_decision: string;
  ip: string;
  action: 'BLOCK';
  mode: 'shadow';
  score: number;
  threshold: number;
  decided_at_alert: number;
  evidence: Verdict['evidence'];
  alert_ids: string[];
  model: { budget_k: number; state_generation: number };
  exclusion: { hit: boolean; status?: string; severity?: string; reason?: string };
  duplicate_of?: string;
  /**
   * Anotacion del Transformer en el momento de la decision. Se guarda para
   * poder medir despues el acuerdo sobre trafico real, que es la unica
   * validacion externa que le queda a ese modelo. No participa en la decision:
   * `action`, `score`, `threshold` y `decided_at_alert` son los del HGB.
   */
  second_opinion?: SecondOpinion;
};

/**
 * Registro de efectos. Es la unica fuente de verdad sobre a quien se ha
 * decidido bloquear: profiles/blocked del sidecar son decision en curso y no
 * sobreviven a un reinicio. Primera vez por IP gana; una reemision se anota
 * pero no vuelve a actuar.
 */
export class VerdictLedger {
  private firstSeen = new Map<string, string>();

  private readonly file: string;

  constructor(file: string) {
    this.file = file;
    mkdirSync(path.dirname(file), { recursive: true });
    if (existsSync(file)) {
      for (const line of readFileSync(file, 'utf-8').split('\n')) {
        if (!line.trim()) continue;
        try {
          const row = JSON.parse(line) as LedgerRecord;
          if (!row.duplicate_of && !this.firstSeen.has(row.ip)) {
            this.firstSeen.set(row.ip, row.ts_decision);
          }
        } catch {
          // Una linea corrupta no debe impedir arrancar: se ignora y se sigue.
        }
      }
    }
  }

  get size(): number {
    return this.firstSeen.size;
  }

  record(verdict: Verdict, exclusion: ExclusionHit | null): { record: LedgerRecord; isNew: boolean } {
    const previous = this.firstSeen.get(verdict.ip);
    const record: LedgerRecord = {
      ts_decision: new Date().toISOString(),
      ip: verdict.ip,
      action: 'BLOCK',
      mode: 'shadow',
      score: verdict.score,
      threshold: verdict.threshold,
      decided_at_alert: verdict.decided_at_alert,
      evidence: verdict.evidence,
      alert_ids: [verdict.alert_id],
      model: { budget_k: verdict.decided_at_alert, state_generation: verdict.state_generation },
      exclusion: exclusion
        ? { hit: true, status: exclusion.status, severity: exclusion.entry.severity, reason: exclusion.entry.reason }
        : { hit: false },
      ...(previous ? { duplicate_of: previous } : {}),
      ...(verdict.second_opinion ? { second_opinion: verdict.second_opinion } : {}),
    };

    appendFileSync(this.file, JSON.stringify(record) + '\n', 'utf-8');
    if (!previous) this.firstSeen.set(verdict.ip, record.ts_decision);
    return { record, isNew: !previous };
  }
}

export type TickResult = {
  read: number;
  sent: number;
  accepted: number;
  duplicates: number;
  lateBehindCursor: number;
  verdicts: number;
  newBlocks: number;
  exclusionHits: LedgerRecord[];
  cursor: unknown[] | null;
  exhausted: boolean;
};

function buildQuery(size: number, searchAfter?: unknown[]) {
  return {
    size,
    track_total_hits: false,
    _source: { includes: DATASET_SOURCE_FIELDS },
    // Ascendente: el puntuador es de flujo y calcula span y huecos entre avisos.
    sort: [{ '@timestamp': { order: 'asc', unmapped_type: 'date' } }, { _id: { order: 'asc' } }],
    ...(searchAfter ? { search_after: searchAfter } : {}),
    query: { range: { '@timestamp': { lte: 'now' } } },
  };
}

function rollback(cursor: unknown[] | null): unknown[] | undefined {
  if (!cursor || cursor.length === 0) return undefined;
  const [stamp, ...rest] = cursor;
  if (typeof stamp !== 'number') return cursor as unknown[];
  return [stamp - ROLLBACK_MS, ...rest];
}

export class ScorerIngestor {
  private cursor: unknown[] | null = null;
  private primed = false;

  private readonly client: ScorerClient;
  private readonly ledger: VerdictLedger;
  private readonly exclusions: Exclusions;
  private readonly batchSize: number;

  constructor(client: ScorerClient, ledger: VerdictLedger, exclusions: Exclusions, batchSize = 1000) {
    this.client = client;
    this.ledger = ledger;
    this.exclusions = exclusions;
    this.batchSize = batchSize;
  }

  /**
   * El cursor es propiedad del sidecar: vive dentro de su escritura atomica.
   *
   * Sin cursor previo NO se rellena hacia atras. La semilla del paquete ya
   * contiene la reputacion de las subredes calculada sobre esa misma captura de
   * 30 dias: reingerirla contaria dos veces cada register_arrival y desplazaria
   * los ratios sub24/sub16 que sostienen el bloqueo al primer aviso. Los
   * perfiles por IP se construyen desde el trafico que llega, hacia delante.
   *
   * ARGOS_SHADOW_BACKFILL_FROM (ISO 8601) fuerza un origen distinto cuando se
   * arranca contra un indice cuya historia NO entro en la semilla.
   */
  private async prime(): Promise<void> {
    if (this.primed) return;

    const { cursor } = await this.client.cursor();
    if (cursor) {
      this.cursor = cursor;
    } else {
      const from = process.env.ARGOS_SHADOW_BACKFILL_FROM;
      const startMs = from ? Date.parse(from) : Date.now();
      if (Number.isNaN(startMs)) {
        throw new Error(`ARGOS_SHADOW_BACKFILL_FROM no es una fecha ISO valida: ${from}`);
      }
      // El _id vacio ordena antes que cualquier id real, asi que search_after
      // deja pasar todo lo estrictamente posterior a ese instante.
      this.cursor = [startMs, ''];
    }
    this.primed = true;
  }

  async tick(): Promise<TickResult> {
    await this.prime();

    const searchAfter = this.primed && this.cursor ? rollback(this.cursor) : undefined;
    const page = await wazuhIndexerSearch<SearchResponse>(buildQuery(this.batchSize, searchAfter));
    const hits = page.hits?.hits ?? [];

    const batch = [];
    for (const hit of hits) {
      const record = toDatasetRecord(hit);
      if (!record || !record.alert_id || !hit.sort) continue;
      batch.push(toScorerEnvelope(record, hit.sort));
    }

    if (batch.length === 0) {
      return {
        read: hits.length, sent: 0, accepted: 0, duplicates: 0, lateBehindCursor: 0,
        verdicts: 0, newBlocks: 0, exclusionHits: [], cursor: this.cursor, exhausted: true,
      };
    }

    const result = await this.client.ingest(batch);
    this.cursor = result.cursor;

    let newBlocks = 0;
    const exclusionHits: LedgerRecord[] = [];
    for (const verdict of result.verdicts) {
      const hit = this.exclusions.match(verdict.ip);
      const { record, isNew } = this.ledger.record(verdict, hit);
      if (isNew) newBlocks += 1;
      if (hit) exclusionHits.push(record);
    }

    return {
      read: hits.length,
      sent: batch.length,
      accepted: result.accepted,
      duplicates: result.duplicates,
      lateBehindCursor: result.late_behind_cursor,
      verdicts: result.verdicts.length,
      newBlocks,
      exclusionHits,
      cursor: result.cursor,
      exhausted: hits.length < this.batchSize,
    };
  }
}
