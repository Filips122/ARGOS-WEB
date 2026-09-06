import { existsSync } from 'fs';
import { open } from 'fs/promises';
import path from 'path';
import { SCORER_FIELDS, type ScorerAlert } from '@/lib/argos-scorer-client';
import { DATASET_SOURCE_FIELDS, toDatasetRecord, type DatasetRecord } from '@/lib/dataset-export';
import { wazuhIndexerSearch } from '@/lib/wazuh-indexer';

// Fuente del simulacro: alertas frescas de Wazuh cuando el servicio responde,
// y el fichero exportado de 30 dias cuando no. La consulta en vivo es
// deliberadamente ligera y de un solo disparo: nada de paginacion ni de bucle.

export type SimulationSource = 'live' | 'file';

export type SimulationBatch = {
  source: SimulationSource;
  alerts: ScorerAlert[];
  total: number;
  range: { from: string; to: string } | null;
  fallbackReason: string | null;
};

// Configurable con ARGOS_DATASET_FILE. El fichero pesa 1,4 GB y vive dentro
// del proyecto por comodidad; moverlo fuera alivia al vigilante de ficheros del
// servidor de desarrollo de Next.
const DATASET_FILE =
  process.env.ARGOS_DATASET_FILE ?? path.join(process.cwd(), 'datasets', 'argos-alerts_30d.jsonl');

// Solo lo que alimenta los once campos del scorer. La lista completa del export
// son 38 campos; pedir menos es menos trabajo para el indexer.
const SIMULATION_SOURCE_FIELDS = DATASET_SOURCE_FIELDS.filter((field) =>
  [
    '@timestamp',
    'timestamp',
    'agent.id',
    'data.srcip',
    'data.src_ip',
    'data.srcport',
    'data.src_port',
    'data.srcuser',
    'data.dstuser',
    'data.username',
    'srcip',
    'source.ip',
    'source.port',
    'user.name',
    'GeoLocation.country_name',
    'GeoLocation.country_code2',
    'GeoLocation.city_name',
    'GeoLocation.location',
  ].includes(field)
);

function project(record: DatasetRecord): ScorerAlert {
  const alert = {} as Record<string, unknown>;
  for (const field of SCORER_FIELDS) alert[field] = record[field];
  return alert as ScorerAlert;
}

function range(alerts: ScorerAlert[]): { from: string; to: string } | null {
  if (alerts.length === 0) return null;
  return { from: alerts[0].timestamp, to: alerts[alerts.length - 1].timestamp };
}

async function fetchFromWazuh(minutes: number, limit: number): Promise<ScorerAlert[]> {
  const page = await wazuhIndexerSearch<{ hits?: { hits?: { _id?: string; _source?: Record<string, any> }[] } }>({
    size: limit,
    track_total_hits: false,
    _source: { includes: SIMULATION_SOURCE_FIELDS },
    // Ascendente por @timestamp y SIN desempate por _id: ordenar por _id obliga
    // al indexer a cargar su fielddata sobre un indice de 56 millones de
    // documentos, que es lo que dispara su circuit breaker. Aqui no paginamos,
    // asi que no hace falta desempate.
    sort: [{ '@timestamp': { order: 'asc', unmapped_type: 'date' } }],
    query: { range: { '@timestamp': { gte: `now-${minutes}m`, lte: 'now' } } },
  });

  const alerts: ScorerAlert[] = [];
  for (const hit of page.hits?.hits ?? []) {
    const record = toDatasetRecord(hit);
    if (record) alerts.push(project(record));
  }
  return alerts;
}

// Media medida sobre el export: ~1.021 bytes por linea. Con holgura.
const BYTES_PER_LINE = 1400;

async function readFromFile(limit: number): Promise<ScorerAlert[]> {
  if (!existsSync(DATASET_FILE)) {
    throw new Error(
      `No hay respaldo local: falta ${DATASET_FILE}. Generalo con /api/argos/dataset?format=jsonl`
    );
  }

  // Lectura de un bloque acotado, NO un flujo sobre el fichero entero. Con un
  // readline de 1,49 GB, romper el bucle no detiene el flujo de inmediato y
  // sigue generando recursos asincronos en segundo plano: eso tumbo el servidor
  // de desarrollo con "Map maximum size exceeded" en los async hooks de Next.
  // Aqui el numero de operaciones asincronas es constante.
  const handle = await open(DATASET_FILE, 'r');
  try {
    const size = Math.min(limit * BYTES_PER_LINE, 64 * 1024 * 1024);
    const buffer = Buffer.allocUnsafe(size);
    const { bytesRead } = await handle.read(buffer, 0, size, 0);

    const text = buffer.subarray(0, bytesRead).toString('utf-8');
    const lines = text.split('\n');
    // La ultima linea puede estar cortada por el limite del bloque.
    if (bytesRead === size) lines.pop();

    const alerts: ScorerAlert[] = [];
    for (const line of lines) {
      if (alerts.length >= limit) break;
      if (!line.trim()) continue;
      try {
        alerts.push(project(JSON.parse(line) as DatasetRecord));
      } catch {
        // Linea incompleta o corrupta: se ignora.
      }
    }
    return alerts;
  } finally {
    await handle.close();
  }
}

export async function getSimulationBatch(options: {
  minutes?: number;
  limit?: number;
  prefer?: 'auto' | 'live' | 'file';
}): Promise<SimulationBatch> {
  const minutes = Math.min(Math.max(options.minutes ?? 60, 1), 1440);
  const limit = Math.min(Math.max(options.limit ?? 3000, 1), 10000);
  const prefer = options.prefer ?? 'auto';

  if (prefer !== 'file') {
    try {
      const alerts = await fetchFromWazuh(minutes, limit);
      if (alerts.length > 0) {
        return { source: 'live', alerts, total: alerts.length, range: range(alerts), fallbackReason: null };
      }
      if (prefer === 'live') {
        return { source: 'live', alerts, total: 0, range: null, fallbackReason: null };
      }
    } catch (error) {
      if (prefer === 'live') throw error;
      const reason = error instanceof Error ? error.message : 'Error desconocido';
      const alerts = await readFromFile(limit);
      return {
        source: 'file',
        alerts,
        total: alerts.length,
        range: range(alerts),
        fallbackReason: reason.slice(0, 300),
      };
    }
  }

  const alerts = await readFromFile(limit);
  return {
    source: 'file',
    alerts,
    total: alerts.length,
    range: range(alerts),
    fallbackReason: prefer === 'file' ? null : 'Wazuh no devolvio alertas en la ventana pedida',
  };
}
