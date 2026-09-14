import { mkdir, readFile, writeFile } from 'fs/promises';
import { gunzipSync } from 'zlib';
import path from 'path';

/**
 * Explotacion real de vulnerabilidades: catalogo KEV de CISA y puntuaciones EPSS.
 *
 * Existe porque la severidad que declara Trivy no predice la explotacion. Medido
 * sobre los 30 dias exportados: de los 28 CVE marcados CRITICAL, NINGUNO esta en
 * KEV; uno marcado MEDIUM si lo esta; y la media EPSS de los LOW (0,00913) es
 * superior a la de los MEDIUM (0,00269).
 *
 * No sustituye a la severidad de Wazuh: se anade al lado, como dato extra.
 */

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz';

const CACHE_PATH = path.join(process.cwd(), '.cache', 'kev-epss-index.json');
const TTL_HOURS = Number(process.env.KEV_EPSS_TTL_HOURS ?? 24);

// Solo se indexa lo que puede llegar a importar. El umbral de accion es 0,1;
// guardar desde 0,02 deja margen para mostrar el valor exacto de cualquier CVE
// que un analista mire, y descarta el 80 % del catalogo que es ruido.
const EPSS_FLOOR = 0.02;

const CVE_PATTERN = /CVE-\d{4}-\d{4,7}/;

export type VulnerabilityContext = {
  cve: string;
  /** En el catalogo de CISA: explotado activamente en la vida real. */
  inKev: boolean;
  /** Probabilidad estimada de explotacion en 30 dias. null si esta bajo el suelo indexado. */
  epss: number | null;
  /** Criterio operativo: en KEV, o EPSS >= 0,1. */
  actionable: boolean;
};

type IndexFile = {
  builtAt: string;
  kevVersion: string;
  kev: string[];
  epss: Record<string, number>;
};

type LoadedIndex = {
  builtAt: number;
  kevVersion: string;
  kev: Set<string>;
  epss: Map<string, number>;
};

let cached: LoadedIndex | null = null;
let building: Promise<LoadedIndex | null> | null = null;

export function extractCve(text: string | undefined | null): string | null {
  if (!text) return null;
  return CVE_PATTERN.exec(text)?.[0] ?? null;
}

function toLoaded(file: IndexFile): LoadedIndex {
  return {
    builtAt: Date.parse(file.builtAt),
    kevVersion: file.kevVersion,
    kev: new Set(file.kev),
    epss: new Map(Object.entries(file.epss)),
  };
}

function isFresh(index: LoadedIndex): boolean {
  return Date.now() - index.builtAt < TTL_HOURS * 3600_000;
}

async function readCache(): Promise<LoadedIndex | null> {
  try {
    return toLoaded(JSON.parse(await readFile(CACHE_PATH, 'utf-8')) as IndexFile);
  } catch {
    return null;
  }
}

async function download(): Promise<IndexFile> {
  const [kevResponse, epssResponse] = await Promise.all([
    fetch(KEV_URL, { cache: 'no-store' }),
    fetch(EPSS_URL, { cache: 'no-store' }),
  ]);

  if (!kevResponse.ok) throw new Error(`KEV ${kevResponse.status}`);
  if (!epssResponse.ok) throw new Error(`EPSS ${epssResponse.status}`);

  const kevData = (await kevResponse.json()) as {
    catalogVersion?: string;
    vulnerabilities?: { cveID: string }[];
  };
  const kev = (kevData.vulnerabilities ?? []).map((entry) => entry.cveID);

  const csv = gunzipSync(Buffer.from(await epssResponse.arrayBuffer())).toString('utf-8');
  const epss: Record<string, number> = {};
  for (const line of csv.split('\n')) {
    if (!line || line.startsWith('#') || line.startsWith('cve,')) continue;
    const [cve, score] = line.split(',');
    const value = Number(score);
    if (cve && Number.isFinite(value) && value >= EPSS_FLOOR) epss[cve] = value;
  }

  return {
    builtAt: new Date().toISOString(),
    kevVersion: kevData.catalogVersion ?? 'desconocida',
    kev,
    epss,
  };
}

async function build(): Promise<LoadedIndex | null> {
  try {
    const file = await download();
    await mkdir(path.dirname(CACHE_PATH), { recursive: true });
    await writeFile(CACHE_PATH, JSON.stringify(file), 'utf-8');
    return toLoaded(file);
  } catch (error) {
    // Sin red, el panel sigue funcionando: simplemente no hay dato extra.
    console.error('KEV/EPSS: no se pudo refrescar el indice.', error);
    return null;
  }
}

/** Carga el indice, refrescandolo si ha caducado. Nunca lanza. */
export async function getVulnerabilityIndex(): Promise<LoadedIndex | null> {
  if (cached && isFresh(cached)) return cached;

  if (!building) {
    building = (async () => {
      const fromDisk = await readCache();
      if (fromDisk && isFresh(fromDisk)) return fromDisk;
      // Un indice caducado es mejor que ninguno si la descarga falla.
      return (await build()) ?? fromDisk;
    })().finally(() => {
      building = null;
    });
  }

  cached = await building;
  return cached;
}

export function lookupCve(index: LoadedIndex | null, cve: string | null): VulnerabilityContext | null {
  if (!index || !cve) return null;
  const inKev = index.kev.has(cve);
  const epss = index.epss.get(cve) ?? null;
  return { cve, inKev, epss, actionable: inKev || (epss !== null && epss >= 0.1) };
}

export function indexStatus(index: LoadedIndex | null) {
  if (!index) return null;
  return {
    kevVersion: index.kevVersion,
    kevEntries: index.kev.size,
    epssEntries: index.epss.size,
    builtAt: new Date(index.builtAt).toISOString(),
  };
}
