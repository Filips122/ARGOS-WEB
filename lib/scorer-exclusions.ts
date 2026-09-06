import { readFileSync } from 'fs';
import path from 'path';

// Lista de exclusion del modo sombra. Se carga como configuracion obligatoria:
// sin ella no se arranca, porque un veredicto sobre infraestructura propia es el
// primer criterio de promocion y sin la lista no se puede detectar.

export type ExclusionSeverity = 'error' | 'grave';

export type ExclusionEntry = {
  cidr: string;
  reason: string;
  severity: ExclusionSeverity;
  source?: string;
};

export type ExclusionConfig = {
  version: number;
  updated_at: string;
  complete: boolean;
  missing: string[];
  note?: string;
  confirmed: ExclusionEntry[];
  candidates: ExclusionEntry[];
};

export type ExclusionHit = {
  entry: ExclusionEntry;
  status: 'confirmed' | 'candidate';
};

type CompiledRule = {
  base: number;
  mask: number;
  entry: ExclusionEntry;
  status: 'confirmed' | 'candidate';
};

const DEFAULT_PATH = path.join(process.cwd(), 'deploy', 'argos_scorer', 'exclusions.json');

function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;

  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

function compile(entry: ExclusionEntry, status: 'confirmed' | 'candidate'): CompiledRule {
  const [address, bitsText] = entry.cidr.split('/');
  const base = ipv4ToInt(address);
  const bits = bitsText === undefined ? 32 : Number(bitsText);

  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    throw new Error(`Entrada de exclusion invalida: ${entry.cidr}`);
  }

  // >>> 0 mantiene el valor sin signo; un /0 se trata aparte porque
  // desplazar 32 posiciones en JS es un no-op, no un cero.
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: (base & mask) >>> 0, mask, entry, status };
}

export class Exclusions {
  private rules: CompiledRule[];
  readonly config: ExclusionConfig;

  constructor(config: ExclusionConfig) {
    this.config = config;
    this.rules = [
      ...config.confirmed.map((entry) => compile(entry, 'confirmed')),
      ...config.candidates.map((entry) => compile(entry, 'candidate')),
    ];
  }

  static load(file = DEFAULT_PATH): Exclusions {
    let raw: string;
    try {
      raw = readFileSync(file, 'utf-8');
    } catch {
      throw new Error(
        `No se encuentra la lista de exclusion en ${file}. Es configuracion obligatoria: ` +
          'sin ella no se puede marcar un veredicto sobre infraestructura propia.'
      );
    }

    const config = JSON.parse(raw) as ExclusionConfig;
    if (!Array.isArray(config.confirmed) || config.confirmed.length === 0) {
      throw new Error('La lista de exclusion no tiene entradas confirmadas.');
    }
    return new Exclusions(config);
  }

  match(ip: string): ExclusionHit | null {
    const value = ipv4ToInt(ip);
    if (value === null) return null;

    for (const rule of this.rules) {
      if (((value & rule.mask) >>> 0) === rule.base) {
        return { entry: rule.entry, status: rule.status };
      }
    }
    return null;
  }

  /** La promocion a bloqueo real queda vetada mientras falten entradas. */
  get blocksPromotion(): boolean {
    return !this.config.complete;
  }

  summary(): string {
    const state = this.config.complete ? 'COMPLETA' : `INCOMPLETA (falta: ${this.config.missing.join(', ')})`;
    return `${this.config.confirmed.length} confirmadas, ${this.config.candidates.length} candidatas · ${state}`;
  }
}
