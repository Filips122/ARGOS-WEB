/**
 * Corredor del modo sombra.
 *
 * Ingiere alertas reales desde el Indexer hacia el sidecar y registra los
 * veredictos. NO ejecuta ninguna accion: ni firewall, ni interfaz, ni nada que
 * salga de var/argos-scorer/verdicts.jsonl.
 *
 *   node --env-file=.env.local deploy/argos_scorer/shadow-run.ts
 *
 * Requiere el sidecar en marcha:
 *   .venv/Scripts/python.exe deploy/argos_scorer/service.py
 */

import path from 'path';
import { ScorerClient } from '../../lib/argos-scorer-client.ts';
import { ScorerIngestor, VerdictLedger, type TickResult } from '../../lib/scorer-ingest.ts';
import { Exclusions } from '../../lib/scorer-exclusions.ts';

const INTERVAL_MS = Number(process.env.ARGOS_SHADOW_INTERVAL_MS ?? 30_000);
const VAR_DIR = process.env.ARGOS_SCORER_STATE_DIR ?? path.join(process.cwd(), 'var', 'argos-scorer');

function stamp(): string {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

const totals = {
  ticks: 0, read: 0, accepted: 0, duplicates: 0, late: 0,
  verdicts: 0, newBlocks: 0, exclusionHits: 0, errors: 0,
};

function report(result: TickResult) {
  totals.ticks += 1;
  totals.read += result.read;
  totals.accepted += result.accepted;
  totals.duplicates += result.duplicates;
  totals.late += result.lateBehindCursor;
  totals.verdicts += result.verdicts;
  totals.newBlocks += result.newBlocks;
  totals.exclusionHits += result.exclusionHits.length;

  console.log(
    `[${stamp()}] leidas=${result.read} aceptadas=${result.accepted} ` +
      `dup=${result.duplicates} tarde=${result.lateBehindCursor} ` +
      `veredictos=${result.verdicts} nuevos=${result.newBlocks}` +
      (result.exhausted ? ' (al dia)' : ' (recuperando atraso)')
  );

  // Un veredicto sobre infraestructura propia es fallo grave: se destaca.
  for (const record of result.exclusionHits) {
    const banner = record.exclusion.severity === 'grave' ? '!!! FALLO GRAVE !!!' : '!!! EXCLUSION !!!';
    console.error(
      `\n${banner}\n` +
        `  IP ${record.ip} bloqueada con score ${record.score} en el aviso #${record.decided_at_alert}\n` +
        `  motivo de exclusion: ${record.exclusion.reason}\n` +
        `  estado de la entrada: ${record.exclusion.status}\n` +
        `  evidencia: ${JSON.stringify(record.evidence)}\n`
    );
  }
}

async function main() {
  const exclusions = Exclusions.load();
  const client = new ScorerClient();
  const ledger = new VerdictLedger(path.join(VAR_DIR, 'verdicts.jsonl'));
  const ingestor = new ScorerIngestor(client, ledger, exclusions);

  const health = await client.health().catch((error) => {
    console.error(
      `\nNo hay sidecar en ${process.env.ARGOS_SCORER_URL ?? 'http://127.0.0.1:8973'}: ${error.message}\n` +
        'Arrancalo con:  .venv/Scripts/python.exe deploy/argos_scorer/service.py\n'
    );
    process.exit(1);
  });

  console.log('='.repeat(72));
  console.log('MODO SOMBRA — sin acciones. Solo se escribe el registro de veredictos.');
  console.log('='.repeat(72));
  console.log(`  sidecar        : estado ${health.state_origin}, gen ${health.state_generation}, LRU ${health.lru_size}`);
  console.log(`  exclusiones    : ${exclusions.summary()}`);
  console.log(`  registro       : ${path.join(VAR_DIR, 'verdicts.jsonl')} (${ledger.size} IPs ya decididas)`);
  console.log(`  cadencia       : ${INTERVAL_MS / 1000}s`);

  if (exclusions.blocksPromotion) {
    console.log('');
    console.log('  AVISO: la lista de exclusion esta INCOMPLETA.');
    console.log(`         Falta: ${exclusions.config.missing.join(', ')}`);
    console.log('         La sombra corre igualmente (no ejecuta acciones y el registro');
    console.log('         es append-only), pero la PROMOCION A BLOQUEO REAL queda vetada.');
  }
  console.log('');

  let stopping = false;
  const stop = (signal: string) => {
    if (stopping) return;
    stopping = true;
    console.log(`\n[${stamp()}] ${signal}: parando.`);
    console.log(
      `  acumulado: ticks=${totals.ticks} leidas=${totals.read} aceptadas=${totals.accepted} ` +
        `dup=${totals.duplicates} tarde=${totals.late} veredictos=${totals.verdicts} ` +
        `IPs nuevas=${totals.newBlocks} exclusiones=${totals.exclusionHits} errores=${totals.errors}`
    );
    process.exit(0);
  };
  process.on('SIGINT', () => stop('SIGINT'));
  process.on('SIGTERM', () => stop('SIGTERM'));

  for (;;) {
    if (stopping) return;
    try {
      const result = await ingestor.tick();
      report(result);
      // Al dia: esperar. Con atraso: seguir inmediatamente para recuperarlo.
      if (result.exhausted) await new Promise((resolve) => setTimeout(resolve, INTERVAL_MS));
    } catch (error) {
      totals.errors += 1;
      console.error(`[${stamp()}] error: ${error instanceof Error ? error.message : String(error)}`);
      await new Promise((resolve) => setTimeout(resolve, INTERVAL_MS));
    }
  }
}

main().catch((error) => {
  console.error('fallo fatal:', error);
  process.exit(1);
});
