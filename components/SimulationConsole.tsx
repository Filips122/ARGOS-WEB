'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

type EvidenceKind = 'enumeracion' | 'lateral' | 'reputacion' | 'volumen';

type Verdict = {
  avisos_decisivos?: { aviso: number; alert_index: number | null }[];
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
  };
  excluded: boolean;
  exclusionStatus?: 'confirmed' | 'candidate';
  exclusionSeverity?: string;
  exclusionReason?: string;
};

type Payload = {
  ok: true;
  source: 'live' | 'file';
  fallbackReason: string | null;
  range: { from: string; to: string } | null;
  illustrativeOnly: boolean;
  stats: {
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
    agreement: AgreementReport;
  };
  policy: SimPolicy;
  verdicts: Verdict[];
  exclusions: { summary: string; complete: boolean; confirmedRules: number; candidateRules: number; hits: number };
};

type Failure = { ok: false; stage: string; error: string; hint?: string };

type SimPolicy = 'hgb' | 'attention' | 'or' | 'and';
type AgreementCell = 'both' | 'hgb_only' | 'attention_only' | 'none';
type AgreementReport = {
  matrix: Record<AgreementCell, number>;
  evaluated_ips: number;
  budgets: number[];
  by_agent: Record<string, Record<AgreementCell, number>>;
  disagreements: { ip: string; at_budget: number; agreement: AgreementCell; hgb: number; attention: number }[];
  note: string;
};

/**
 * Que modelo decide DENTRO del simulacro. Es un banco de pruebas: cambiarlo
 * aqui no cambia quien decide en la ingesta real, que es siempre el HGB, el
 * unico con validacion externa.
 */
const POLICY_LABEL: Record<SimPolicy, string> = {
  hgb: 'Principal (HGB)',
  attention: 'Transformer solo',
  or: 'Consenso OR',
  and: 'Consenso AND',
};

const POLICY_HINT: Record<SimPolicy, string> = {
  hgb: 'El modelo que decide hoy. Es el único con validación externa.',
  attention: 'Segunda opinión sola. Empata con el principal en test interno.',
  or: 'Bloquea si cualquiera cruza su umbral: más cobertura, menos precisión.',
  and: 'Bloquea solo si ambos cruzan: más precisión, menos cobertura.',
};

const AGREEMENT_LABEL: Record<AgreementCell, string> = {
  both: 'Ambos bloquearían',
  hgb_only: 'Solo el principal',
  attention_only: 'Solo el Transformer',
  none: 'Ninguno',
};

const SPEEDS = [1, 5, 20, 100] as const;

// La banda de promocion acordada en el plan de Fase 3.
const BAND = { min: 0.6, max: 0.85 };

const KIND_LABEL: Record<EvidenceKind, { short: string; help: string }> = {
  enumeracion: { short: 'ENUMERACIÓN', help: 'Probó dos o más cuentas distintas' },
  lateral: { short: 'ALCANCE LATERAL', help: 'Alcanzó dos o más máquinas' },
  reputacion: { short: 'REPUTACIÓN DE SUBRED', help: 'Sin evidencia propia: su /24 ya produjo hostiles' },
  volumen: { short: 'VOLUMEN', help: 'Ni cuentas ni máquinas múltiples ni subred marcada' },
};

function num(value: number) {
  return value.toLocaleString('es-ES');
}

function clock(iso: string) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toISOString().slice(11, 19);
}

export function SimulationConsole() {
  const [minutes, setMinutes] = useState(60);
  const [limit, setLimit] = useState(10000);
  const [order, setOrder] = useState<'cronologico' | 'impacto'>('cronologico');
  const [policy, setPolicy] = useState<SimPolicy>('hgb');
  const [data, setData] = useState<Payload | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [loading, setLoading] = useState(false);

  const [shown, setShown] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<(typeof SPEEDS)[number]>(20);
  const feedRef = useRef<HTMLDivElement>(null);

  const run = useCallback(async () => {
    setLoading(true);
    setFailure(null);
    setData(null);
    setShown(0);
    setPlaying(false);

    try {
      const response = await fetch(
        `/api/argos/simulation?minutes=${minutes}&limit=${limit}&policy=${policy}`,
        { cache: 'no-store' }
      );
      const json = (await response.json()) as Payload | Failure;
      if (!json.ok) setFailure(json);
      else {
        setData(json);
        setPlaying(true);
      }
    } catch (error) {
      setFailure({ ok: false, stage: 'red', error: error instanceof Error ? error.message : 'Error desconocido' });
    } finally {
      setLoading(false);
    }
  }, [minutes, limit, policy]);

  const verdicts = data?.verdicts ?? [];

  useEffect(() => {
    if (!playing || verdicts.length === 0) return;
    if (shown >= verdicts.length) {
      setPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => setShown((value) => value + 1), Math.max(1000 / speed, 16));
    return () => window.clearTimeout(timer);
  }, [playing, shown, speed, verdicts.length]);

  useEffect(() => {
    if (order === 'cronologico') feedRef.current?.scrollTo({ top: 0 });
  }, [shown, order]);

  const visible = useMemo(() => {
    const slice = verdicts.slice(0, shown);
    return order === 'impacto'
      ? [...slice].sort((a, b) => b.prevented_alerts - a.prevented_alerts)
      : [...slice].reverse();
  }, [verdicts, shown, order]);

  const preventedSoFar = useMemo(
    () => verdicts.slice(0, shown).reduce((sum, verdict) => sum + verdict.prevented_alerts, 0),
    [verdicts, shown]
  );

  const stats = data?.stats;
  const inBand = stats ? stats.block_rate >= BAND.min && stats.block_rate <= BAND.max : false;

  return (
    <div className="simWrap">
      <header className="simHeader">
        <div>
          <p className="eyebrow">SIMULACRO · NO EJECUTA NINGUNA ACCIÓN</p>
          <h1>Bloqueo temprano de IPs</h1>
          <p className="simLede">
            Reproduce alertas reales contra los modelos del TFM y muestra a quién habría bloqueado,
            en qué aviso y con qué evidencia. Ningún firewall se toca; Wazuh solo se lee.
          </p>
        </div>

        <div className="simControls">
          <label>
            <span>Ventana</span>
            <select value={minutes} onChange={(event) => setMinutes(Number(event.target.value))} disabled={loading}>
              <option value={15}>15 min</option>
              <option value={60}>1 hora</option>
              <option value={360}>6 horas</option>
              <option value={1440}>24 horas</option>
            </select>
          </label>
          <label>
            <span>Alertas</span>
            <select value={limit} onChange={(event) => setLimit(Number(event.target.value))} disabled={loading}>
              <option value={1000}>1.000</option>
              <option value={3000}>3.000</option>
              <option value={6000}>6.000</option>
              <option value={10000}>10.000</option>
            </select>
          </label>
          <label>
            <span>Decide</span>
            <select
              value={policy}
              onChange={(event) => setPolicy(event.target.value as SimPolicy)}
              disabled={loading}
              title={POLICY_HINT[policy]}
            >
              {(Object.keys(POLICY_LABEL) as SimPolicy[]).map((item) => (
                <option key={item} value={item}>{POLICY_LABEL[item]}</option>
              ))}
            </select>
          </label>
          <button type="button" className="simRun" onClick={run} disabled={loading}>
            {loading ? 'EJECUTANDO…' : 'EJECUTAR SIMULACRO'}
          </button>
        </div>
      </header>

      {failure && (
        <div className="simAlert simAlertBad">
          <b>No se pudo ejecutar ({failure.stage})</b>
          <p>{failure.error}</p>
          {failure.hint && <p className="simHint">{failure.hint}</p>}
        </div>
      )}

      {data && stats && (
        <>
          <div className="simBanners">
            <span className={`simBadge ${data.source === 'live' ? 'live' : 'file'}`}>
              {data.source === 'live' ? 'DATOS FRESCOS DE WAZUH' : 'RESPALDO · FICHERO DE 30 DÍAS'}
            </span>
            {data.range && (
              <span className="simRange">
                {data.range.from.slice(0, 19).replace('T', ' ')} → {data.range.to.slice(0, 19).replace('T', ' ')}
              </span>
            )}
          </div>

          {/* El resultado de seguridad se afirma, no se deduce del silencio. */}
          <div className={`simAlert ${data.exclusions.hits === 0 ? 'simAlertOk' : 'simAlertBad'}`}>
            <b>
              {data.exclusions.hits === 0
                ? `✓ Ningún veredicto sobre infraestructura propia (${data.exclusions.confirmedRules} reglas confirmadas)`
                : `FALLO GRAVE · ${data.exclusions.hits} veredicto(s) sobre infraestructura propia`}
            </b>
            {data.exclusions.hits === 0 ? (
              <p>
                Primer criterio de promoción, superado en esta ejecución. Rangos no enrutables, agentes
                propios, honeypot e indexer comprobados contra cada IP bloqueada.
                {!data.exclusions.complete && ' Lista aún incompleta: la promoción a bloqueo real sigue vetada.'}
              </p>
            ) : (
              verdicts
                .filter((verdict) => verdict.excluded)
                .map((verdict) => (
                  <p key={verdict.ip}>
                    {verdict.ip} — {verdict.exclusionReason}
                  </p>
                ))
            )}
          </div>

          {data.fallbackReason && (
            <div className="simAlert simAlertWarn">
              <b>Wazuh no respondió; se usó el respaldo local</b>
              <p>{data.fallbackReason}</p>
            </div>
          )}

          {data.illustrativeOnly && (
            <div className="simAlert simAlertWarn">
              <b>Cifras ilustrativas, no métrica de rendimiento</b>
              <p>
                El fichero de 30 días es el periodo con el que se entrenaron estos modelos. Sirve para
                enseñar el mecanismo; para medir haría falta tráfico que los modelos no hayan visto.
              </p>
            </div>
          )}

          <div className="simStats">
            <Stat label="Alertas reproducidas" value={num(stats.total_alerts)} />
            <Stat label="IPs con origen de red" value={num(stats.ips_with_network_origin)} />
            <Stat label="Bloqueadas" value={num(stats.blocked)} tone="danger" />
            <Stat
              label="Tasa de bloqueo"
              value={`${(stats.block_rate * 100).toFixed(1)} %`}
              foot={inBand ? 'dentro de la banda 60-85 %' : 'FUERA de la banda 60-85 %'}
              tone={inBand ? 'ok' : 'warn'}
            />
            <Stat label="Mediana de corte" value={`aviso ${stats.median_cut ?? '—'}`} foot="referencia: aviso 5" />
            <Stat label="Alertas suprimidas" value={num(stats.prevented_alerts)} tone="ok" />
            <Stat label="Del volumen total" value={`${(stats.prevented_ratio * 100).toFixed(0)} %`} tone="ok" />
          </div>

          {/* Desglose obligatorio: el agregado sin reparto por grupo es
              exactamente el error que el §4.3 del paquete obliga a evitar. */}
          <section className="simBreakdown">
            <div className="simBreakCard">
              <p className="eyebrow">DESGLOSE · POR QUÉ NO BASTA EL PORCENTAJE</p>
              <p className="simBreakLede">
                El {(stats.prevented_ratio * 100).toFixed(0)} % es un agregado, y los agregados esconden
                concentración. Aquí está el reparto real.
              </p>
              <div className="simBreakRow">
                <b>{(stats.concentration.top3_share * 100).toFixed(0)} %</b>
                <span>de lo suprimido lo aportan solo 3 IPs</span>
              </div>
              <div className="simBreakRow">
                <b>{num(stats.concentration.median_prevented_per_ip)}</b>
                <span>mediana de alertas suprimidas por IP (máx. {num(stats.concentration.max_prevented)})</span>
              </div>
              <div className="simBreakRow">
                <b>{stats.concentration.zero_effect_blocks}</b>
                <span>bloqueos sin efecto medible en esta ventana</span>
              </div>
              <ol className="simTop">
                {stats.concentration.top_contributors.map((item) => (
                  <li key={item.ip}>
                    <code>{item.ip}</code>
                    <span>{num(item.prevented_alerts)} suprimidas</span>
                    <small>aviso #{item.decided_at_alert}</small>
                  </li>
                ))}
              </ol>
            </div>

            <div className="simBreakCard">
              <p className="eyebrow">ACUERDO ENTRE LOS DOS MODELOS</p>
              <p className="simBreakLede">
                {stats.agreement.evaluated_ips > 0 ? (
                  <>
                    Sobre {num(stats.agreement.evaluated_ips)} IPs con 2 o más avisos, que es donde el
                    Transformer opina. Presupuestos {stats.agreement.budgets.join(', ')}.
                  </>
                ) : (
                  'Ninguna IP alcanzó dos avisos en esta ventana: el Transformer no llega a opinar.'
                )}
              </p>
              {(Object.keys(AGREEMENT_LABEL) as AgreementCell[]).map((cell) => {
                const value = stats.agreement.matrix[cell] ?? 0;
                const total = stats.agreement.evaluated_ips || 1;
                return (
                  <div className="simBreakRow" key={cell}>
                    <b>{num(value)}</b>
                    <span>
                      {AGREEMENT_LABEL[cell]} · {((value / total) * 100).toFixed(0)} %
                    </span>
                  </div>
                );
              })}

              {/* La convencion obliga a desglosar todo agregado. Una IP que
                  alcanza varias maquinas cuenta en cada una, asi que las filas
                  suman mas que el total: es un reparto, no una particion. */}
              {Object.keys(stats.agreement.by_agent).length > 0 && (
                <>
                  <p className="simBreakLede simAgreeSub">
                    Por agente destino. Una IP que alcanza varias máquinas cuenta en cada una, así que
                    las filas suman más que el total.
                  </p>
                  <ol className="simTop">
                    {Object.entries(stats.agreement.by_agent)
                      .sort((a, b) => {
                        const sum = (row: Record<AgreementCell, number>) =>
                          row.both + row.hgb_only + row.attention_only + row.none;
                        return sum(b[1]) - sum(a[1]);
                      })
                      .slice(0, 5)
                      .map(([agent, row]) => (
                        <li key={agent}>
                          <code>{agent}</code>
                          <span>
                            {row.both} ambos · {row.hgb_only} solo principal · {row.attention_only} solo Transformer
                          </span>
                        </li>
                      ))}
                  </ol>
                </>
              )}

              {stats.agreement.disagreements.length > 0 && (
                <>
                  <p className="simBreakLede simAgreeSub">Mayores discrepancias:</p>
                  <ol className="simTop">
                    {stats.agreement.disagreements.slice(0, 3).map((item) => (
                      <li key={item.ip}>
                        <code>{item.ip}</code>
                        <span>
                          principal {Math.round(item.hgb * 100)} · Transformer {Math.round(item.attention * 100)}
                        </span>
                        <small>K={item.at_budget}</small>
                      </li>
                    ))}
                  </ol>
                </>
              )}

              <p className="simAgreeNote">
                Test interno, sin validación externa. El Transformer <b>no decide</b>: en la ingesta
                real bloquea siempre el modelo principal. Esta matriz existe para medir el acuerdo
                sobre tráfico real, que es la única validación que le queda.
              </p>
            </div>

            <div className="simBreakCard">
              <p className="eyebrow">CALIDAD DE LAS DECISIONES</p>
              <p className="simBreakLede">
                Qué evidencia acompaña a cada bloqueo y cuánto margen tuvo sobre su umbral.
              </p>
              <div className="simKinds">
                {(Object.keys(KIND_LABEL) as EvidenceKind[]).map((kind) => {
                  const count = stats.evidence_kinds[kind] ?? 0;
                  if (count === 0) return null;
                  return (
                    <div className={`simKind k-${kind}`} key={kind} title={KIND_LABEL[kind].help}>
                      <b>{count}</b>
                      <span>{KIND_LABEL[kind].short}</span>
                      <small>{KIND_LABEL[kind].help}</small>
                    </div>
                  );
                })}
              </div>
              <div className="simBreakRow">
                <b>{stats.margins.tight_count} / {stats.blocked}</b>
                <span>decisiones con margen &lt; {stats.margins.tight_threshold} sobre el umbral</span>
              </div>
              <div className="simBreakRow">
                <b>{stats.margins.min ?? '—'}</b>
                <span>margen más fino (mediana {stats.margins.median ?? '—'})</span>
              </div>
              <p className="simCaveat">
                <b>Sesgo de ventana:</b> {stats.censoring.censored} de las {stats.censoring.unblocked} IPs
                sin bloquear no llegaron a acumular {stats.censoring.last_budget} avisos. No se puede
                afirmar que sean benignas: la ventana terminó antes. La tasa de bloqueo está sesgada a la baja.
              </p>
            </div>
          </section>

          <div className="simPlayer">
            <button type="button" onClick={() => setPlaying((value) => !value)} disabled={verdicts.length === 0}>
              {playing ? '❚❚ PAUSA' : '▶ REPRODUCIR'}
            </button>
            <button type="button" onClick={() => { setShown(0); setPlaying(true); }} disabled={verdicts.length === 0}>
              ↻ REINICIAR
            </button>
            <div className="simSpeeds">
              {SPEEDS.map((value) => (
                <button type="button" key={value} className={speed === value ? 'active' : ''} onClick={() => setSpeed(value)}>
                  ×{value}
                </button>
              ))}
            </div>
            <div className="simSpeeds simOrder">
              <button type="button" className={order === 'cronologico' ? 'active' : ''} onClick={() => setOrder('cronologico')}>
                CRONOLÓGICO
              </button>
              <button type="button" className={order === 'impacto' ? 'active' : ''} onClick={() => setOrder('impacto')}>
                POR IMPACTO
              </button>
            </div>
            <div className="simProgress">
              <div className="simProgressBar" style={{ width: `${(shown / Math.max(verdicts.length, 1)) * 100}%` }} />
            </div>
            <span className="simCounter">
              {num(shown)} / {num(verdicts.length)} · {num(preventedSoFar)} suprimidas
            </span>
          </div>

          <div className="simFeed" ref={feedRef}>
            {visible.length === 0 && <p className="simEmpty">Pulsa reproducir para ver los veredictos en orden.</p>}
            {visible.map((verdict) => {
              const tight = verdict.margin < stats.margins.tight_threshold;
              return (
                <article
                  key={`${verdict.ip}-${verdict.alert_index}`}
                  className={`simCard${verdict.excluded ? ' excluded' : ''}${tight ? ' tight' : ''}`}
                >
                  <div className="simCardTop">
                    <b>{verdict.ip}</b>
                    <span className="simCut">aviso #{verdict.decided_at_alert}</span>
                    <span className={`simKindTag k-${verdict.evidence_kind}`} title={KIND_LABEL[verdict.evidence_kind].help}>
                      {KIND_LABEL[verdict.evidence_kind].short}
                    </span>
                    <span className="simScore">{verdict.score.toFixed(3)}</span>
                  </div>
                  <div className="simEvidence">
                    <span>{verdict.evidence.usuarios_probados} cuenta(s) probada(s)</span>
                    <span>{verdict.evidence.maquinas_alcanzadas} máquina(s)</span>
                    <span>subred /24 hostil {(verdict.evidence.reputacion_subred_24 * 100).toFixed(0)} %</span>
                    <span className={verdict.prevented_alerts === 0 ? 'simNoEffect' : 'simPrevented'}>
                      {verdict.prevented_alerts === 0
                        ? 'no suprimió nada en la ventana'
                        : `${num(verdict.prevented_alerts)} alertas suprimidas`}
                    </span>
                  </div>
                  <div className="simCardFoot">
                    <span>{clock(verdict.timestamp)}</span>
                    <span>umbral {verdict.threshold.toFixed(3)}</span>
                    <span className={tight ? 'simTightTag' : ''}>
                      margen {verdict.margin >= 0 ? '+' : ''}{verdict.margin.toFixed(4)}
                      {tight ? ' · AJUSTADA' : ''}
                    </span>
                    {verdict.excluded && <span className="simExcluded">EXCLUIDA · {verdict.exclusionReason}</span>}
                  </div>
                  {/* Que avisos pesaron, enlazados con su alerta en el lote
                      reproducido. Solo lo da el Transformer. */}
                  {verdict.avisos_decisivos && verdict.avisos_decisivos.length > 0 && (
                    <div className="simDecisive">
                      <span>avisos decisivos</span>
                      {verdict.avisos_decisivos.map((item) => (
                        <b key={item.aviso} title={item.alert_index === null ? 'fuera del lote' : `alerta #${item.alert_index}`}>
                          #{item.aviso}
                          {item.alert_index !== null && <i>→ {item.alert_index}</i>}
                        </b>
                      ))}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        </>
      )}

      {!data && !failure && !loading && (
        <p className="simEmpty">
          Elige una ventana y ejecuta. Se intentan datos frescos de Wazuh; si el servicio no responde,
          se usa automáticamente el fichero exportado de 30 días.
        </p>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  foot,
  tone,
}: {
  label: string;
  value: string;
  foot?: string;
  tone?: 'ok' | 'danger' | 'warn';
}) {
  return (
    <div className={`simStat${tone ? ` ${tone}` : ''}`}>
      <b>{value}</b>
      <span>{label}</span>
      {foot && <small>{foot}</small>}
    </div>
  );
}
