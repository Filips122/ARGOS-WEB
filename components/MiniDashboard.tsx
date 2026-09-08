'use client';

import { useState } from 'react';
import {
  attackTypeStats as mockAttackTypeStats,
  kpis as mockKpis,
  mitreStats as mockMitreStats,
  severityStats as mockSeverityStats,
  timelineStats as mockTimelineStats,
  topCountries as mockTopCountries,
} from '@/lib/mock-data';
import type { ArgosLiveData } from '@/lib/argos-normalizers';

export function MiniDashboard({
  kpis = mockKpis,
  charts,
  mode = 'demo',
}: {
  kpis?: typeof mockKpis;
  charts?: ArgosLiveData['charts'];
  mode?: 'live' | 'partial' | 'demo';
}) {
  const attackTypeStats = charts?.attacksByType ?? mockAttackTypeStats;
  const severityStats = charts?.severityDistribution ?? mockSeverityStats;
  const timelineStats = charts?.alertsTimeline ?? mockTimelineStats;
  const topCountries = charts?.topCountries ?? mockTopCountries;
  const mitreStats = charts?.mitreTactics ?? mockMitreStats;
  const riskDistribution = charts?.riskDistribution;
  const correlationSources = charts?.correlationSources;
  const criminalIntelligence = charts?.criminalIntelligence;
  const vulnerabilityIntelligence = charts?.vulnerabilityIntelligence;

  return (
    <section className="dashboardDeck">
      <div className="dashboardHeader">
        <div>
          <p className="eyebrow">ANALYTICS LAYER</p>
          <h2>SOC Intelligence Dashboard</h2>
        </div>
        <p>Resumen táctico para priorización de alertas, anomalías IA y cobertura de agentes.</p>
      </div>

      <div className="kpiGrid">
        {kpis.map((kpi) => <KpiCard key={kpi.label} {...kpi} />)}
      </div>

      <div className="chartGrid primaryCharts">
        <BarChart title="Ataques por tipo" data={attackTypeStats} />
        <DonutChart title="Distribución por severidad" data={severityStats} />
        <StackedTimeline title="Volumen por tramo y cuánto viene de IPs peligrosas" data={timelineStats} />
        <HorizontalBars title="Top países origen" data={topCountries} />
      </div>

      <div className="chartGrid secondaryCharts">
        <RiskMatrix data={riskDistribution} />
        <HorizontalBars title="MITRE tactics" data={mitreStats} />
        <CorrelationSources data={correlationSources} />
      </div>

      <VulnerabilityIntelligence data={vulnerabilityIntelligence} />

      <CriminalIntelligenceDashboard data={criminalIntelligence} />
    </section>
  );
}

function KpiCard({ label, value, trend, tone }: { label: string; value: string; trend: string; tone: string }) {
  return (
    <article className={`kpiCard ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{trend}</small>
    </article>
  );
}

function BarChart({ title, data }: { title: string; data: { label: string; value: number }[] }) {
  const max = Math.max(1, ...data.map((item) => item.value));
  return (
    <article className="chartCard">
      <ChartTitle title={title} />
      <div className="barChart">
        {data.map((item) => (
          <div className="barColumn" key={item.label}>
            <div className="barTrack">
              <div className="barFill" style={{ height: `${Math.max(12, (item.value / max) * 100)}%` }} />
            </div>
            <small title={item.label}>{item.label}</small>
          </div>
        ))}
      </div>
    </article>
  );
}

function HorizontalBars({ title, data }: { title: string; data: { label: string; value: number }[] }) {
  const max = Math.max(1, ...data.map((item) => item.value));
  return (
    <article className="chartCard">
      <ChartTitle title={title} />
      <div className="horizontalBars">
        {data.map((item) => (
          <div className="hBarRow" key={item.label}>
            <span>{item.label}</span>
            <div><i style={{ width: `${(item.value / max) * 100}%` }} /></div>
            <b>{item.value}</b>
          </div>
        ))}
      </div>
    </article>
  );
}

function DonutChart({ title, data }: { title: string; data: { label: string; value: number; color: string }[] }) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  let cursor = 0;
  const gradient = data.map((item) => {
    const start = cursor;
    const end = total > 0 ? cursor + (item.value / total) * 100 : cursor;
    cursor = end;
    return `${item.color} ${start}% ${end}%`;
  }).join(', ');

  return (
    <article className="chartCard donutCard">
      <ChartTitle title={title} />
      <div className="donutWrap">
        <div className="donut" style={{ background: `conic-gradient(${gradient})` }}>
          <span>{total}</span>
          <small>alertas</small>
        </div>
        <div className="legendList">
          {data.map((item) => (
            <div key={item.label}><i style={{ background: item.color }} />{item.label}<b>{item.value}</b></div>
          ))}
        </div>
      </div>
    </article>
  );
}

type TimelineBucket = { label: string; alerts: number; ai: number; ips?: number };

/**
 * Volumen por tramo de 3 h, con la parte que viene de IPs peligrosas.
 *
 * Antes eran dos líneas: alertas y alertas con score de ventana >= 70. Ese
 * umbral lo cruzaba el 100 % de las alertas, así que las dos líneas caían una
 * encima de otra y la gráfica no decía nada. Además una línea interpola entre
 * tramos —dibuja una pendiente entre las 12h y las 15h como si hubiera algo en
 * medio— y con tramos vacíos trazaba caídas suaves a cero que sugerían un
 * descenso gradual que no ocurrió: simplemente esas alertas ya no están
 * cargadas.
 *
 * Ahora es una columna apilada por tramo. Misma unidad, y una serie es
 * subconjunto de la otra: eso es parte-de-un-todo, que se apila, no dos barras
 * al lado. El segmento destacado son las alertas cuya IP tiene riesgo >= 0,9,
 * que sí varía (medido: del 53 % al 91 %) y separa un pico de volumen de un
 * pico de peligro.
 *
 * Forma «énfasis»: un color para lo que importa, gris para el resto.
 */
function StackedTimeline({ title, data }: { title: string; data: TimelineBucket[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...data.map((item) => item.alerts));
  const totalAlerts = data.reduce((sum, item) => sum + item.alerts, 0);
  const totalRisk = data.reduce((sum, item) => sum + item.ai, 0);
  // El tramo con mayor proporción de riesgo: es el único valor que se etiqueta
  // directamente. Una cifra sobre cada columna sería ruido y no se lee.
  const peak = data.reduce(
    (best, item, index) =>
      item.alerts > 0 && item.ai / item.alerts > best.ratio ? { index, ratio: item.ai / item.alerts } : best,
    { index: -1, ratio: 0 }
  );

  return (
    <article className="chartCard">
      <ChartTitle title={title} />
      <div className="stackChart" role="img" aria-label={`${title}. ${totalAlerts} alertas, ${totalRisk} de IPs con riesgo alto.`}>
        {data.map((item, index) => {
          const share = item.alerts > 0 ? item.ai / item.alerts : 0;
          const height = (item.alerts / max) * 100;
          const riskHeight = item.alerts > 0 ? (item.ai / item.alerts) * 100 : 0;
          return (
            <div
              className={`stackCol${hover === index ? ' on' : ''}`}
              key={item.label}
              onMouseEnter={() => setHover(index)}
              onMouseLeave={() => setHover(null)}
              onFocus={() => setHover(index)}
              onBlur={() => setHover(null)}
              tabIndex={0}
            >
              <div className="stackPlot">
                {index === peak.index && item.alerts > 0 && (
                  <span className="stackPeak" style={{ bottom: `${height}%` }}>
                    {Math.round(share * 100)} %
                  </span>
                )}
                <div className="stackBar" style={{ height: `${height}%` }}>
                  <i className="stackRest" />
                  <i className="stackRisk" style={{ height: `${riskHeight}%` }} />
                </div>
                {hover === index && (
                  <div className="stackTip" role="tooltip">
                    <b>{item.label}</b>
                    <span>{item.alerts.toLocaleString('es-ES')} alertas</span>
                    <span>
                      {item.ai.toLocaleString('es-ES')} de IPs con riesgo alto ({Math.round(share * 100)} %)
                    </span>
                    {item.ips !== undefined && <span>{item.ips} IP(s) distintas</span>}
                  </div>
                )}
              </div>
              <small>{item.label}</small>
            </div>
          );
        })}
      </div>
      <div className="stackLegend">
        <span><i className="swRisk" />De IPs con riesgo ≥ 0,9</span>
        <span><i className="swRest" />Resto</span>
      </div>
    </article>
  );
}

function RiskMatrix({ data }: { data?: ArgosLiveData['charts']['riskDistribution'] }) {
  const [selectedRange, setSelectedRange] = useState<ArgosLiveData['charts']['riskDistribution'][number] | null>(null);
  const cells = data?.length ? data : buildFallbackRiskBuckets();

  return (
    <article className="chartCard riskCard">
      <ChartTitle title="AI risk distribution" />
      <div className="riskGrid">
        {cells.map((bucket) => (
          <button
            type="button"
            key={bucket.label}
            className={bucket.tone}
            onClick={() => setSelectedRange(bucket)}
          >
            <span>{bucket.label}</span>
            <b>{bucket.count}</b>
          </button>
        ))}
      </div>
      {selectedRange && (
        <div className="riskPopover" role="dialog" aria-label={`Detalle AI risk ${selectedRange.label}`}>
          <div className="riskPopoverHeader">
            <div>
              <span>AI RISK {selectedRange.label}</span>
              <b>{selectedRange.count.toLocaleString('es-ES')} alertas</b>
            </div>
            <button type="button" onClick={() => setSelectedRange(null)} aria-label="Cerrar detalle AI Risk">x</button>
          </div>
          <div className="riskScoreList">
            {selectedRange.scores.length > 0 ? selectedRange.scores.map((item) => (
              <div key={item.score}>
                <span>Score {item.score}</span>
                <b>{item.count.toLocaleString('es-ES')}</b>
              </div>
            )) : (
              <p>No hay alertas en este rango.</p>
            )}
          </div>
        </div>
      )}
    </article>
  );
}

function buildFallbackRiskBuckets(): ArgosLiveData['charts']['riskDistribution'] {
  const scores = [54, 67, 73, 81, 85, 88, 93, 96];
  return Array.from({ length: 8 }, (_, index) => {
    const min = index * 12.5;
    const max = min + 12.5;
    const scoreCounts = scores
      .filter((score) => score >= min && (index === 7 ? score <= max : score < max))
      .map((score) => ({ score, count: 1 }));

    return {
      label: `${min}-${max}`,
      min,
      max,
      count: scoreCounts.reduce((sum, item) => sum + item.count, 0),
      tone: max > 87.5 ? 'critical' : max > 75 ? 'high' : max > 50 ? 'medium' : 'low',
      scores: scoreCounts,
    };
  });
}

function CorrelationSources({ data }: { data?: { label: string; value: number }[] }) {
  const sources = data?.length ? data : [
    { label: 'Wazuh + IA', value: 34 },
    { label: 'Suricata + IA', value: 28 },
    { label: 'Zeek + IA', value: 16 },
    { label: 'All combined', value: 22 },
  ];
  return <HorizontalBars title="Correlación por fuente" data={sources} />;
}

/**
 * Explotacion real de vulnerabilidades. No sustituye a la severidad de Wazuh:
 * la contrasta. Medido sobre 30 dias de este despliegue, el 99,9 % de las
 * alertas CRITICAL son hallazgos de Trivy y ninguno de sus 28 CVE marcados
 * CRITICAL figura en el catalogo de explotacion activa de CISA.
 */
function VulnerabilityIntelligence({ data }: { data?: ArgosLiveData['charts']['vulnerabilityIntelligence'] }) {
  if (!data) return null;

  if (!data.available) {
    return (
      <section className="vulnDeck" aria-label="Explotacion real de vulnerabilidades">
        <div className="dashboardHeader vulnHeader">
          <div>
            <p className="eyebrow">CISA KEV + EPSS</p>
            <h2>Explotación real</h2>
          </div>
          <p>Catálogos no disponibles: sin conexión para descargar KEV/EPSS. El resto del panel no se ve afectado.</p>
        </div>
      </section>
    );
  }

  const { contrast } = data;
  const noise = data.distinctCves - data.actionableCves;

  return (
    <section className="vulnDeck" aria-label="Explotacion real de vulnerabilidades">
      <div className="dashboardHeader vulnHeader">
        <div>
          <p className="eyebrow">CISA KEV + EPSS</p>
          <h2>Explotación real</h2>
        </div>
        <p>
          Contraste de la severidad declarada frente a explotación observada.
          Catálogo KEV {data.kevVersion ?? '—'}. No modifica la severidad de Wazuh.
        </p>
      </div>

      <div className="criminalKpiGrid">
        <KpiCard label="CVE detectados" value={String(data.distinctCves)} trend={`${data.alertsWithCve} alertas`} tone="ai" />
        <KpiCard label="Explotados (KEV)" value={String(data.exploitedCves)} trend="explotación confirmada" tone="critical" />
        <KpiCard label="Accionables" value={String(data.actionableCves)} trend="KEV o EPSS ≥ 0,1" tone="high" />
        <KpiCard
          label="Ruido de inventario"
          value={String(noise)}
          trend={data.noiseReductionFactor ? `cola reducida ×${data.noiseReductionFactor}` : 'sin accionables'}
          tone="ok"
        />
      </div>

      {contrast.criticalAlerts > 0 && (
        <div className="vulnContrast">
          <p className="eyebrow">SEVERIDAD DECLARADA FRENTE A EXPLOTACIÓN</p>
          <div className="vulnContrastRow">
            <b>{contrast.criticalAlerts}</b>
            <span>alertas marcadas CRITICAL por el nivel de regla de Wazuh</span>
          </div>
          <div className="vulnContrastRow">
            <b>{contrast.criticalFromVulnScan}</b>
            <span>de ellas son hallazgos de escáner de vulnerabilidades, no ataques en curso</span>
          </div>
          <div className="vulnContrastRow strong">
            <b>{contrast.criticalActuallyExploited}</b>
            <span>corresponden a CVE con explotación real conocida</span>
          </div>
        </div>
      )}

      <div className="chartGrid criminalCharts">
        <HorizontalBars title="Reparto por explotación" data={data.severityVsExploitation} />
        <TopExploitedCves data={data.topExploited} />
      </div>
    </section>
  );
}

function TopExploitedCves({ data }: { data: ArgosLiveData['charts']['vulnerabilityIntelligence']['topExploited'] }) {
  return (
    <article className="chartCard">
      <ChartTitle title="Prioridad real de parcheo" />
      {data.length === 0 ? (
        <p className="vulnEmpty">Ningún CVE accionable en las alertas cargadas.</p>
      ) : (
        <ul className="vulnList">
          {data.map((item) => (
            <li key={item.cve}>
              <code>{item.cve}</code>
              {item.inKev && <span className="vulnKev">KEV</span>}
              <small>{item.epss === null ? 'EPSS < 0,02' : `EPSS ${item.epss.toFixed(3)}`}</small>
              <b>{item.alerts}</b>
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function CriminalIntelligenceDashboard({ data }: { data?: ArgosLiveData['charts']['criminalIntelligence'] }) {
  const fallback = data ?? {
    enabled: false,
    minAlertsPerIp: 10,
    cacheTtlHours: 24,
    overview: {
      publicIps: 0,
      eligibleIps: 0,
      checkedIps: 0,
      cachedIps: 0,
      highRiskIps: 0,
      maliciousAlerts: 0,
      privateAlerts: 0,
      belowThresholdAlerts: 0,
      rateLimitedAlerts: 0,
    },
    reputationBuckets: [
      { label: '0-39', value: 0, color: '#38f8d4' },
      { label: '40-79', value: 0, color: '#ffd166' },
      { label: '80-100', value: 0, color: '#ff2f5f' },
      { label: 'Unknown', value: 0, color: '#7ea8b8' },
    ],
    topReportedIps: [],
    statusBreakdown: [],
  };
  const statusRows = fallback.statusBreakdown.length
    ? fallback.statusBreakdown
    : [{ label: fallback.enabled ? 'Waiting for repeated IPs' : 'API key missing', value: 0 }];

  return (
    <section className="criminalDeck" aria-label="Criminal Intelligence Dashboard">
      <div className="dashboardHeader criminalHeader">
        <div>
          <p className="eyebrow">ABUSEIPDB ENRICHMENT</p>
          <h2>Criminal Intelligence Dashboard</h2>
        </div>
        <p>
          IPs publicas consultadas solo cuando se repiten al menos {fallback.minAlertsPerIp} veces.
          Cache local: {fallback.cacheTtlHours}h.
        </p>
      </div>

      <div className="criminalKpiGrid">
        <KpiCard label="Eligible IPs" value={String(fallback.overview.eligibleIps)} trend="publicas repetidas" tone="ai" />
        <KpiCard label="Checked IPs" value={String(fallback.overview.checkedIps)} trend={`${fallback.overview.cachedIps} desde cache`} tone="ok" />
        <KpiCard label="High Risk IPs" value={String(fallback.overview.highRiskIps)} trend="score >= 80" tone="critical" />
        <KpiCard label="Flagged Alerts" value={String(fallback.overview.maliciousAlerts)} trend="en alertas cargadas" tone="high" />
      </div>

      <div className="chartGrid criminalCharts">
        <DonutChart title="AbuseIPDB reputation" data={fallback.reputationBuckets} />
        <HorizontalBars title="Lookup status" data={statusRows} />
        <TopReportedIps data={fallback.topReportedIps} enabled={fallback.enabled} rateLimitedUntil={fallback.rateLimitedUntil} />
      </div>
    </section>
  );
}

function TopReportedIps({
  data,
  enabled,
  rateLimitedUntil,
}: {
  data: { label: string; value: number; meta: string }[];
  enabled: boolean;
  rateLimitedUntil?: string;
}) {
  return (
    <article className="chartCard criminalIpsCard">
      <ChartTitle title="Top reported IPs" />
      <div className="criminalIpList">
        {data.length > 0 ? data.map((item) => (
          <div className="criminalIpRow" key={item.label}>
            <div>
              <b>{item.label}</b>
              <span>{item.meta}</span>
            </div>
            <strong>{item.value}</strong>
          </div>
        )) : (
          <p>
            {enabled
              ? 'Sin IPs publicas repetidas suficientes para consultar.'
              : 'Configura ABUSEIPDB_API_KEY para activar el enriquecimiento.'}
          </p>
        )}
      </div>
      {rateLimitedUntil && <small className="rateLimitNotice">Rate limited hasta {new Date(rateLimitedUntil).toLocaleString('es-ES')}</small>}
    </article>
  );
}

function ChartTitle({ title }: { title: string }) {
  return (
    <div className="chartTitle">
      <h3>{title}</h3>
      <span>LIVE DATA</span>
    </div>
  );
}
