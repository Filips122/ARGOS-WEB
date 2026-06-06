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
        <LineChart title="Alertas vs IA por hora" data={timelineStats} />
        <HorizontalBars title="Top países origen" data={topCountries} />
      </div>

      <div className="chartGrid secondaryCharts">
        <RiskMatrix data={riskDistribution} />
        <HorizontalBars title="MITRE tactics" data={mitreStats} />
        <CorrelationSources data={correlationSources} />
      </div>
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

function LineChart({ title, data }: { title: string; data: { label: string; alerts: number; ai: number }[] }) {
  const max = Math.max(1, ...data.flatMap((item) => [item.alerts, item.ai]));
  const pointsAlerts = data.map((item, index) => `${(index / (data.length - 1)) * 100},${100 - (item.alerts / max) * 86}`).join(' ');
  const pointsAi = data.map((item, index) => `${(index / (data.length - 1)) * 100},${100 - (item.ai / max) * 86}`).join(' ');

  return (
    <article className="chartCard">
      <ChartTitle title={title} />
      <svg className="lineSvg" viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label={title}>
        <polyline points={pointsAlerts} className="lineAlerts" />
        <polyline points={pointsAi} className="lineAi" />
      </svg>
      <div className="lineLegend"><span>Total alerts</span><span>AI risk events</span></div>
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

function ChartTitle({ title }: { title: string }) {
  return (
    <div className="chartTitle">
      <h3>{title}</h3>
      <span>LIVE DATA</span>
    </div>
  );
}
