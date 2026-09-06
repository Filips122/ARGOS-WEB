import { agentHealth as mockAgentHealth, attacks as mockAttacks, type Attack } from '@/lib/mock-data';

export const regions = ['Europe', 'Asia', 'North America', 'South America', 'Africa', 'Oceania'] as const;
export type RegionFilter = typeof regions[number];

export function CommandSidebar({
  attacks = mockAttacks,
  agentHealth = mockAgentHealth,
  selectedRegions = regions,
  onToggleRegion,
}: {
  attacks?: Attack[];
  agentHealth?: typeof mockAgentHealth;
  selectedRegions?: readonly RegionFilter[];
  onToggleRegion?: (region: RegionFilter) => void;
}) {
  const selectedRegionSet = new Set(selectedRegions);
  // Antes mostraba 96/87/78/69 por posicion, numeros decorativos que parecian
  // una puntuacion de riesgo. Ahora es el recuento real de alertas por destino.
  const targetCounts = new Map<string, number>();
  for (const attack of attacks) {
    targetCounts.set(attack.target.name, (targetCounts.get(attack.target.name) ?? 0) + 1);
  }
  const topTargets = [...targetCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 4);

  return (
    <aside className="commandPanel sidebarPanel">
      <div className="miniModule sidebarMiniModule">
        <p className="eyebrow">TOP TARGETS</p>
        {topTargets.map(([target, count], index) => (
          <div className="targetRow" key={target}>
            <span>0{index + 1}</span>
            <b>{target}</b>
            <small>{count.toLocaleString('es-ES')} alertas</small>
          </div>
        ))}
      </div>

      <SectionTitle eyebrow="FILTER" title="Regions" />
      <div className="regionGrid">
        {regions.map((region) => {
          const active = selectedRegionSet.has(region);

          return (
            <button
              type="button"
              className={active ? 'active' : ''}
              aria-pressed={active}
              key={region}
              onClick={() => onToggleRegion?.(region)}
            >
              {region}
            </button>
          );
        })}
      </div>

      <SectionTitle eyebrow="SENSORS" title="Agent Health" />
      <div className="healthList">
        {agentHealth.map((agent) => (
          <div className="healthItem" key={agent.name}>
            <span className={`healthDot ${agent.status}`} />
            <div>
              <b>{agent.name}</b>
              <small>{agent.metric}</small>
            </div>
          </div>
        ))}
      </div>
    </aside>
  );
}

function SectionTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div className="sectionTitle">
      <span>{eyebrow}</span>
      <h2>{title}</h2>
    </div>
  );
}
