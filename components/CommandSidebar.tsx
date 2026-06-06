import { agentHealth as mockAgentHealth } from '@/lib/mock-data';

const layers = ['Wazuh Alerts', 'GeoIP Origins', 'AI Risk Score', 'Agent Targets'];
export const regions = ['Europe', 'Asia', 'North America', 'South America', 'Africa', 'Oceania'] as const;
export type RegionFilter = typeof regions[number];

export function CommandSidebar({
  agentHealth = mockAgentHealth,
  selectedRegions = regions,
  onToggleRegion,
}: {
  agentHealth?: typeof mockAgentHealth;
  selectedRegions?: readonly RegionFilter[];
  onToggleRegion?: (region: RegionFilter) => void;
}) {
  const selectedRegionSet = new Set(selectedRegions);

  return (
    <aside className="commandPanel sidebarPanel">
      <SectionTitle eyebrow="CONTROL" title="Operational Layers" />
      <div className="layerList">
        {layers.map((layer) => (
          <label className="layerItem" key={layer}>
            <input type="checkbox" defaultChecked />
            <span>{layer}</span>
          </label>
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
