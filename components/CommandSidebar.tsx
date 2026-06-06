import { agentHealth as mockAgentHealth } from '@/lib/mock-data';

const layers = ['Wazuh Alerts', 'Suricata IDS', 'Zeek Flows', 'MCP Agents', 'AI Anomalies', 'IPS Blocks'];
const regions = ['Europe', 'Asia', 'North America', 'South America', 'Africa', 'Oceania'];

export function CommandSidebar({ agentHealth = mockAgentHealth }: { agentHealth?: typeof mockAgentHealth }) {
  return (
    <aside className="commandPanel sidebarPanel">
      <SectionTitle eyebrow="CONTROL" title="Operational Layers" />
      <div className="layerList">
        {layers.map((layer, index) => (
          <label className="layerItem" key={layer}>
            <input type="checkbox" defaultChecked={index < 5} />
            <span>{layer}</span>
          </label>
        ))}
      </div>

      <SectionTitle eyebrow="FILTER" title="Regions" />
      <div className="regionGrid">
        {regions.map((region) => <button key={region}>{region}</button>)}
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
