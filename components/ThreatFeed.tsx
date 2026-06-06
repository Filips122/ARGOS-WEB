import { attacks as mockAttacks, severityColors, type Attack } from '@/lib/mock-data';

function getOriginLabel(attack: Attack) {
  return [attack.source.city, attack.source.country].filter(Boolean).join(', ') || attack.source.name;
}

export function ThreatFeed({
  attacks = mockAttacks,
  mode = 'demo',
  selectedAttackId,
  onSelectAttack,
}: {
  attacks?: Attack[];
  mode?: 'live' | 'partial' | 'demo';
  selectedAttackId?: string;
  onSelectAttack?: (attack: Attack) => void;
}) {
  const topTargets = Array.from(new Set(attacks.map((attack) => attack.target.name))).slice(0, 4);

  return (
    <aside className="commandPanel feedPanel">
      <div className="feedHeader">
        <div>
          <p className="eyebrow">LIVE SOC FEED</p>
          <h2>Threat Stream</h2>
        </div>
        <span className="liveBadge">{mode === 'demo' ? 'DEMO' : 'LIVE'}</span>
      </div>

      <div className="alertStream">
        {attacks.slice(0, 7).map((attack) => (
          <button
            type="button"
            className={`alertCard${selectedAttackId === attack.id ? ' active' : ''}`}
            key={attack.id}
            onClick={() => onSelectAttack?.(attack)}
          >
            <div className="alertMeta">
              <span style={{ color: severityColors[attack.severity] }}>{attack.severity.toUpperCase()}</span>
              <small>{attack.timestamp}</small>
            </div>
            <h3>{attack.type}</h3>
            <p>{getOriginLabel(attack)} → {attack.target.name}</p>
            <div className="alertFooter">
              <span>AI {attack.score}</span>
              <span>Rule {attack.wazuhRule}</span>
              <span>{attack.mcpTool}</span>
            </div>
          </button>
        ))}
      </div>

      <div className="miniModule">
        <p className="eyebrow">TOP TARGETS</p>
        {topTargets.map((target, index) => (
          <div className="targetRow" key={target}>
            <span>0{index + 1}</span>
            <b>{target}</b>
            <small>{Math.max(96 - index * 9, 61)} risk</small>
          </div>
        ))}
      </div>
    </aside>
  );
}
