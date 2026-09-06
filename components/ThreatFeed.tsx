import { attacks as mockAttacks, severityColors, type Attack } from '@/lib/mock-data';

function getOriginLabel(attack: Attack) {
  const label = [attack.source.city, attack.source.country].filter(Boolean).join(', ') || attack.source.name;
  // La alerta no traia coordenadas: el punto del globo se asigno por hash de la
  // IP. Se marca para no presentar una posicion sintetica como geolocalizacion.
  return attack.geoApproximate ? `${label} (aprox.)` : label;
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
            {attack.ipRisk && <IpRiskTag risk={attack.ipRisk} ip={attack.source.ip} />}
            {attack.vulnerability && <VulnerabilityTag vuln={attack.vulnerability} />}
          </button>
        ))}
      </div>

    </aside>
  );
}

const KIND_TEXT: Record<NonNullable<Attack['ipRisk']>['evidenceKind'], string> = {
  enumeracion: 'probó varias cuentas',
  lateral: 'alcanzó varias máquinas',
  reputacion: 'su /24 ya produjo hostiles',
  volumen: 'sin evidencia destacada',
};

/**
 * Riesgo de la IP de origen: qué probabilidad da el modelo a que ESTA dirección
 * merezca bloqueo, según lo que ha hecho. Va junto al AI Score de ventana, que
 * puntúa el minuto del agente y reparte el mismo número entre todas sus alertas.
 */
function IpRiskTag({ risk, ip }: { risk: NonNullable<Attack['ipRisk']>; ip?: string }) {
  const level = risk.score >= 0.9 ? 'alto' : risk.score >= 0.6 ? 'medio' : 'bajo';
  return (
    <div className={`ipRiskTag ${level}`}>
      <b>IP {(risk.score * 100).toFixed(0)}</b>
      <span>{ip ?? ''}</span>
      <small>
        {risk.usersTried}c · {risk.agentsReached}m · /24 {(risk.subnetHostileRatio * 100).toFixed(0)}%
        {risk.blocked ? ` · bloquearía en aviso ${risk.decidedAtAlert}` : ` · ${KIND_TEXT[risk.evidenceKind]}`}
      </small>
    </div>
  );
}

/**
 * Contexto de explotacion real, AL LADO de la severidad de Wazuh y sin
 * sustituirla. Medido sobre 30 dias: de los 28 CVE que Trivy marca CRITICAL,
 * ninguno esta en el catalogo KEV de explotacion activa.
 */
function VulnerabilityTag({ vuln }: { vuln: NonNullable<Attack['vulnerability']> }) {
  const level = vuln.inKev ? 'kev' : vuln.actionable ? 'alta' : 'ruido';
  const label =
    level === 'kev'
      ? 'EXPLOTADA EN LA VIDA REAL'
      : level === 'alta'
        ? 'EXPLOTACIÓN PROBABLE'
        : 'SIN EXPLOTACIÓN CONOCIDA';

  return (
    <div className={`vulnTag ${level}`}>
      <b>{label}</b>
      <span>{vuln.cve}</span>
      <small>{vuln.epss === null ? 'EPSS < 0,02' : `EPSS ${vuln.epss.toFixed(3)}`}</small>
    </div>
  );
}
