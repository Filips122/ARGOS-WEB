import { attacks as mockAttacks, type Attack } from '@/lib/mock-data';
import type { ArgosServiceStatus } from '@/lib/argos-normalizers';

export function CommandTopbar({
  attacks = mockAttacks,
  serviceStatus,
  loading = false,
}: {
  attacks?: Attack[];
  serviceStatus?: ArgosServiceStatus;
  loading?: boolean;
}) {
  const criticalCount = attacks.filter((attack) => attack.severity === 'critical').length;
  const avgScore = Math.round(attacks.reduce((sum, attack) => sum + attack.score, 0) / Math.max(attacks.length, 1));

  return (
    <header className="commandTopbar">
      <div className="brandBlock">
        <div className="brandMark">A</div>
        <div>
          <p className="eyebrow">GLOBAL THREAT COMMAND CENTER</p>
          <h1>ARGOS-SOC IA</h1>
        </div>
      </div>

      <div className="systemStrip" aria-label="Estado de servicios principales">
        <StatusPill label="WAZUH" value={loading ? 'SYNC' : serviceStatus?.manager === 'offline' ? 'OFFLINE' : 'ONLINE'} tone={serviceStatus?.manager === 'offline' ? 'danger' : 'ok'} />
        <StatusPill label="MCP" value="12 AGENTS" tone="ok" />
        <StatusPill label="SURICATA" value="RUNNING" tone="info" />
        <StatusPill label="AI SCORE" value={`${avgScore}`} tone="ai" />
        <StatusPill label="THREAT" value={criticalCount > 1 ? 'HIGH' : 'ELEVATED'} tone="danger" />
      </div>
    </header>
  );
}

function StatusPill({ label, value, tone }: { label: string; value: string; tone: 'ok' | 'info' | 'ai' | 'danger' }) {
  return (
    <div className={`statusPill ${tone}`}>
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}
