'use client';

import { AttackGlobe } from '@/components/AttackGlobe';
import { CommandSidebar } from '@/components/CommandSidebar';
import { CommandTopbar } from '@/components/CommandTopbar';
import { MiniDashboard } from '@/components/MiniDashboard';
import { ThreatFeed } from '@/components/ThreatFeed';
import { useArgosLiveData } from '@/lib/use-argos-live-data';

export function ArgosCommandCenter() {
  const { data, error, loading } = useArgosLiveData();
  const hasRealAttacks = (data?.attacks?.length ?? 0) > 0 && data?.mode !== 'demo' && !data?.errors.alerts;
  const attackMode = hasRealAttacks ? data?.mode : data?.errors.alerts ? 'demo' : data?.mode;

  return (
    <main className="appShell">
      <CommandTopbar attacks={data?.attacks} serviceStatus={data?.serviceStatus} loading={loading} />

      {error && <div className="connectionBanner">ARGOS LIVE API OFFLINE · DEMO MODE</div>}
      {data?.mode === 'demo' && !error && <div className="connectionBanner">WAZUH / INDEXER OFFLINE · DEMO MODE</div>}
      {data?.mode === 'partial' && data.errors.alerts && (
        <div className="connectionBanner">WAZUH MANAGER ONLINE · INDEXER OFFLINE · ALERTS IN DEMO MODE</div>
      )}

      <section className="commandGrid" aria-label="Pantalla de mando ARGOS-SOC IA">
        <CommandSidebar agentHealth={data?.agentHealth} />
        <AttackGlobe attacks={data?.attacks} mode={attackMode} alertsTotal30d={data?.summary.alertsLast30d} />
        <ThreatFeed attacks={data?.attacks} mode={attackMode} />
      </section>

      <MiniDashboard kpis={data?.kpis} charts={data?.charts} mode={data?.mode} />
    </main>
  );
}
