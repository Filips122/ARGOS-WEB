'use client';

import { AttackGlobe } from '@/components/AttackGlobe';
import { CommandSidebar, regions, type RegionFilter } from '@/components/CommandSidebar';
import { CommandTopbar } from '@/components/CommandTopbar';
import { MiniDashboard } from '@/components/MiniDashboard';
import { McpChatWidget } from '@/components/McpChatWidget';
import { ThreatFeed } from '@/components/ThreatFeed';
import type { Attack } from '@/lib/mock-data';
import { useArgosLiveData } from '@/lib/use-argos-live-data';
import { useMemo, useState } from 'react';

function getRegionForAttack(attack: Attack): RegionFilter | null {
  const { lat, lon, country } = attack.source;

  if (Number.isFinite(lat) && Number.isFinite(lon)) {
    if (lat >= 35 && lat <= 72 && lon >= -25 && lon <= 45) return 'Europe';
    if (lat >= -35 && lat <= 37 && lon >= -20 && lon <= 55) return 'Africa';
    if (lat >= 5 && lat <= 83 && lon >= -170 && lon <= -50) return 'North America';
    if (lat >= -56 && lat <= 15 && lon >= -90 && lon <= -30) return 'South America';
    if (lat >= -50 && lat <= 0 && lon >= 110 && lon <= 180) return 'Oceania';
    if (lat >= -10 && lat <= 80 && lon >= 45 && lon <= 180) return 'Asia';
  }

  const normalizedCountry = country.toLowerCase();
  if (['australia', 'new zealand', 'fiji', 'papua new guinea', 'au', 'nz'].includes(normalizedCountry)) return 'Oceania';
  if (['united states', 'canada', 'mexico', 'us', 'ca', 'mx'].includes(normalizedCountry)) return 'North America';
  if (['brazil', 'argentina', 'chile', 'colombia', 'peru', 'br'].includes(normalizedCountry)) return 'South America';

  return null;
}

export function ArgosCommandCenter() {
  const { data, error, loading } = useArgosLiveData();
  const [selectedRegions, setSelectedRegions] = useState<RegionFilter[]>(() => [...regions]);
  const [selectedPinnedAttack, setSelectedPinnedAttack] = useState<Attack | null>(null);
  const hasRealAttacks = (data?.attacks?.length ?? 0) > 0 && data?.mode !== 'demo' && !data?.errors.alerts;
  const attackMode = hasRealAttacks ? data?.mode : data?.errors.alerts ? 'demo' : data?.mode;
  const visibleAttacks = useMemo(() => {
    const attacks = data?.attacks;
    if (!attacks) return attacks;
    if (selectedRegions.length === regions.length) return attacks;

    const selectedRegionSet = new Set(selectedRegions);
    return attacks.filter((attack) => {
      const region = getRegionForAttack(attack);
      return region ? selectedRegionSet.has(region) : true;
    });
  }, [data?.attacks, selectedRegions]);
  const toggleRegion = (region: RegionFilter) => {
    setSelectedRegions((currentRegions) => {
      if (currentRegions.includes(region)) {
        return currentRegions.filter((currentRegion) => currentRegion !== region);
      }

      return regions.filter((currentRegion) => currentRegions.includes(currentRegion) || currentRegion === region);
    });
  };

  return (
    <main className="appShell">
      <CommandTopbar attacks={visibleAttacks} serviceStatus={data?.serviceStatus} loading={loading} />

      {error && <div className="connectionBanner">ARGOS LIVE API OFFLINE · DEMO MODE</div>}
      {data?.mode === 'demo' && !error && <div className="connectionBanner">WAZUH / INDEXER OFFLINE · DEMO MODE</div>}
      {data?.mode === 'partial' && data.errors.alerts && (
        <div className="connectionBanner">WAZUH MANAGER ONLINE · INDEXER OFFLINE · ALERTS IN DEMO MODE</div>
      )}

      <section className="commandGrid" aria-label="Pantalla de mando ARGOS-SOC IA">
        <CommandSidebar
          attacks={visibleAttacks}
          agentHealth={data?.agentHealth}
          selectedRegions={selectedRegions}
          onToggleRegion={toggleRegion}
        />
        <AttackGlobe
          attacks={visibleAttacks}
          mode={attackMode}
          alertsTotal30d={data?.summary.alertsLast30d}
          selectedPinnedAttack={selectedPinnedAttack}
          onSelectedPinnedAttackChange={setSelectedPinnedAttack}
        />
        <ThreatFeed
          attacks={visibleAttacks}
          mode={attackMode}
          selectedAttackId={selectedPinnedAttack?.id}
          onSelectAttack={setSelectedPinnedAttack}
        />
      </section>

      <MiniDashboard kpis={data?.kpis} charts={data?.charts} mode={data?.mode} />
      <McpChatWidget />
    </main>
  );
}
