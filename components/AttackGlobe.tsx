'use client';

import dynamic from 'next/dynamic';
import * as THREE from 'three';
import { useEffect, useMemo, useRef, useState } from 'react';
import { attacks as mockAttacks, severityColors, type Attack } from '@/lib/mock-data';

const Globe = dynamic(() => import('react-globe.gl'), { ssr: false }) as any;
const ACTIVE_ATTACK_WINDOW_MS = 120_000;
const pinnedAttackColor = '#b56cff';

type GlobePoint = {
  id: string;
  role: 'source' | 'target';
  lat: number;
  lng: number;
  color: string;
  altitude: number;
  size: number;
  label: string;
  selected: boolean;
  attack?: Attack;
  source?: Attack['source'];
  sourceAttacks?: Attack[];
  target?: Attack['target'];
  targetAttacks?: Attack[];
};

type AttackArc = Attack & {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
  color: string;
  dashInitialGap: number;
  dashAnimateTime: number;
  label: string;
};

const severityRank: Record<Attack['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function getGlobeCoords(lat: number, lng: number, altitude: number) {
  const phi = (90 - lat) * Math.PI / 180;
  const theta = (90 - lng) * Math.PI / 180;
  const radius = 100 * (1 + altitude);
  const phiSin = Math.sin(phi);

  return {
    x: radius * phiSin * Math.cos(theta),
    y: radius * Math.cos(phi),
    z: radius * phiSin * Math.sin(theta),
  };
}

function getAttackAgeMs(attack: Attack, now: number) {
  const absoluteTimestamp = attack.receivedAt ? new Date(attack.receivedAt).getTime() : Number.NaN;

  if (Number.isFinite(absoluteTimestamp)) {
    return Math.max(0, now - absoluteTimestamp);
  }

  const relativeMatch = attack.timestamp.match(/^hace\s+(\d+)(s|m|h)$/i);
  if (!relativeMatch) return 0;

  const value = Number(relativeMatch[1]);
  const unit = relativeMatch[2].toLowerCase();

  if (unit === 's') return value * 1000;
  if (unit === 'm') return value * 60_000;
  return value * 60 * 60_000;
}

function getOriginLabel(attack: Attack) {
  const label = [attack.source.city, attack.source.country].filter(Boolean).join(', ') || attack.source.name;
  // Coordenadas de reserva asignadas por hash de la IP: se marca para no
  // presentar una posicion sintetica como geolocalizacion real.
  return attack.geoApproximate ? `${label} (aprox.)` : label;
}

function getStableUnitInterval(value: string) {
  const hash = value.split('').reduce((total, char) => ((total << 5) - total + char.charCodeAt(0)) | 0, 0);
  return Math.abs(hash % 1000) / 1000;
}

function sortAttacksForSelection(attacks: Attack[]) {
  const now = Date.now();

  return [...attacks].sort((a, b) => {
    const ageDelta = getAttackAgeMs(b, now) - getAttackAgeMs(a, now);
    if (ageDelta !== 0) return ageDelta;
    return severityRank[a.severity] - severityRank[b.severity];
  });
}

export function AttackGlobe({
  attacks = mockAttacks,
  mode = 'demo',
  alertsTotal30d,
  selectedPinnedAttack,
  onSelectedPinnedAttackChange,
}: {
  attacks?: Attack[];
  mode?: 'live' | 'partial' | 'demo';
  alertsTotal30d?: number;
  selectedPinnedAttack?: Attack | null;
  onSelectedPinnedAttackChange?: (attack: Attack | null) => void;
}) {
  const shellRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ width: 960, height: 620 });
  const [selectedAttack, setSelectedAttack] = useState<Attack | null>(null);
  const [selectedSource, setSelectedSource] = useState<GlobePoint | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<GlobePoint | null>(null);
  const [selectedTableAttack, setSelectedTableAttack] = useState<Attack | null>(null);
  const [alertsPage, setAlertsPage] = useState(0);
  const anchoredAlertIdRef = useRef<string | null>(null);
  const [globeAttacks, setGlobeAttacks] = useState<Attack[]>([]);
  const stableAttackCacheRef = useRef(new Map<string, Attack>());
  const stableArcCacheRef = useRef(new Map<string, AttackArc>());

  const selectPinnedAttack = (attack: Attack) => {
    setSelectedAttack(attack);
    setSelectedTableAttack(attack);
    setSelectedSource(null);
    setSelectedTarget(null);
    onSelectedPinnedAttackChange?.(attack);
  };

  const clearPinnedAttack = (attackId?: string) => {
    setSelectedTableAttack(null);

    if (!attackId || selectedAttack?.id === attackId) {
      setSelectedAttack(null);
      setSelectedSource(null);
      setSelectedTarget(null);
      onSelectedPinnedAttackChange?.(null);
    }
  };

  useEffect(() => {
    if (!selectedPinnedAttack) return;

    setSelectedAttack(selectedPinnedAttack);
    setSelectedTableAttack(selectedPinnedAttack);
    setSelectedSource(null);
    setSelectedTarget(null);
  }, [selectedPinnedAttack]);

  useEffect(() => {
    setGlobeAttacks((currentAttacks) => {
      const now = Date.now();
      const currentById = new Map(currentAttacks.map((attack) => [attack.id, attack]));
      const nextAttacks = attacks.reduce<Attack[]>((activeAttacks, attack) => {
        if (getAttackAgeMs(attack, now) > ACTIVE_ATTACK_WINDOW_MS && selectedAttack?.id !== attack.id) return activeAttacks;

        const stableAttack = currentById.get(attack.id) ?? stableAttackCacheRef.current.get(attack.id) ?? attack;
        stableAttackCacheRef.current.set(attack.id, stableAttack);
        activeAttacks.push(stableAttack);
        return activeAttacks;
      }, []);

      if (selectedAttack && !nextAttacks.some((attack) => attack.id === selectedAttack.id)) {
        const stableAttack = currentById.get(selectedAttack.id) ?? stableAttackCacheRef.current.get(selectedAttack.id) ?? selectedAttack;
        stableAttackCacheRef.current.set(selectedAttack.id, stableAttack);
        nextAttacks.push(stableAttack);
      }

      const activeIds = new Set(nextAttacks.map((attack) => attack.id));

      for (const cachedId of stableAttackCacheRef.current.keys()) {
        if (!activeIds.has(cachedId)) stableAttackCacheRef.current.delete(cachedId);
      }

      for (const cachedId of stableArcCacheRef.current.keys()) {
        if (!activeIds.has(cachedId)) stableArcCacheRef.current.delete(cachedId);
      }

      const unchanged = currentAttacks.length === nextAttacks.length
        && currentAttacks.every((attack, index) => attack === nextAttacks[index]);

      return unchanged ? currentAttacks : nextAttacks;
    });
  }, [attacks, selectedAttack]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      setGlobeAttacks((currentAttacks) => {
        const now = Date.now();
        const nextAttacks = currentAttacks.filter((attack) => (
          getAttackAgeMs(attack, now) <= ACTIVE_ATTACK_WINDOW_MS || selectedAttack?.id === attack.id
        ));

        if (nextAttacks.length === currentAttacks.length) return currentAttacks;

        const activeIds = new Set(nextAttacks.map((attack) => attack.id));
        for (const cachedId of stableAttackCacheRef.current.keys()) {
          if (!activeIds.has(cachedId)) stableAttackCacheRef.current.delete(cachedId);
        }
        for (const cachedId of stableArcCacheRef.current.keys()) {
          if (!activeIds.has(cachedId)) stableArcCacheRef.current.delete(cachedId);
        }

        return nextAttacks;
      });
    }, 5000);

    return () => window.clearInterval(interval);
  }, [selectedAttack]);

  useEffect(() => {
    const element = shellRef.current;
    if (!element) return;

    const updateSize = () => {
      const rect = element.getBoundingClientRect();
      setSize({ width: Math.max(320, Math.floor(rect.width)), height: Math.max(520, Math.floor(rect.height)) });
    };

    updateSize();
    const observer = new ResizeObserver(updateSize);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const arcsData = useMemo(() => globeAttacks.map((attack) => {
    const cachedArc = stableArcCacheRef.current.get(attack.id);
    if (cachedArc) return cachedArc;

    const arc: AttackArc = {
      ...attack,
      startLat: attack.source.lat,
      startLng: attack.source.lon,
      endLat: attack.target.lat,
      endLng: attack.target.lon,
      color: severityColors[attack.severity],
      dashInitialGap: getStableUnitInterval(attack.id),
      dashAnimateTime: attack.severity === 'critical' ? 2600 : 3800,
      label: `${attack.id} - ${attack.type} - ${getOriginLabel(attack)} -> ${attack.target.name} - IA ${attack.score}`,
    };

    stableArcCacheRef.current.set(attack.id, arc);
    return arc;
  }), [globeAttacks]);

  const pointsData = useMemo<GlobePoint[]>(() => {
    const selectedSourceId = selectedSource?.id ?? null;
    const selectedTargetId = selectedTarget?.id ?? null;
    const targets = Array.from(
      globeAttacks.reduce((groups, attack) => {
        const key = `${attack.target.name}-${attack.target.lat}-${attack.target.lon}`;
        const group = groups.get(key);

        if (group) {
          group.push(attack);
        } else {
          groups.set(key, [attack]);
        }

        return groups;
      }, new Map<string, Attack[]>())
    ).map(([key, targetAttacks]) => {
        const firstAttack = targetAttacks[0];
        const hasSelectedAttack = targetAttacks.some((attack) => attack.id === selectedAttack?.id);
        return {
        id: `target-${key}`,
        role: 'target' as const,
        lat: firstAttack.target.lat,
        lng: firstAttack.target.lon,
        color: hasSelectedAttack ? pinnedAttackColor : '#5eb6ff',
        altitude: 0.035,
        size: 1.28,
        selected: selectedTargetId === `target-${key}` || hasSelectedAttack,
        label: `Destino: ${firstAttack.target.name} - ${targetAttacks.length} ataque${targetAttacks.length > 1 ? 's' : ''}`,
        target: firstAttack.target,
        targetAttacks,
      };
    });

    const sources = Array.from(
      globeAttacks.reduce((groups, attack) => {
        const key = `${attack.source.ip ?? attack.source.name}-${attack.source.lat}-${attack.source.lon}`;
        const group = groups.get(key);

        if (group) {
          group.push(attack);
        } else {
          groups.set(key, [attack]);
        }

        return groups;
      }, new Map<string, Attack[]>())
    ).map(([key, sourceAttacks]) => {
      const sortedSourceAttacks = sortAttacksForSelection(sourceAttacks);
      const firstAttack = sortedSourceAttacks[0];
      const hasSelectedAttack = sourceAttacks.some((attack) => attack.id === selectedAttack?.id);
      const highestSeverityAttack = sortedSourceAttacks.reduce((highest, attack) => (
        severityRank[attack.severity] < severityRank[highest.severity] ? attack : highest
      ), firstAttack);

      return {
        id: `source-${key}`,
        role: 'source' as const,
        lat: firstAttack.source.lat,
        lng: firstAttack.source.lon,
        color: hasSelectedAttack ? pinnedAttackColor : severityColors[highestSeverityAttack.severity],
        altitude: 0.025,
        size: highestSeverityAttack.severity === 'critical' ? 1.38 : 1.08,
        selected: selectedSourceId === `source-${key}` || hasSelectedAttack,
        label: `Origen: ${getOriginLabel(firstAttack)} - ${sourceAttacks.length} ataque${sourceAttacks.length > 1 ? 's' : ''}`,
        source: firstAttack.source,
        sourceAttacks: sortedSourceAttacks,
      };
    });

    return [...sources, ...targets];
  }, [globeAttacks, selectedAttack, selectedSource, selectedTarget]);

  const ringsData = useMemo(() => globeAttacks.map((attack) => ({
    lat: attack.target.lat,
    lng: attack.target.lon,
    color: severityColors[attack.severity],
    maxRadius: attack.severity === 'critical' ? 5.4 : 3.4,
    propagationSpeed: attack.severity === 'critical' ? 2.6 : 1.8,
    repeatPeriod: attack.severity === 'critical' ? 700 : 1200,
  })), [globeAttacks]);

  const alertsPageSize = 10;
  const alertsPageCount = Math.max(1, Math.ceil(attacks.length / alertsPageSize));
  const totalAlertsLabel = (alertsTotal30d ?? attacks.length).toLocaleString('es-ES');
  const loadedAlertsLabel = attacks.length.toLocaleString('es-ES');
  const pipelineAlerts = useMemo(
    () => attacks.slice(alertsPage * alertsPageSize, alertsPage * alertsPageSize + alertsPageSize),
    [alertsPage, attacks]
  );

  useEffect(() => {
    setAlertsPage((currentPage) => {
      const anchoredAlertId = anchoredAlertIdRef.current;

      if (anchoredAlertId) {
        const anchoredIndex = attacks.findIndex((attack) => attack.id === anchoredAlertId);
        if (anchoredIndex >= 0) return Math.min(alertsPageCount - 1, Math.floor(anchoredIndex / alertsPageSize));
      }

      return Math.min(currentPage, alertsPageCount - 1);
    });
  }, [attacks, alertsPageCount]);

  useEffect(() => {
    anchoredAlertIdRef.current = pipelineAlerts[0]?.id ?? null;
  }, [pipelineAlerts]);

  const goToAlertsPage = (page: number) => {
    const nextPage = Math.min(alertsPageCount - 1, Math.max(0, page));
    anchoredAlertIdRef.current = attacks[nextPage * alertsPageSize]?.id ?? null;
    setAlertsPage(nextPage);
  };

  return (
    <section className="globeCommand">
      <div className="globeTitleRow">
        <div>
          <p className="eyebrow">3D THREAT GEOSPATIAL LAYER</p>
          <h2>Global Attack Surface</h2>
        </div>
        <div className="globeControls">
          <span>DRAG</span>
          <span>ZOOM</span>
          <span>ROTATE</span>
        </div>
      </div>

      <div className="globeViewport" ref={shellRef}>
        <div className="scanLine" />
        <div className="globeHud hudTopLeft">
          <span>ACTIVE ROUTES</span>
          <b>{globeAttacks.length}</b>
          <small>ultimos 120s</small>
        </div>
        <div className="globeHud hudBottomRight">
          <span>PIPELINE</span>
          <b>SIEM - IA - SOC</b>
          <small>{mode === 'live' ? 'wazuh live mode' : mode === 'partial' ? 'partial live mode' : 'mock live mode'}</small>
        </div>

        <Globe
          width={size.width}
          height={size.height}
          globeImageUrl="//unpkg.com/three-globe/example/img/earth-night.jpg"
          backgroundImageUrl="//unpkg.com/three-globe/example/img/night-sky.png"
          arcsData={arcsData}
          arcStartLat="startLat"
          arcStartLng="startLng"
          arcEndLat="endLat"
          arcEndLng="endLng"
          arcColor={(arc: any) => {
            const color = arc.id === selectedAttack?.id ? pinnedAttackColor : arc.color;
            return [color, color];
          }}
          arcAltitude={(arc: any) => arc.severity === 'critical' ? 0.36 : 0.24}
          arcStroke={(arc: any) => arc.severity === 'critical' ? 0.9 : 0.5}
          arcDashLength={0.28}
          arcDashGap={0.16}
          arcDashInitialGap="dashInitialGap"
          arcDashAnimateTime="dashAnimateTime"
          arcsTransitionDuration={0}
          arcLabel="label"
          customLayerData={pointsData}
          customThreeObject={(point: GlobePoint) => {
            const material = new THREE.MeshBasicMaterial({
              color: point.color,
              transparent: true,
              opacity: point.role === 'source' ? 0.96 : 0.9,
            });
            const mesh = new THREE.Mesh(new THREE.SphereGeometry(point.selected ? point.size * 1.45 : point.size, 20, 20), material);
            const coords = getGlobeCoords(point.lat, point.lng, point.altitude);
            mesh.position.set(coords.x, coords.y, coords.z);
            return mesh;
          }}
          customThreeObjectUpdate={(obj: THREE.Object3D, point: GlobePoint) => {
            const coords = getGlobeCoords(point.lat, point.lng, point.altitude);
            obj.position.set(coords.x, coords.y, coords.z);
            obj.scale.setScalar(point.selected ? 1.45 : 1);
          }}
          customLayerLabel="label"
          onCustomLayerClick={(point: GlobePoint) => {
            if (point.role === 'source') {
              const sourceAttacks = point.sourceAttacks ?? [];

              if (sourceAttacks.length <= 1) {
                setSelectedAttack(sourceAttacks[0] ?? point.attack ?? null);
                setSelectedSource(null);
              } else {
                setSelectedSource(point);
                setSelectedAttack(null);
              }

              setSelectedTarget(null);
            }

            if (point.role === 'target') {
              setSelectedTarget(point);
              setSelectedSource(null);
              setSelectedAttack(null);
            }
          }}
          ringsData={ringsData}
          ringLat="lat"
          ringLng="lng"
          ringColor={(ring: any) => (t: number) => `${ring.color}${Math.round((1 - t) * 255).toString(16).padStart(2, '0')}`}
          ringMaxRadius="maxRadius"
          ringPropagationSpeed="propagationSpeed"
          ringRepeatPeriod="repeatPeriod"
          atmosphereColor="#38f8d4"
          atmosphereAltitude={0.18}
          backgroundColor="rgba(0,0,0,0)"
        />

        {selectedAttack && (
          <AttackDetailCard
            attack={selectedAttack}
            onClose={() => {
              clearPinnedAttack(selectedAttack.id);
            }}
            onBack={selectedSource || selectedTarget ? () => setSelectedAttack(null) : undefined}
          />
        )}

        {selectedSource && !selectedAttack && (
          <SourceAttackList
            sourcePoint={selectedSource}
            onClose={() => setSelectedSource(null)}
            onSelectAttack={(attack) => setSelectedAttack(attack)}
          />
        )}

        {selectedTarget && !selectedAttack && (
          <TargetAttackList
            targetPoint={selectedTarget}
            onClose={() => setSelectedTarget(null)}
            onSelectAttack={(attack) => setSelectedAttack(attack)}
          />
        )}
      </div>

      <div className="pipelineStrip">
        <span>Source Telemetry</span>
        <b>-</b>
        <span>Wazuh / Suricata / Zeek</span>
        <b>-</b>
        <span>AI Risk Score</span>
        <b>-</b>
        <span>SOC Prioritization</span>
        <b>-</b>
        <span>IPS Response</span>
      </div>

      <section className="wazuhAlertTable" aria-label="Tabla de alertas Wazuh">
        <div className="wazuhAlertTableHeader">
          <div>
            <span>{mode === 'demo' ? 'DEMO ALERTS' : 'WAZUH ALERTS'}</span>
            <b>
              {totalAlertsLabel} detecciones ultimos 30 dias
              {alertsTotal30d && alertsTotal30d > attacks.length ? ` (${loadedAlertsLabel} cargadas)` : ''}
            </b>
          </div>
          <div className="wazuhPager">
            <button
              type="button"
              onClick={() => goToAlertsPage(0)}
              disabled={alertsPage === 0}
              aria-label="Primera pagina de alertas Wazuh"
            >
              First
            </button>
            <button
              type="button"
              onClick={() => goToAlertsPage(alertsPage - 10)}
              disabled={alertsPage === 0}
              aria-label="Retroceder diez paginas de alertas Wazuh"
            >
              -10
            </button>
            <button
              type="button"
              onClick={() => goToAlertsPage(alertsPage - 1)}
              disabled={alertsPage === 0}
              aria-label="Pagina anterior de alertas Wazuh"
            >
              Prev
            </button>
            <span>{alertsPage + 1}/{alertsPageCount}</span>
            <button
              type="button"
              onClick={() => goToAlertsPage(alertsPage + 1)}
              disabled={alertsPage >= alertsPageCount - 1}
              aria-label="Pagina siguiente de alertas Wazuh"
            >
              Next
            </button>
            <button
              type="button"
              onClick={() => goToAlertsPage(alertsPage + 10)}
              disabled={alertsPage >= alertsPageCount - 1}
              aria-label="Avanzar diez paginas de alertas Wazuh"
            >
              +10
            </button>
            <button
              type="button"
              onClick={() => goToAlertsPage(alertsPageCount - 1)}
              disabled={alertsPage >= alertsPageCount - 1}
              aria-label="Ultima pagina de alertas Wazuh"
            >
              Last
            </button>
          </div>
        </div>

        {selectedTableAttack && (
          <AttackDetailCard
            attack={selectedTableAttack}
            className="tableAttackDetail"
            onClose={() => {
              clearPinnedAttack(selectedTableAttack.id);
            }}
          />
        )}

        <div className="wazuhAlertRows" role="table">
          <div className="wazuhAlertRow wazuhAlertHead" role="row">
            <span role="columnheader">Severity</span>
            <span role="columnheader">Tipo</span>
            <span role="columnheader">Origen</span>
            <span role="columnheader">IP origen</span>
            <span role="columnheader">Destino</span>
            <span role="columnheader">Regla</span>
            <span role="columnheader">AI Score</span>
            <span role="columnheader">Class</span>
          </div>
          {pipelineAlerts.map((attack) => (
            <button
              type="button"
              className="wazuhAlertRow"
              role="row"
              key={attack.id}
              onClick={() => {
                selectPinnedAttack(attack);
              }}
            >
              <span role="cell" style={{ color: severityColors[attack.severity] }}>{attack.severity.toUpperCase()}</span>
              <span role="cell">{attack.type}</span>
              <span role="cell">{getOriginLabel(attack)}</span>
              <span role="cell">{attack.source.ip ?? 'unknown'}</span>
              <span role="cell">{attack.target.name}</span>
              <span role="cell">{attack.wazuhRule}</span>
              <span role="cell" title={attack.ai ? `${attack.ai.modelId} - ${attack.ai.prediction}` : 'Heuristica Wazuh'}>
                {attack.score}
              </span>
              <span role="cell" className={`classificationCell ${attack.ai?.prediction ?? 'unknown'}`}>
                {attack.ai?.prediction ?? 'unknown'}
              </span>
            </button>
          ))}
        </div>
      </section>
    </section>
  );
}

function AttackDetailCard({
  attack,
  onClose,
  onBack,
  className,
}: {
  attack: Attack;
  onClose: () => void;
  onBack?: () => void;
  className?: string;
}) {
  return (
    <article className={`attackDetailCard${className ? ` ${className}` : ''}`} aria-live="polite">
      <div className="attackDetailHeader">
        <div>
          <span style={{ color: severityColors[attack.severity] }}>{attack.severity.toUpperCase()}</span>
          <h3>{attack.type}</h3>
        </div>
        <div className="attackDetailActions">
          {onBack && <button type="button" onClick={onBack} aria-label="Volver a la lista de ataques">Back</button>}
          <button type="button" onClick={onClose} aria-label="Cerrar detalle de ataque">x</button>
        </div>
      </div>
      <div className="attackDetailMeta">
        <b>{attack.id}</b>
        <span>{attack.timestamp}</span>
        <span title={attack.ai ? `${attack.ai.modelId} - ${attack.ai.prediction}` : undefined}>
          AI {attack.score}
        </span>
      </div>
      <dl className="attackDetailGrid">
        <div><dt>Origen</dt><dd>{getOriginLabel(attack)}</dd></div>
        <div><dt>IP origen</dt><dd>{attack.source.ip}</dd></div>
        <div><dt>Coordenadas</dt><dd>{attack.source.lat.toFixed(4)}, {attack.source.lon.toFixed(4)}</dd></div>
        <div><dt>Destino</dt><dd>{attack.target.name}</dd></div>
        <div><dt>Agente</dt><dd>{attack.agent}</dd></div>
        <div><dt>Zona</dt><dd>{attack.zone}</dd></div>
        <div><dt>Tactica</dt><dd>{attack.tactic}</dd></div>
        <div><dt>Wazuh rule</dt><dd>{attack.wazuhRule}</dd></div>
        {attack.ai && <div><dt>Modelo IA</dt><dd>{attack.ai.modelId}</dd></div>}
        {attack.ai && <div><dt>Prediccion IA</dt><dd>{attack.ai.prediction} ({Math.round(attack.ai.confidence * 100)}%)</dd></div>}
        {attack.ai?.taxonomy && <div><dt>Prediccion taxonomica IA</dt><dd>{attack.ai.taxonomy.label} ({Math.round(attack.ai.taxonomy.confidence * 100)}%)</dd></div>}
        {attack.ai?.csrLanl && <div><dt>CSR-LANL entidad</dt><dd>{attack.ai.csrLanl.entity}</dd></div>}
        {attack.ai?.csrLanl && <div><dt>CSR-LANL clasificacion</dt><dd>{attack.ai.csrLanl.classification.replaceAll('_', ' ')}</dd></div>}
        {attack.ai?.csrLanl && <div><dt>CSR-LANL score</dt><dd>{Math.round(attack.ai.csrLanl.supervisedScore * 100)}%</dd></div>}
        {attack.ai?.csrLanl && <div><dt>Anomalia entidad</dt><dd>{attack.ai.csrLanl.entityAnomalyScore.toFixed(3)}</dd></div>}
        {attack.ai?.csrLanl && <div><dt>Novedad contexto</dt><dd>{Math.round(attack.ai.csrLanl.contextNoveltyScore * 100)}%</dd></div>}
        <div><dt>Suricata SID</dt><dd>{attack.suricataSid}</dd></div>
        <div><dt>MCP tool</dt><dd>{attack.mcpTool}</dd></div>
        <div><dt>Sensores</dt><dd>{attack.sensorSources.join(' / ')}</dd></div>
      </dl>
    </article>
  );
}

function SourceAttackList({
  sourcePoint,
  onClose,
  onSelectAttack,
}: {
  sourcePoint: GlobePoint;
  onClose: () => void;
  onSelectAttack: (attack: Attack) => void;
}) {
  const sourceAttacks = sortAttacksForSelection(sourcePoint.sourceAttacks ?? []);

  return (
    <article className="attackDetailCard targetAttackCard" aria-live="polite">
      <div className="attackDetailHeader">
        <div>
          <span>ORIGEN</span>
          <h3>{sourcePoint.source ? [sourcePoint.source.city, sourcePoint.source.country].filter(Boolean).join(', ') || sourcePoint.source.name : 'Origen'}</h3>
        </div>
        <button type="button" onClick={onClose} aria-label="Cerrar ataques del origen">x</button>
      </div>
      <div className="attackDetailMeta">
        <b>{sourcePoint.source?.ip ?? 'unknown'}</b>
        <span>{sourceAttacks.length} ataque{sourceAttacks.length !== 1 ? 's' : ''}</span>
        <span>{sourceAttacks[0]?.timestamp}</span>
      </div>
      <div className="targetAttackList">
        {sourceAttacks.map((attack) => (
          <button type="button" key={attack.id} onClick={() => onSelectAttack(attack)}>
            <span style={{ color: severityColors[attack.severity] }}>{attack.severity.toUpperCase()}</span>
            <b>{attack.type}</b>
            <small>{attack.timestamp} - {attack.target.name} - AI {attack.score}</small>
          </button>
        ))}
      </div>
    </article>
  );
}

function TargetAttackList({
  targetPoint,
  onClose,
  onSelectAttack,
}: {
  targetPoint: GlobePoint;
  onClose: () => void;
  onSelectAttack: (attack: Attack) => void;
}) {
  const targetAttacks = sortAttacksForSelection(targetPoint.targetAttacks ?? []);

  return (
    <article className="attackDetailCard targetAttackCard" aria-live="polite">
      <div className="attackDetailHeader">
        <div>
          <span>DESTINO</span>
          <h3>{targetPoint.target?.name}</h3>
        </div>
        <button type="button" onClick={onClose} aria-label="Cerrar ataques del destino">x</button>
      </div>
      <div className="attackDetailMeta">
        <b>{targetPoint.target?.country}</b>
        <span>{targetAttacks.length} ataque{targetAttacks.length !== 1 ? 's' : ''}</span>
        <span>{targetAttacks[0]?.agent}</span>
      </div>
      <div className="targetAttackList">
        {targetAttacks.map((attack) => (
          <button type="button" key={attack.id} onClick={() => onSelectAttack(attack)}>
            <span style={{ color: severityColors[attack.severity] }}>{attack.severity.toUpperCase()}</span>
            <b>{attack.type}</b>
            <small>{getOriginLabel(attack)} - {attack.source.ip} - AI {attack.score}</small>
          </button>
        ))}
      </div>
    </article>
  );
}
