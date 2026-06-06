'use client';

import dynamic from 'next/dynamic';
import * as THREE from 'three';
import { useEffect, useMemo, useRef, useState } from 'react';
import { attacks as mockAttacks, severityColors, type Attack } from '@/lib/mock-data';

const Globe = dynamic(() => import('react-globe.gl'), { ssr: false }) as any;

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
  target?: Attack['target'];
  targetAttacks?: Attack[];
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

export function AttackGlobe({
  attacks = mockAttacks,
  mode = 'demo',
  alertsTotal30d,
}: {
  attacks?: Attack[];
  mode?: 'live' | 'partial' | 'demo';
  alertsTotal30d?: number;
}) {
  const shellRef = useRef<HTMLDivElement | null>(null);
  const [size, setSize] = useState({ width: 960, height: 620 });
  const [selectedAttack, setSelectedAttack] = useState<Attack | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<GlobePoint | null>(null);
  const [alertsPage, setAlertsPage] = useState(0);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(interval);
  }, []);

  const globeAttacks = useMemo(
    () => attacks.filter((attack) => getAttackAgeMs(attack, now) <= 60_000),
    [attacks, now]
  );

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

  const arcsData = useMemo(() => globeAttacks.map((attack) => ({
    ...attack,
    startLat: attack.source.lat,
    startLng: attack.source.lon,
    endLat: attack.target.lat,
    endLng: attack.target.lon,
    color: severityColors[attack.severity],
    label: `${attack.id} - ${attack.type} - ${attack.source.country} -> ${attack.target.name} - IA ${attack.score}`,
  })), [globeAttacks]);

  const pointsData = useMemo<GlobePoint[]>(() => {
    const selectedSourceId = selectedAttack ? `${selectedAttack.id}-src` : null;
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
      return {
        id: `target-${key}`,
        role: 'target' as const,
        lat: firstAttack.target.lat,
        lng: firstAttack.target.lon,
        color: '#5eb6ff',
        altitude: 0.035,
        size: 1.28,
        selected: selectedTargetId === `target-${key}`,
        label: `Destino: ${firstAttack.target.name} - ${targetAttacks.length} ataque${targetAttacks.length > 1 ? 's' : ''}`,
        target: firstAttack.target,
        targetAttacks,
      };
    });

    const sources = globeAttacks.map((attack) => ({
      id: `${attack.id}-src`,
      role: 'source' as const,
      lat: attack.source.lat,
      lng: attack.source.lon,
      color: severityColors[attack.severity],
      altitude: 0.025,
      size: attack.severity === 'critical' ? 1.38 : 1.08,
      selected: selectedSourceId === `${attack.id}-src`,
      label: `Origen: ${attack.source.country} - ${attack.source.ip}`,
      attack,
    }));

    return [...sources, ...targets];
  }, [globeAttacks, selectedAttack, selectedTarget]);

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
    setAlertsPage(0);
  }, [attacks]);

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
          <small>ultimos 60s</small>
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
          arcColor={(arc: any) => [arc.color, '#38f8d4']}
          arcAltitude={(arc: any) => arc.severity === 'critical' ? 0.36 : 0.24}
          arcStroke={(arc: any) => arc.severity === 'critical' ? 0.9 : 0.5}
          arcDashLength={0.38}
          arcDashGap={0.22}
          arcDashInitialGap={() => Math.random()}
          arcDashAnimateTime={(arc: any) => arc.severity === 'critical' ? 1100 : 1850}
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
            if (point.role === 'source' && point.attack) {
              setSelectedAttack(point.attack);
              setSelectedTarget(null);
            }

            if (point.role === 'target') {
              setSelectedTarget(point);
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
          <AttackDetailCard attack={selectedAttack} onClose={() => setSelectedAttack(null)} />
        )}

        {selectedTarget && !selectedAttack && (
          <TargetAttackList
            targetPoint={selectedTarget}
            onClose={() => setSelectedTarget(null)}
            onSelectAttack={(attack) => {
              setSelectedAttack(attack);
              setSelectedTarget(null);
            }}
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
              onClick={() => setAlertsPage((page) => Math.max(0, page - 1))}
              disabled={alertsPage === 0}
              aria-label="Pagina anterior de alertas Wazuh"
            >
              Prev
            </button>
            <span>{alertsPage + 1}/{alertsPageCount}</span>
            <button
              type="button"
              onClick={() => setAlertsPage((page) => Math.min(alertsPageCount - 1, page + 1))}
              disabled={alertsPage >= alertsPageCount - 1}
              aria-label="Pagina siguiente de alertas Wazuh"
            >
              Next
            </button>
          </div>
        </div>

        <div className="wazuhAlertRows" role="table">
          <div className="wazuhAlertRow wazuhAlertHead" role="row">
            <span role="columnheader">Severidad</span>
            <span role="columnheader">Tipo</span>
            <span role="columnheader">Origen</span>
            <span role="columnheader">Destino</span>
            <span role="columnheader">Regla</span>
            <span role="columnheader">AI</span>
          </div>
          {pipelineAlerts.map((attack) => (
            <button
              type="button"
              className="wazuhAlertRow"
              role="row"
              key={attack.id}
              onClick={() => {
                setSelectedAttack(attack);
                setSelectedTarget(null);
              }}
            >
              <span role="cell" style={{ color: severityColors[attack.severity] }}>{attack.severity.toUpperCase()}</span>
              <span role="cell">{attack.type}</span>
              <span role="cell">{attack.source.ip ?? attack.source.country}</span>
              <span role="cell">{attack.target.name}</span>
              <span role="cell">{attack.wazuhRule}</span>
              <span role="cell">{attack.score}</span>
            </button>
          ))}
        </div>
      </section>
    </section>
  );
}

function AttackDetailCard({ attack, onClose }: { attack: Attack; onClose: () => void }) {
  return (
    <article className="attackDetailCard" aria-live="polite">
      <div className="attackDetailHeader">
        <div>
          <span style={{ color: severityColors[attack.severity] }}>{attack.severity.toUpperCase()}</span>
          <h3>{attack.type}</h3>
        </div>
        <button type="button" onClick={onClose} aria-label="Cerrar detalle de ataque">x</button>
      </div>
      <div className="attackDetailMeta">
        <b>{attack.id}</b>
        <span>{attack.timestamp}</span>
        <span>AI {attack.score}</span>
      </div>
      <dl className="attackDetailGrid">
        <div><dt>Origen</dt><dd>{attack.source.name} ({attack.source.country})</dd></div>
        <div><dt>IP origen</dt><dd>{attack.source.ip}</dd></div>
        <div><dt>Destino</dt><dd>{attack.target.name}</dd></div>
        <div><dt>Agente</dt><dd>{attack.agent}</dd></div>
        <div><dt>Zona</dt><dd>{attack.zone}</dd></div>
        <div><dt>Tactica</dt><dd>{attack.tactic}</dd></div>
        <div><dt>Wazuh rule</dt><dd>{attack.wazuhRule}</dd></div>
        <div><dt>Suricata SID</dt><dd>{attack.suricataSid}</dd></div>
        <div><dt>MCP tool</dt><dd>{attack.mcpTool}</dd></div>
        <div><dt>Sensores</dt><dd>{attack.sensorSources.join(' / ')}</dd></div>
      </dl>
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
  const targetAttacks = targetPoint.targetAttacks ?? [];

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
            <small>{attack.source.country} - {attack.source.ip} - AI {attack.score}</small>
          </button>
        ))}
      </div>
    </article>
  );
}
