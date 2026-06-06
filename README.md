# ARGOS-SOC IA

Pantalla de mando para un proyecto SIEM + IDS/IPS + IA con Next.js, Wazuh, MCP Agents y globo 3D interactivo.

## Instalar

```powershell
npm config set registry https://registry.npmjs.org/
npm install
npm audit
npm run dev
```

Abrir:

```txt
http://localhost:3000
```

## Dependencias principales

```powershell
npm install next react react-dom react-globe.gl three
npm install -D typescript @types/node @types/react @types/react-dom @types/three
```

El proyecto incluye `overrides` para forzar `postcss@8.5.10` y evitar el aviso de vulnerabilidad moderada detectado por `npm audit`.

## Estructura

- `app/page.tsx`: composición principal.
- `components/AttackGlobe.tsx`: globo 3D interactivo.
- `components/CommandTopbar.tsx`: barra superior ARGOS-SOC IA.
- `components/CommandSidebar.tsx`: capas, filtros y health de agentes.
- `components/ThreatFeed.tsx`: feed SOC en vivo.
- `components/MiniDashboard.tsx`: KPIs, barras, donut, línea, distribución de riesgo.
- `lib/mock-data.ts`: datos mock listos para sustituir por Wazuh/MCP/GeoIP.
- `app/api/attacks/route.ts`: endpoint mock `/api/attacks`.
