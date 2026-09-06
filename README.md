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

## Asistente conversacional (MCP)

El panel lleva un chat que consulta el SOC en lenguaje natural. Detrás hay un
servidor MCP propio (`deploy/argos_mcp/server.ts`) con siete herramientas de
**solo lectura**: estado de la plataforma, búsqueda de alertas, riesgo de una
IP, resumen de amenazas, vulnerabilidades explotadas, simulacro de bloqueo y
estado de los modelos.

Ese mismo servidor se consume desde tres sitios:

| Cliente | Cómo |
|---|---|
| El propio panel, en el navegador | Botón `CONSULTA`. Necesita `ANTHROPIC_API_KEY`. |
| Claude Code | `.mcp.json` del repositorio, ya configurado. |
| Claude Desktop | Añadir el bloque `mcpServers` de la cabecera de `server.ts`. |

Para el chat del navegador, en `.env.local`:

```txt
ANTHROPIC_API_KEY=sk-ant-...
```

Sin esa clave el chat **no se rompe**: cae a un comparador de palabras clave
determinista y lo declara en la respuesta. Una suscripción de Claude no sirve
aquí: no expone ninguna credencial programática, es un producto distinto de la
API. Detalle completo en `METRICAS.md`, sección 10.

Comprobar qué motor responderá:

```powershell
curl http://localhost:3000/api/argos/mcp-chat
```

Probar el servidor MCP sin navegador ni clave:

```powershell
node deploy/argos_mcp/test_client.ts
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
- `deploy/argos_mcp/server.ts`: servidor MCP, siete herramientas de solo lectura.
- `lib/mcp-host.ts`: la web como host MCP (cliente stdio contra ese servidor).
- `app/api/argos/mcp-chat/route.ts`: chat del panel, con bucle de herramientas.
