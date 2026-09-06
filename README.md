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
| El propio panel, en el navegador | Botón `CONSULTA`. **No necesita configuración** si tienes Claude Code instalado. |
| Claude Code | `.mcp.json` del repositorio, ya configurado. |
| Claude Desktop | Añadir el bloque `mcpServers` de la cabecera de `server.ts`. |

El chat del navegador elige motor solo:

1. **Suscripción** — si encuentra el CLI de Claude Code, lo invoca en modo no
   interactivo. No hace falta clave ni configuración.
2. **Clave de API** — si defines `ANTHROPIC_API_KEY` en `.env.local`.
3. **Reglas** — si no hay ninguno de los dos, o si fallan, responde un
   comparador de palabras clave determinista y **lo declara** en pantalla.

`ARGOS_CHAT_ENGINE=cli|api|keywords` fuerza uno concreto.

> **Aviso.** Con el motor de suscripción, este endpoint lanza un agente en tu
> máquina, acotado a las siete herramientas de solo lectura y con las de
> escritura denegadas. Aun así, **no expongas la aplicación fuera de
> localhost**. Detalle en `METRICAS.md`, sección 10.

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
- `lib/claude-cli.ts`: motor de suscripción, vía CLI de Claude Code.
- `app/api/argos/mcp-chat/route.ts`: chat del panel, con bucle de herramientas.
