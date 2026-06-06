# WAZUH.md — Integración de Wazuh con ARGOS-SOC IA

## Objetivo

Integrar datos reales de Wazuh en la web **ARGOS-SOC IA**, evitando introducir información manualmente en el frontend.

La integración debe permitir que el dashboard Next.js consuma información desde:

- **Wazuh Manager API** para agentes, estado del manager, reglas, grupos y metadatos operativos.
- **Wazuh Indexer API** para alertas, eventos, severidades, agentes afectados y datos históricos.

La arquitectura deseada es:

```txt
Wazuh Manager API / Wazuh Indexer
        ↓
Next.js API Routes internas
        ↓
Normalización de datos
        ↓
ARGOS-SOC IA frontend
        ↓
Globo 3D + feed SOC + dashboard inferior
```

Nunca exponer credenciales, tokens ni direcciones internas directamente en componentes React del navegador.

---

## Datos conocidos del entorno

```txt
WAZUH_API_USER=wazuh-filip
WAZUH_API_HOST=122.122.122.122
```

La contraseña no debe escribirse en el código ni en este documento. Debe ir en `.env.local`.

---

## Reglas de seguridad obligatorias

1. No llamar a Wazuh directamente desde componentes client-side.
2. No hardcodear usuario, contraseña, token ni IP sensible en `.tsx`.
3. Usar variables de entorno en `.env.local`.
4. Añadir `.env.local` a `.gitignore` si no está incluido.
5. Usar API Routes de Next.js como capa backend.
6. Los endpoints internos de Next deben devolver datos ya filtrados y normalizados.
7. No devolver al frontend respuestas completas si contienen campos sensibles.
8. En producción, no usar `NODE_TLS_REJECT_UNAUTHORIZED=0`.
9. Para laboratorio, se puede permitir certificado autofirmado solo de forma temporal y documentada.
10. No subir `package-lock.json` generado con registries privados o internos ajenos al entorno del usuario.

---

## Variables de entorno necesarias

Crear o actualizar el archivo `.env.local` en la raíz del proyecto:

```env
# Wazuh Manager API
WAZUH_API_URL=https://122.122.122.122:55000
WAZUH_API_USER=wazuh-filip
WAZUH_API_PASSWORD=CAMBIAR_POR_PASSWORD_REAL

# Wazuh Indexer API
WAZUH_INDEXER_URL=https://122.122.122.122:9200
WAZUH_INDEXER_USER=CAMBIAR_POR_USUARIO_INDEXER
WAZUH_INDEXER_PASSWORD=CAMBIAR_POR_PASSWORD_INDEXER

# Solo para laboratorio si Wazuh usa certificado autofirmado.
# No usar en producción.
# NODE_TLS_REJECT_UNAUTHORIZED=0
```

Asegurar que `.gitignore` contiene:

```gitignore
.env.local
.env*.local
node_modules
.next
```

---

## Dependencias

No debería hacer falta instalar librerías nuevas para la integración básica, porque Next.js ya incluye `fetch` en runtime Node.

Si se quiere validar variables de entorno con esquema, se puede añadir después `zod`, pero no es obligatorio.

Comandos base:

```powershell
npm install
npm audit
npm run dev
```

---

## Archivos a crear

Crear estos archivos:

```txt
lib/wazuh.ts
lib/wazuh-indexer.ts
lib/argos-normalizers.ts
app/api/wazuh/agents/route.ts
app/api/wazuh/manager/route.ts
app/api/wazuh/alerts/route.ts
app/api/argos/live/route.ts
```

Opcionalmente crear:

```txt
components/WazuhConnectionStatus.tsx
components/LiveWazuhProvider.tsx
```

---

# 1. Cliente para Wazuh Manager API

Crear `lib/wazuh.ts`:

```ts
const WAZUH_API_URL = process.env.WAZUH_API_URL;
const WAZUH_API_USER = process.env.WAZUH_API_USER;
const WAZUH_API_PASSWORD = process.env.WAZUH_API_PASSWORD;

function assertWazuhApiEnv() {
  if (!WAZUH_API_URL || !WAZUH_API_USER || !WAZUH_API_PASSWORD) {
    throw new Error(
      "Missing Wazuh API environment variables: WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD"
    );
  }
}

async function getWazuhToken(): Promise<string> {
  assertWazuhApiEnv();

  const basicAuth = Buffer.from(
    `${WAZUH_API_USER}:${WAZUH_API_PASSWORD}`
  ).toString("base64");

  const response = await fetch(
    `${WAZUH_API_URL}/security/user/authenticate?raw=true`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
      },
      cache: "no-store",
    }
  );

  if (!response.ok) {
    throw new Error(`Wazuh authentication failed: ${response.status}`);
  }

  return response.text();
}

export async function wazuhApiGet<T>(endpoint: string): Promise<T> {
  assertWazuhApiEnv();

  const token = await getWazuhToken();

  const response = await fetch(`${WAZUH_API_URL}${endpoint}`, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
    cache: "no-store",
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(
      `Wazuh API request failed: ${response.status} ${response.statusText} ${body}`
    );
  }

  return response.json() as Promise<T>;
}
```

---

# 2. Cliente para Wazuh Indexer API

Crear `lib/wazuh-indexer.ts`:

```ts
const WAZUH_INDEXER_URL = process.env.WAZUH_INDEXER_URL;
const WAZUH_INDEXER_USER = process.env.WAZUH_INDEXER_USER;
const WAZUH_INDEXER_PASSWORD = process.env.WAZUH_INDEXER_PASSWORD;

function assertWazuhIndexerEnv() {
  if (!WAZUH_INDEXER_URL || !WAZUH_INDEXER_USER || !WAZUH_INDEXER_PASSWORD) {
    throw new Error(
      "Missing Wazuh Indexer environment variables: WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD"
    );
  }
}

export async function wazuhIndexerSearch<T>(body: unknown): Promise<T> {
  assertWazuhIndexerEnv();

  const basicAuth = Buffer.from(
    `${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}`
  ).toString("base64");

  const response = await fetch(
    `${WAZUH_INDEXER_URL}/wazuh-alerts-*/_search`,
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/json",
      },
      cache: "no-store",
      body: JSON.stringify(body),
    }
  );

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Wazuh Indexer request failed: ${response.status} ${response.statusText} ${text}`
    );
  }

  return response.json() as Promise<T>;
}

export async function getRecentWazuhAlerts(limit = 50) {
  return wazuhIndexerSearch({
    size: limit,
    sort: [
      {
        "@timestamp": {
          order: "desc",
        },
      },
    ],
    query: {
      range: {
        "@timestamp": {
          gte: "now-24h",
          lte: "now",
        },
      },
    },
  });
}
```

---

# 3. API Route para agentes

Crear `app/api/wazuh/agents/route.ts`:

```ts
import { NextResponse } from "next/server";
import { wazuhApiGet } from "@/lib/wazuh";

export const runtime = "nodejs";

export async function GET() {
  try {
    const data = await wazuhApiGet("/agents?limit=100");

    return NextResponse.json({
      ok: true,
      source: "wazuh-manager",
      data,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        source: "wazuh-manager",
        error: error instanceof Error ? error.message : "Unknown Wazuh API error",
      },
      { status: 500 }
    );
  }
}
```

---

# 4. API Route para manager

Crear `app/api/wazuh/manager/route.ts`:

```ts
import { NextResponse } from "next/server";
import { wazuhApiGet } from "@/lib/wazuh";

export const runtime = "nodejs";

export async function GET() {
  try {
    const data = await wazuhApiGet("/manager/info");

    return NextResponse.json({
      ok: true,
      source: "wazuh-manager",
      data,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        source: "wazuh-manager",
        error: error instanceof Error ? error.message : "Unknown Wazuh manager error",
      },
      { status: 500 }
    );
  }
}
```

---

# 5. API Route para alertas

Crear `app/api/wazuh/alerts/route.ts`:

```ts
import { NextResponse } from "next/server";
import { getRecentWazuhAlerts } from "@/lib/wazuh-indexer";

export const runtime = "nodejs";

export async function GET() {
  try {
    const data = await getRecentWazuhAlerts(100);

    return NextResponse.json({
      ok: true,
      source: "wazuh-indexer",
      data,
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        source: "wazuh-indexer",
        error: error instanceof Error ? error.message : "Unknown Wazuh Indexer error",
      },
      { status: 500 }
    );
  }
}
```

---

# 6. Normalizador para ARGOS-SOC IA

Crear `lib/argos-normalizers.ts`.

Este archivo debe convertir datos crudos de Wazuh en una estructura limpia que puedan usar:

- globo 3D,
- feed lateral,
- KPI cards,
- gráficos inferiores,
- tabla de agentes,
- métricas de severidad.

Ejemplo inicial:

```ts
export type ArgosSeverity = "critical" | "high" | "medium" | "low" | "info";

export type ArgosAttack = {
  id: string;
  timestamp: string;
  sourceIp: string;
  sourceCountry: string;
  sourceLat: number;
  sourceLng: number;
  targetAgent: string;
  targetIp?: string;
  targetLat: number;
  targetLng: number;
  ruleId?: string;
  ruleDescription: string;
  attackType: string;
  severity: ArgosSeverity;
  aiScore: number;
  sensor: "wazuh" | "suricata" | "zeek" | "mcp" | "hybrid";
  mitreTactic?: string;
};

export type ArgosKpis = {
  totalEvents24h: number;
  correlatedAlerts: number;
  aiAnomalies: number;
  criticalIncidents: number;
  activeAgents: number;
  disconnectedAgents: number;
  meanRiskScore: number;
};

export function mapWazuhLevelToSeverity(level?: number): ArgosSeverity {
  if (!level && level !== 0) return "info";
  if (level >= 12) return "critical";
  if (level >= 9) return "high";
  if (level >= 6) return "medium";
  if (level >= 3) return "low";
  return "info";
}

export function estimateAiScoreFromWazuhLevel(level?: number): number {
  if (!level && level !== 0) return 20;
  return Math.min(100, Math.max(5, Math.round(level * 7.5)));
}

export function inferAttackType(description?: string): string {
  const text = description?.toLowerCase() ?? "";

  if (text.includes("brute") || text.includes("authentication failure")) {
    return "Brute Force";
  }

  if (text.includes("scan") || text.includes("nmap")) {
    return "Port Scan";
  }

  if (text.includes("sql")) {
    return "SQL Injection";
  }

  if (text.includes("malware") || text.includes("trojan")) {
    return "Malware";
  }

  if (text.includes("privilege") || text.includes("sudo")) {
    return "Privilege Escalation";
  }

  return "Suspicious Activity";
}
```

El agente debe ampliar este normalizador cuando conozca la forma exacta de las respuestas reales del Indexer.

---

# 7. Endpoint unificado para la web

Crear `app/api/argos/live/route.ts`.

Este endpoint debe ser el que consuma el frontend principal.

Objetivo:

```txt
/api/argos/live
```

Debe devolver un objeto ya listo para la UI:

```ts
{
  ok: true,
  updatedAt: string,
  manager: {...},
  agents: [...],
  attacks: [...],
  kpis: {...},
  charts: {
    attacksByType: [...],
    severityDistribution: [...],
    alertsTimeline: [...],
    topCountries: [...],
    mitreTactics: [...],
    riskDistribution: [...],
    correlationSources: [...]
  }
}
```

Implementación inicial:

```ts
import { NextResponse } from "next/server";
import { wazuhApiGet } from "@/lib/wazuh";
import { getRecentWazuhAlerts } from "@/lib/wazuh-indexer";

export const runtime = "nodejs";

export async function GET() {
  try {
    const [agents, manager, alerts] = await Promise.allSettled([
      wazuhApiGet("/agents?limit=100"),
      wazuhApiGet("/manager/info"),
      getRecentWazuhAlerts(100),
    ]);

    return NextResponse.json({
      ok: true,
      updatedAt: new Date().toISOString(),
      manager: manager.status === "fulfilled" ? manager.value : null,
      agents: agents.status === "fulfilled" ? agents.value : null,
      alerts: alerts.status === "fulfilled" ? alerts.value : null,
      errors: {
        manager: manager.status === "rejected" ? manager.reason?.message : null,
        agents: agents.status === "rejected" ? agents.reason?.message : null,
        alerts: alerts.status === "rejected" ? alerts.reason?.message : null,
      },
    });
  } catch (error) {
    return NextResponse.json(
      {
        ok: false,
        error: error instanceof Error ? error.message : "Unknown ARGOS live error",
      },
      { status: 500 }
    );
  }
}
```

Después, reemplazar la respuesta cruda por datos normalizados usando `lib/argos-normalizers.ts`.

---

# 8. Conexión con el frontend

El frontend no debe consumir `/api/wazuh/agents` y `/api/wazuh/alerts` directamente salvo para pruebas.

La página principal debe consumir:

```txt
/api/argos/live
```

Crear o actualizar un hook:

```ts
import { useEffect, useState } from "react";

export function useArgosLiveData(refreshMs = 10000) {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const response = await fetch("/api/argos/live", {
          cache: "no-store",
        });

        const json = await response.json();

        if (!response.ok || !json.ok) {
          throw new Error(json.error ?? "Failed to load ARGOS live data");
        }

        if (!cancelled) {
          setData(json);
          setError(null);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Unknown error");
          setLoading(false);
        }
      }
    }

    load();
    const interval = window.setInterval(load, refreshMs);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [refreshMs]);

  return { data, error, loading };
}
```

---

# 9. Cómo alimentar el globo 3D

El componente `AttackGlobe.tsx` debe recibir datos como props.

Objetivo:

```tsx
<AttackGlobe attacks={data.attacks} />
```

Cada ataque debe contener:

```ts
{
  sourceLat: number;
  sourceLng: number;
  targetLat: number;
  targetLng: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
  attackType: string;
  sourceCountry: string;
  targetAgent: string;
  aiScore: number;
}
```

Si una alerta Wazuh no tiene geolocalización, usar fallback temporal:

```txt
sourceLat/sourceLng: país desconocido o coordenadas mock por IP privada
```

Más adelante se puede integrar GeoIP real.

---

# 10. Geolocalización IP

Wazuh no siempre tendrá latitud/longitud directamente.

Implementación por fases:

## Fase A — mock seguro

Si no hay GeoIP, asignar coordenadas aproximadas por país o región simulada.

## Fase B — GeoIP local

Usar una base MaxMind GeoLite2 local en backend.

No consultar servicios públicos por cada alerta en frontend.

## Fase C — Enriquecimiento previo

Enriquecer eventos antes de llegar a la UI:

```txt
Wazuh/Indexer → proceso de enriquecimiento → coordenadas → ARGOS-SOC IA
```

---

# 11. Dashboard inferior

Los datos de `/api/argos/live` deben alimentar:

## KPIs

- Total Events 24h
- Correlated Alerts
- AI Anomalies
- Critical Incidents
- Active Agents
- Disconnected Agents
- Mean AI Risk Score

## Gráficos

- Ataques por tipo
- Distribución por severidad
- Alertas por hora
- Top países origen
- Top agentes atacados
- Tácticas MITRE
- Distribución de AI Risk Score
- Correlación por fuente

---

# 12. Manejo de errores visible en UI

Si Wazuh no responde, la web debe seguir funcionando.

Mostrar estado:

```txt
WAZUH: OFFLINE
INDEXER: OFFLINE
MCP: MOCK MODE
AI ENGINE: MOCK MODE
```

No romper la página completa.

Comportamiento deseado:

1. Si `/api/argos/live` funciona, mostrar datos reales.
2. Si falla Wazuh API pero funciona Indexer, mostrar alertas y marcar agentes como desconocidos.
3. Si falla Indexer pero funciona Wazuh API, mostrar agentes y estado del manager.
4. Si falla todo, volver a datos mock y mostrar banner `DEMO MODE`.

---

# 13. Pruebas manuales

Después de implementar, probar:

```powershell
npm install
npm audit
npm run build
npm run dev
```

Probar endpoints en navegador:

```txt
http://localhost:3000/api/wazuh/manager
http://localhost:3000/api/wazuh/agents
http://localhost:3000/api/wazuh/alerts
http://localhost:3000/api/argos/live
```

También probar con PowerShell:

```powershell
Invoke-RestMethod http://localhost:3000/api/wazuh/manager
Invoke-RestMethod http://localhost:3000/api/wazuh/agents
Invoke-RestMethod http://localhost:3000/api/wazuh/alerts
Invoke-RestMethod http://localhost:3000/api/argos/live
```

---

# 14. Problemas frecuentes

## Error de certificado

Síntoma:

```txt
self-signed certificate
unable to verify the first certificate
```

Soluciones:

- Laboratorio temporal: `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- Solución correcta: instalar CA/certificado válido.

## Error 401

Revisar:

- usuario,
- contraseña,
- endpoint,
- si el usuario tiene permisos suficientes.

## Error ETIMEDOUT

Revisar:

- IP,
- VPN,
- firewall,
- puerto 55000,
- puerto 9200,
- conectividad desde la máquina donde corre Next.

## Error 403 en Indexer

Revisar permisos del usuario del Indexer.

## La web carga pero no hay alertas

Revisar índice:

```txt
wazuh-alerts-*
```

Puede variar según versión/configuración.

---

# 15. Criterios de aceptación

La tarea se considera completada cuando:

1. Existe `.env.local` con variables Wazuh.
2. No hay credenciales en archivos `.ts` o `.tsx`.
3. `/api/wazuh/manager` responde o devuelve error controlado.
4. `/api/wazuh/agents` responde o devuelve error controlado.
5. `/api/wazuh/alerts` responde o devuelve error controlado.
6. `/api/argos/live` devuelve estructura unificada para la UI.
7. La página principal puede usar datos reales o volver a mock mode si Wazuh falla.
8. El globo puede recibir ataques normalizados.
9. El dashboard inferior puede recibir KPIs y gráficos normalizados.
10. `npm run build` funciona.
11. `npm audit` no muestra vulnerabilidades críticas o altas.

---

# 16. Resultado esperado

Al finalizar, ARGOS-SOC IA debe dejar de depender de datos manuales y pasar a obtener información real desde Wazuh.

La interfaz debe mostrar:

- agentes Wazuh activos/desconectados,
- alertas recientes,
- severidad,
- eventos críticos,
- origen aproximado de amenazas,
- feed SOC en vivo,
- KPIs operacionales,
- gráficos de actividad,
- estado de servicios,
- base preparada para MCP agents e IA real.

La integración debe mantener la estética de pantalla de mando global y reforzar la finalidad del TFM: monitorizar, correlacionar, priorizar y visualizar amenazas usando SIEM + IDS/IPS + IA.
