# CONTEXT.md — ARGOS-SOC IA

## 1. Visión general del proyecto

**ARGOS-SOC IA** es una plataforma web de visualización y monitorización de ciberseguridad orientada a un entorno **SIEM + IDS/IPS + IA**. El objetivo es construir una pantalla de mando moderna, inspirada visualmente en interfaces tipo OSIRIS, pero adaptada a un caso realista de SOC académico/profesional.

La idea principal es mostrar, de forma visual e interactiva, los ataques que llegan desde distintas zonas geográficas, su relación con agentes desplegados, fuentes de telemetría de seguridad y puntuaciones de riesgo generadas por modelos de inteligencia artificial.

El proyecto parte del TFM **SIEM_IDS_IPS_IA**, cuyo objetivo es diseñar una arquitectura reproducible de monitorización y detección basada en:

- SIEM, especialmente Wazuh.
- IDS/IPS, como Suricata y/o Zeek.
- Agentes distribuidos.
- MCP agents o servicios de automatización/orquestación.
- Modelos de IA/ML para detección de anomalías.
- Dashboards, alertas, correlación y priorización operacional.

El frontend actual debe ser una primera versión visual hecha con **Next.js**, inicialmente usando datos simulados, pero preparada para conectarse después a fuentes reales.

---

## 2. Nombre e identidad

### Nombre del sistema

**ARGOS-SOC IA**

### Significado conceptual

ARGOS representa vigilancia continua, múltiples puntos de observación y capacidad de supervisión global. El nombre encaja con una plataforma que observa eventos procedentes de red, endpoints, agentes, sensores IDS/IPS, SIEM y modelos de IA.

### Subtítulo recomendado

**Global Threat Monitoring for SIEM · IDS/IPS · AI**

O también:

**Wazuh · Suricata · Zeek · MCP Agents · AI Risk Engine**

---

## 3. Objetivo funcional

Construir una web estilo pantalla de mando SOC donde se pueda visualizar:

- De dónde llegan los ataques.
- A qué agentes, hosts o zonas internas afectan.
- Qué fuente los detecta: Wazuh, Suricata, Zeek, MCP, IA o combinaciones.
- Qué severidad tienen.
- Qué score de anomalía o riesgo les asigna la IA.
- Qué eventos están correlacionados.
- Qué actividad debería priorizar un analista.

En la primera fase, la web funciona con datos mock. En fases posteriores deberá conectarse a datos reales de Wazuh, sensores IDS/IPS, MCP agents y pipelines de IA.

---

## 4. Objetivo académico y de TFM

La web no debe ser solo una visualización bonita. Debe representar visualmente la arquitectura y la aportación del TFM:

```text
Telemetry Sources
      ↓
Wazuh / Suricata / Zeek / MCP Agents
      ↓
SIEM Correlation
      ↓
AI Risk Scoring
      ↓
SOC Prioritization
      ↓
Optional IPS / Response Actions
```

El sistema busca demostrar cómo una arquitectura híbrida puede ayudar a:

- Centralizar eventos de seguridad.
- Normalizar telemetría heterogénea.
- Correlacionar señales de distintas fuentes.
- Reducir fatiga de alertas.
- Priorizar incidentes mediante IA.
- Evaluar utilidad operacional, no solo métricas ML clásicas.

---

## 5. Estilo visual deseado

La interfaz debe parecer una **pantalla de mando de ciberseguridad**, no un dashboard administrativo tradicional.

### Inspiración

- OSIRIS-like command interface.
- Global intelligence platform.
- SOC / cyber command center.
- Interfaces oscuras, densas, técnicas y operativas.

### Sensación buscada

- Profesional.
- Futurista.
- Técnica.
- Defendible académicamente.
- Visualmente impactante.
- No excesivamente “hacker verde” ni estilo videojuego.

### Paleta recomendada

- Fondo principal: negro azulado / navy oscuro.
- Paneles: azul petróleo oscuro con transparencia.
- Bordes: cian tenue.
- Texto principal: blanco/gris claro.
- Texto secundario: gris azulado.

### Colores por severidad

- Critical: rojo.
- High: naranja.
- Medium: amarillo.
- Low: cian/azul.
- AI anomaly: violeta.

---

## 6. Estructura de la interfaz

La página debe dividirse en dos grandes bloques:

1. **Pantalla de mando superior**.
2. **Mini-dashboard analítico inferior**.

---

## 7. Pantalla de mando superior

Esta es la zona principal y debe ocupar la mayor parte de la vista inicial.

### 7.1. Topbar

La barra superior debe mostrar:

- Nombre: **ARGOS-SOC IA**.
- Subtítulo o misión.
- Estado de servicios.
- Hora local o UTC.
- Nivel global de amenaza.

Ejemplo:

```text
ARGOS-SOC IA   |   WAZUH: ONLINE   |   MCP: 12 AGENTS   |   SURICATA: RUNNING   |   AI ENGINE: ACTIVE   |   THREAT LEVEL: HIGH
```

### 7.2. Sidebar izquierda

Panel de capas, filtros y estado de sensores.

Debe incluir elementos como:

```text
LAYERS
[x] Wazuh Alerts
[x] Suricata IDS
[x] Zeek Flows
[x] MCP Agents
[x] AI Anomalies
[ ] IPS Auto-Block
[ ] Cowrie Honeypot
```

Filtros recomendados:

- Región.
- Severidad.
- Tipo de ataque.
- Fuente de detección.
- Agente afectado.

También puede incluir un pequeño bloque de estado:

```text
SENSORS
Wazuh Manager: Online
Suricata Sensor: Running
Zeek Sensor: Running
MCP Agents: Active
AI Engine: Active
```

### 7.3. Centro: globo 3D

El globo 3D debe ser el protagonista visual de la página.

Debe permitir:

- Rotación libre.
- Zoom.
- Movimiento interactivo.
- Arcos de ataque origen → destino.
- Puntos de impacto.
- Ondas o ripples en destinos activos.
- Colores por severidad.
- Tooltips con información operacional.

Tooltip recomendado:

```text
Attack: SSH Brute Force
Source: Moscow, RU
Target: agent-linux-01
Sensor: Wazuh + Suricata
AI Score: 94
Severity: Critical
```

### 7.4. Panel derecho

Panel SOC de actividad viva.

Debe incluir:

- Live alerts feed.
- Últimos incidentes IA.
- Top targeted agents.
- Top attack types.
- Eventos críticos recientes.

Ejemplo:

```text
19:41:22  CRITICAL  SSH Brute Force     RU → agent-linux-01   AI 94
19:40:58  HIGH      Port Scan           CN → dmz-fw-01        AI 87
19:40:11  MEDIUM    Suspicious Auth     BR → ad-server-02     AI 72
```

### 7.5. Barra inferior de la pantalla de mando

Pequeña franja que represente el pipeline de detección:

```text
Telemetry → SIEM Correlation → AI Scoring → SOC Prioritization → Response
```

O una cadena tipo kill chain:

```text
Reconnaissance → Brute Force → Privilege Attempt → Lateral Movement → Exfil Signal
```

---

## 8. Mini-dashboard inferior

Debajo de la pantalla de mando debe existir un dashboard compacto con métricas y gráficos.

El objetivo es complementar la vista global con analítica operacional.

### 8.1. KPI cards

Tarjetas numéricas recomendadas:

- Total Events 24h.
- Correlated Alerts.
- AI Anomalies Detected.
- Critical Incidents.
- Active Agents.
- Blocked by IPS.
- Mean AI Risk Score.
- False Positive Reduction.

Ejemplo:

```text
Total Events: 128,432
Correlated Alerts: 1,245
AI Anomalies: 84
Critical Incidents: 12
Active Agents: 37
Mean Risk Score: 78
```

### 8.2. Gráficos recomendados

#### Ataques por tipo

Gráfico de barras con categorías como:

- Brute Force.
- Port Scan.
- SQL Injection.
- Malware.
- Lateral Movement.
- Privilege Escalation.

#### Distribución por severidad

Pie chart o donut chart:

- Critical.
- High.
- Medium.
- Low.
- Informational.

#### Evolución temporal

Gráfico lineal:

- Alertas por hora.
- Eventos IA por hora.
- Comparativa total alerts vs AI risk events.

#### Top países origen

Barras horizontales o lista compacta:

- Russia.
- China.
- United States.
- Brazil.
- Germany.

#### Top agentes objetivo

Lista o barras:

- web-01.
- agent-linux-01.
- ad-server-02.
- dmz-fw-01.
- database-01.

#### MITRE tactics

Gráfico de barras o donut:

- Initial Access.
- Execution.
- Persistence.
- Discovery.
- Lateral Movement.
- Exfiltration.

#### AI risk distribution

Distribución por rangos:

- 0–20.
- 21–40.
- 41–60.
- 61–80.
- 81–100.

#### Correlation sources

Mostrar cuántos eventos vienen de:

- Wazuh only.
- Suricata only.
- Zeek only.
- MCP only.
- Wazuh + Suricata.
- Wazuh + AI.
- Suricata + AI.
- All combined.

---

## 9. Datos iniciales mock

La primera versión puede usar datos simulados definidos en TypeScript.

Estructura recomendada para un ataque:

```ts
export type AttackEvent = {
  id: string;
  timestamp: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  source: {
    ip: string;
    city: string;
    country: string;
    lat: number;
    lng: number;
  };
  target: {
    agentId: string;
    hostname: string;
    zone: string;
    lat: number;
    lng: number;
  };
  sensors: Array<'wazuh' | 'suricata' | 'zeek' | 'mcp' | 'ai'>;
  wazuhRuleId?: string;
  suricataSid?: string;
  mitreTactic?: string;
  aiScore: number;
  status: 'new' | 'correlated' | 'investigating' | 'blocked' | 'closed';
};
```

---

## 10. Futuras integraciones reales

### 10.1. Wazuh

La web debería poder conectarse en el futuro a:

- Wazuh API.
- Alertas de Wazuh.
- Estado de agentes.
- Reglas y grupos.
- Severidad.
- MITRE mappings.

Datos útiles:

- `rule.id`.
- `rule.level`.
- `rule.description`.
- `agent.id`.
- `agent.name`.
- `agent.ip`.
- `data.srcip`.
- `data.dstip`.
- `mitre.tactic`.
- `mitre.technique`.

### 10.2. Suricata

Integración futura con eventos `eve.json`:

- Alertas IDS.
- Signatures.
- Source IP.
- Destination IP.
- Protocol.
- Flow.
- Severity.

Datos útiles:

- `src_ip`.
- `dest_ip`.
- `alert.signature`.
- `alert.category`.
- `alert.severity`.
- `proto`.
- `flow_id`.

### 10.3. Zeek

Integración futura con logs transaccionales:

- `conn.log`.
- `dns.log`.
- `http.log`.
- `ssl.log`.
- `notice.log`.

Útil para enriquecer contexto y correlación.

### 10.4. MCP agents

Los MCP agents pueden representar servicios auxiliares para:

- Consultar fuentes.
- Automatizar enriquecimiento.
- Ejecutar tareas de triage.
- Coordinar acciones seguras.
- Consultar modelos o herramientas externas.

### 10.5. Motor IA

La IA debe aportar:

- Score de anomalía.
- Clasificación de riesgo.
- Priorización.
- Detección de comportamiento raro.
- Agrupación de eventos similares.
- Señales para correlación.

---

## 11. Arquitectura frontend esperada

Tecnologías principales:

- Next.js.
- React.
- TypeScript.
- Tailwind CSS o CSS moderno.
- react-globe.gl.
- Three.js.

Estructura recomendada:

```text
app/
  layout.tsx
  page.tsx
  globals.css

components/
  TopBar.tsx
  CommandSidebar.tsx
  AttackGlobe.tsx
  LiveThreatFeed.tsx
  DetectionPipeline.tsx
  MiniDashboard.tsx
  KpiCard.tsx
  charts/
    BarChart.tsx
    DonutChart.tsx
    LineChart.tsx
    HorizontalBarChart.tsx

lib/
  mock-data.ts
  types.ts
  metrics.ts
  formatters.ts
```

---

## 12. Prioridades de desarrollo

### Fase 1 — Diseño visual

- Branding ARGOS-SOC IA.
- Pantalla de mando completa.
- Globo 3D protagonista.
- Paneles laterales.
- Dashboard inferior.

### Fase 2 — Interactividad

- Filtros por severidad.
- Filtros por fuente.
- Selección de ataque.
- Tooltips enriquecidos.
- Detalle de agente afectado.

### Fase 3 — Datos reales

- Endpoint mock `/api/attacks`.
- Adaptador Wazuh.
- Adaptador Suricata.
- Adaptador MCP.
- Normalización común de eventos.

### Fase 4 — IA y correlación

- Ingesta de scores IA.
- Correlación temporal.
- Priorización por riesgo.
- Dashboard de rendimiento operacional.

### Fase 5 — Respuesta limitada

- Simulación de bloqueo IPS.
- Estado de respuesta.
- Acciones reversibles.
- Evidencia para defensa del TFM.

---

## 13. Principios de diseño

1. El globo 3D debe ser protagonista, no un elemento decorativo.
2. Cada visualización debe tener sentido SOC.
3. Los datos mock deben parecer realistas.
4. La UI debe comunicar correlación, IA y priorización.
5. La estética debe ser seria, técnica y moderna.
6. La web debe estar preparada para evolucionar hacia datos reales.
7. No se debe mostrar automatización peligrosa sin controles.
8. La respuesta IPS debe tratarse como simulada o limitada hasta validación.

---

## 14. Resultado esperado

El resultado final esperado es una plataforma web tipo command center que permita presentar el TFM de forma visual, clara y profesional.

Debe transmitir que ARGOS-SOC IA es capaz de:

- Observar actividad global de amenazas.
- Mostrar ataques por zona geográfica.
- Relacionar ataques con agentes Wazuh/MCP.
- Visualizar señales de IDS/IPS.
- Mostrar scores de IA.
- Priorizar eventos para analistas.
- Reducir ruido mediante correlación.
- Servir como base para una integración real con SIEM, IDS/IPS y modelos ML.

---

## 15. Resumen corto

**ARGOS-SOC IA** busca ser una pantalla de mando SOC para el proyecto SIEM_IDS_IPS_IA. La web debe mostrar ataques globales en un globo 3D interactivo, conectarlos con agentes Wazuh/MCP y sensores IDS/IPS, añadir puntuaciones de riesgo de IA y complementar la vista con un dashboard inferior de métricas y gráficos. Inicialmente funcionará con datos mock en Next.js, pero debe estar diseñada para conectarse después a datos reales de Wazuh, Suricata, Zeek, MCP agents y modelos de anomalías.
