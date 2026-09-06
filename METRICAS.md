# ARGOS-SOC IA — Qué muestra la aplicación

Inventario de cada pantalla, cada métrica y qué representa en el proyecto.
Se indica siempre **de dónde sale el número** y, cuando procede, qué **no**
significa.

> Convención usada en este documento:
> **[real]** calculado sobre datos vivos · **[fijo]** valor escrito en el código,
> no refleja estado · **[derivado]** calculado a partir de otra métrica ·
> **[externo]** viene de un servicio de terceros.

---

## 0. Arquitectura en una frase

La aplicación **no almacena nada**. Lee de Wazuh (API REST del manager +
Indexer/OpenSearch), enriquece con modelos de IA y catálogos externos, y
presenta. Dos rutas independientes:

| Ruta | Qué hace |
|---|---|
| `/` | Panel de mando en vivo. Sondea `/api/argos/live` cada 5 s. |
| `/simulacro` | Reproduce alertas contra el modelo de bloqueo. Sin acciones. |

Un proceso aparte, el **sidecar** (`127.0.0.1:8973`), mantiene los modelos
cargados en memoria. Si no está levantado, la web se repliega a lanzar
subprocesos Python y todo sigue funcionando, solo que más lento (15 s frente
a 4,3 s por refresco).

---

## 1. Barra superior (`CommandTopbar`)

| Indicador | Origen | Qué representa |
|---|---|---|
| `MANAGER` | **[real]** | `ONLINE`/`OFFLINE` según responda `/manager/info`. |
| `INDEXER` | **[real]** | Si la consulta de alertas al Indexer tuvo éxito. |
| `ALERTAS` | **[real]** | Alertas cargadas en este refresco. |
| `AI SCORE` | **[derivado]** | Media del `score` de las alertas cargadas. |
| `THREAT` | **[derivado]** | `HIGH` si hay más de una alerta crítica, si no `ELEVATED`. |

> Aquí había antes `MCP · 12 AGENTS` y `SURICATA · RUNNING`, ambos escritos a
> mano. Retirados: ni MCP ni Suricata están integrados. Sustituidos por estado
> del Indexer y recuento de alertas, que sí se miden.

---

## 2. Barra lateral (`CommandSidebar`)

| Elemento | Origen | Qué representa |
|---|---|---|
| **Top targets** | **[real]** | Los cuatro agentes con más alertas, ordenados por volumen. |
| Recuento junto a cada objetivo | **[real]** | Alertas dirigidas a ese agente. Antes eran `96/87/78/69` por posición, decorativos. |
| **Regions** | **[real]** | Filtro por continente, deducido de la latitud/longitud del origen. |
| **Agent Health** | **[real]** | Seis filas de estado, detalladas abajo. |

### Agent Health — las seis filas

| Fila | Qué mide |
|---|---|
| Wazuh Manager | Si responde la API REST. |
| Wazuh Agents | Agentes activos y desconectados según el inventario. |
| Wazuh Indexer | Si la consulta de alertas tuvo éxito, y cuántas se cargaron. |
| GeoIP Enrichment | Coordenadas **reales** frente a **aproximadas**, separadas. |
| Risk Scoring | Si el modelo de IA respondió, con el score medio. |
| Flow Average | Eventos de 24 h dividido entre 1.440 → flujos por minuto. |

> Había una séptima fila, `MCP Agents`, permanentemente en `planned`. Retirada:
> no hay integración MCP en el proyecto.

---

## 3. Globo 3D (`AttackGlobe`)

Representación geoespacial de los ataques. Solo dibuja las alertas de los
**últimos 120 segundos**, para que el globo respire en vez de saturarse.

| Capa | Qué representa |
|---|---|
| **Arcos** | Trayecto origen → agente destino. Color según severidad. |
| **Puntos** | Orígenes geolocalizados y agentes destino. |
| **Anillos** | Pulso sobre el destino. Radio mayor si la severidad es crítica. |

> **Geolocalización de reserva:** si una alerta no trae coordenadas, se le
> asigna un punto de una lista fija mediante un hash de la IP. Esas alertas
> llevan ahora la marca `geoApproximate` y su origen se muestra como
> **«ciudad (aprox.)»** tanto en el globo como en el feed. La fila GeoIP de
> salud separa reales de aproximadas. Medido: **657 de 10.001 (6,6 %)**.

### Tabla de alertas del globo

Ocho columnas, paginadas de diez en diez:

`SEVERIDAD` · `TIPO` · `ORIGEN` · `IP` · `DESTINO` · `REGLA` · `AI SCORE` · `CLASIFICACIÓN`

Al pulsar una fila se abre la **ficha de detalle**, documentada en la sección
3.1.

### 3.1 Ficha de detalle de una alerta

Diecinueve campos. Los ocho primeros son hechos de la alerta; el resto son
salidas de modelos y etiquetas internas.

#### Identificación y contexto

| Campo | Qué representa |
|---|---|
| **Origen** | Ciudad y país de la IP. Lleva `(aprox.)` si las coordenadas son de reserva. |
| **IP origen** | Dirección atacante. `unknown` si la alerta no la trae. |
| **Coordenadas** | Latitud y longitud del origen, con cuatro decimales. |
| **Destino** | Nombre del agente Wazuh que registró la alerta. |
| **Agente** | El mismo agente. Duplicado histórico de «Destino». |
| **Zona** | Ciudad o país usado para agrupar en el filtro de regiones. Medido: 51 valores distintos. |
| **Táctica** | Táctica MITRE ATT&CK. De `rule.mitre.tactic` si existe; si no, se infiere del tipo. Medido: `Credential Access` en el 97 %. |
| **Wazuh rule** | Identificador numérico de la regla que disparó. |

#### Salidas del modelo de ventana (LAB-ALERTS)

| Campo | Qué representa |
|---|---|
| **AI `<n>`** (cabecera) | Score de ventana ×100. **Es del minuto del agente, no de esta alerta.** Ver sección 5. |
| **Modelo IA** | Identificador y versión del modelo que produjo el score. Sirve para trazar qué artefacto decidió. |
| **Predicción IA** | `attack` o `benign`, con la confianza. La confianza es la probabilidad de la clase elegida, no una medida de fiabilidad del modelo. |
| **Predicción taxonómica IA** | Familia de actividad de un segundo modelo multiclase que comparte contrato de características. **Es enriquecimiento, nunca la decisión de ataque.** Medido: `CredentialAccess` en el 99 %. |

#### Bloque CSR-LANL — capa experimental

> **Advertencia previa: estos cuatro campos no son interpretables en ARGOS.**
> Se muestran porque la capa está integrada, pero ver el aviso al final del
> bloque antes de citarlos en ninguna parte.

CSR-LANL es un modelo entrenado sobre un corpus público de registros de
autenticación, flujos de red, DNS y procesos, con actividad de equipo rojo
etiquetada. Trabaja con **209 características sobre ventanas de una hora
agrupadas por entidad**, sobre 13,1 millones de ventanas y 16.155 entidades.

| Campo | Qué representa |
|---|---|
| **CSR-LANL entidad** | La entidad puntuada. En ARGOS se mapea al **identificador del agente** (`025`, `011`…), no a un usuario o equipo como en el corpus original. |
| **CSR-LANL clasificación** | Tres niveles por umbral sobre el score supervisado: `low_signal` (< 0,95), `suspicious_entity` (0,95–0,9893), `high_risk_entity` (≥ 0,9893). Medido en vivo: **el 100 % son `low_signal`**. |
| **CSR-LANL score** | Score supervisado ×100. Probabilidad de que la entidad se parezca a las ventanas con actividad de equipo rojo del corpus. Medido: rango 0,0012–0,9220. |
| **Anomalía entidad** | Score de un IsolationForest auxiliar. Mide **rareza conductual**, no ataque. El propio paquete lo declara «enriquecimiento y explicación, no decisión primaria». |
| **Novedad contexto** | Fracción de indicadores de novedad activos: usuario nuevo, máquina destino nueva, proceso nuevo, par origen-destino nuevo… |

**Por qué no son interpretables aquí.** El paquete requiere las mismas 209
columnas del entrenamiento y trata las ausentes como error de esquema. Wazuh no
produce esas familias de datos, así que el adaptador **rellena con cero** todo
lo que falta. Su propia salida lo declara:

> «CSR-LANL model was trained on auth/flow/dns/proc windows; ARGOS Wazuh adapter
> fills unavailable feature families with zero.»

Un modelo que recibe la mayoría de sus entradas a cero opera fuera de su
dominio. Y sus métricas de origen ya eran modestas: **ROC-AUC 0,940 pero PR-AUC
0,0168**, con precisión entre los cincuenta primeros resultados de 0,040 — dos
aciertos de cada cincuenta revisiones.

Se mantiene visible porque documenta una decisión del trabajo (probar
transferencia entre dominios y medir que no funciona), no porque aporte señal.

#### Etiquetas internas

| Campo | Qué representa | Estado |
|---|---|---|
| **Suricata SID** | Identificador de firma de Suricata. | **Siempre `N/A`.** Suricata no está integrado; medido sobre 10.001 alertas, un único valor. |
| **MCP tool** | Etiqueta de encaminamiento heredada. Tres valores: `auth.window` (95 %), `wazuh.triage` (5 %), `argos.local-simulator`. | Es una **clasificación de tipo de alerta**, no una herramienta MCP. El nombre es engañoso. |
| **Sensores** | Fuentes que contribuyeron. | **Siempre `Wazuh / AI Engine`.** Solo hay una fuente real. |

---

## 4. Feed de alertas (`ThreatFeed`)

Las **siete alertas más recientes**. Cada tarjeta lleva:

### Bloque base

| Campo | Origen | Qué representa |
|---|---|---|
| Severidad | **[real]** | Traducción de `rule.level`: crítica ≥12, alta ≥9, media ≥6, baja el resto. |
| Tipo | **[derivado]** | Inferido por palabras clave de la descripción de la regla. |
| Origen → destino | **[real]** | Ciudad/país de la IP y nombre del agente. |
| `AI <n>` | **[real]** | Score de **ventana**. Ver la advertencia de abajo. |
| `Rule <id>` | **[real]** | Identificador de la regla de Wazuh. |
| `mcpTool` | **[derivado]** | Etiqueta de encaminamiento. `auth.window`, `wazuh.triage` o `argos.local-simulator`. |

### `IP <n>` — riesgo por dirección **[real]**

```
IP 98   45.156.87.93   2c · 1m · /24 100% · bloquearía en aviso 5
```

Probabilidad que da el modelo a que **esa dirección** merezca bloqueo, según
lo que ha hecho: cuentas probadas (`c`), máquinas alcanzadas (`m`), reputación
hostil de su subred /24, y en qué aviso habría cortado.

Aparece solo en alertas con IP de origen. En la muestra medida son el **22,6 %**
de las alertas del panel; el resto (Trivy, syscheck, systemd) no tienen atacante
al que puntuar. De las IPs que sí aparecen, la cobertura es del **100 %**.

### Etiqueta de explotación real **[externo]**

```
EXPLOTADA EN LA VIDA REAL   CVE-2025-27363   EPSS 0.278
```

Tres estados: `EXPLOTADA EN LA VIDA REAL` (en el catálogo KEV de CISA),
`EXPLOTACIÓN PROBABLE` (EPSS ≥ 0,1), `SIN EXPLOTACIÓN CONOCIDA`.

---

## 5. Los dos scores de IA — la distinción que más importa

La aplicación muestra **dos números distintos** que responden a preguntas
distintas. Confundirlos es el error más fácil de cometer al leer el panel.

| | `AI <n>` (ventana) | `IP <n>` (dirección) |
|---|---|---|
| **Pregunta** | ¿Este minuto de este agente parece ataque? | ¿La conducta de esta IP justifica bloquearla? |
| **Unidad** | 1 minuto × agente | Dirección IP |
| **Modelo** | LAB-ALERTS (`models_examples/`) | EarlyBlockScorer (`deploy/argos_scorer/`) |
| **Entradas** | 16 agregados del minuto | 22 variables de conducta de la IP |
| **Usa campos del motor de reglas** | Sí (3 de 16) | **No, por diseño** |
| **Valores distintos sobre 10.000 alertas** | **8–15** | **39–148** |

### Por qué el `AI Score` sale casi siempre igual

**No es un juicio por alerta.** El modelo puntúa el minuto completo del agente
y copia el mismo número a todas las alertas de dentro. Medido: el **100 % de
las ventanas contienen más de una IP distinta**, así que cuatro atacantes
golpeando el mismo servidor en el mismo minuto reciben **el mismo score**.

Además satura: entrenado sobre una tarea donde responder «ataque» siempre ya
acierta el 98,64 %, predice `attack` en el 100 % de las alertas recientes. Y su
etiqueta se derivó del propio motor de reglas de Wazuh, así que mide parecido
con el criterio de Wazuh, no ataque.

Verás tarjetas con `score=100` y `severidad=low`: la IA dice riesgo máximo y
Wazuh dice severidad baja. Las dos «tienen razón» en su marco.

---

## 6. Panel analítico (`MiniDashboard`)

### 6.1 KPIs

| KPI | Origen | Qué representa |
|---|---|---|
| **Eventos 24h** | **[real]** | Recuento total de alertas de las últimas 24 h. Consulta separada y barata. |
| **Alertas correladas** | **[real]** | Total de 30 días, con cuántas se cargaron realmente (tope 10.000). |
| **Anomalías IA** | **[derivado]** | Alertas con score ≥ 70, y la media al lado. |
| **Críticas** | **[real]** | Alertas de severidad crítica. **Ojo: el 99,9 % son hallazgos de Trivy.** |
| **Agentes activos** | **[real]** | Activos y desconectados. |
| **AI Risk** | **[derivado]** | Media del score. `high` si ≥ 80. |

### 6.2 Gráficas

| Gráfica | Qué representa |
|---|---|
| **Ataques por tipo** | Reparto por el tipo inferido de la descripción. |
| **Distribución por severidad** | Donut de crítica/alta/media/baja. |
| **Alertas vs IA por hora** | **[real]** Ocho tramos de tres horas, por la **hora real** de cada alerta. Ver la nota de abajo. |
| **Top países origen** | Los cinco países más frecuentes. |
| **AI risk distribution** | Ocho tramos de 12,5 puntos. Con el score actual, casi todo se apila en pocos tramos. |
| **MITRE tactics** | Tácticas ATT&CK de las reglas. |
| **Correlation sources** | **[real]** Enriquecimientos que de verdad se aplican: modelo de ventana, riesgo por IP, reputación AbuseIPDB y explotación real de CVE. |

> **Sobre la línea temporal.** Antes agrupaba por la posición en la lista
> (`index % 8`), lo que producía ocho barras casi idénticas con forma de
> distribución horaria que no lo era. Corregido: ahora agrupa por la hora real.
>
> Consecuencia esperable: como el panel carga las **10.000 alertas más
> recientes**, que a caudal actual son unas cinco horas, la gráfica muestra
> datos en tres o cuatro tramos y **cero en el resto**. Eso es correcto —antes
> los ceros se rellenaban con reparto artificial—, pero conviene saberlo al
> interpretarla: no es una distribución de 24 horas, es la ventana que cabe en
> 10.000 alertas.
>
> Las filas de `Correlation sources` listaban antes Suricata y Zeek, que no
> están integrados y valían siempre cero.

### 6.3 Criminal Intelligence — AbuseIPDB **[externo]**

Reputación colaborativa de IPs. Solo consulta direcciones **públicas que se
repiten al menos 10 veces**, con caché en disco de 24 h y tope de consultas por
refresco, para no agotar la cuota.

| Métrica | Qué representa |
|---|---|
| **Eligible IPs** | Públicas que superan el umbral de repetición. |
| **Checked IPs** | Consultadas de verdad, y cuántas salieron de caché. |
| **High Risk IPs** | Con puntuación de abuso ≥ 80. |
| **Flagged Alerts** | Alertas cuya IP tiene puntuación ≥ 80. |
| **Reputation donut** | Tramos 0-39 / 40-79 / 80-100 / desconocida. |
| **Lookup status** | Por qué no se consultó cada IP: privada, bajo umbral, limitada por cuota. |

### 6.4 Explotación real — CISA KEV + EPSS **[externo]**

Contrasta la severidad declarada con la explotación observada. **No modifica la
severidad de Wazuh.**

| Métrica | Qué representa |
|---|---|
| **CVE detectados** | Vulnerabilidades distintas en las alertas cargadas. |
| **Explotados (KEV)** | Presentes en el catálogo de explotación activa de CISA. |
| **Accionables** | En KEV, o con EPSS ≥ 0,1 (10 % de probabilidad de explotación en 30 días). |
| **Ruido de inventario** | El resto, con el factor de reducción de la cola de revisión. |

#### El contraste — el bloque que da sentido al panel

```
222  alertas marcadas CRITICAL por el nivel de regla de Wazuh
219  de ellas son hallazgos de escáner, no ataques en curso
  2  corresponden a CVE con explotación real conocida
```

Medido sobre 30 días: de los **28 CVE que Trivy marca CRITICAL, ninguno está
en KEV**; uno etiquetado MEDIUM sí. Y la severidad LOW tiene un EPSS medio
(0,00913) **superior** al de MEDIUM (0,00269).

**Prioridad real de parcheo:** los CVE accionables ordenados por probabilidad
de explotación. De 5.839 vulnerabilidades quedan **24** — una reducción de
**243×**.

---

## 7. Simulacro (`/simulacro`)

Reproduce alertas reales contra el modelo de bloqueo temprano y enseña a quién
habría bloqueado, en qué aviso y con qué evidencia. **No ejecuta ninguna
acción**: ni firewall, ni escritura en Wazuh.

**Fuente:** intenta datos frescos de Wazuh con una consulta ligera de un solo
disparo; si el servicio no responde, cae automáticamente al fichero exportado
de 30 días y lo advierte en pantalla.

### Cabecera de seguridad

Confirmación explícita de que **ningún veredicto cayó sobre infraestructura
propia** — rangos no enrutables, agentes, honeypot e indexer. Es el primer
criterio de promoción a bloqueo real, y se afirma en positivo en vez de
deducirse del silencio.

### Métricas principales

| Métrica | Qué representa |
|---|---|
| **Alertas reproducidas** | Volumen de entrada. |
| **IPs con origen de red** | Direcciones distintas puntuables. |
| **Bloqueadas** | Cuántas cruzaron su umbral. |
| **Tasa de bloqueo** | Porcentaje, con aviso si sale de la banda 60-85 %. |
| **Mediana de corte** | En qué aviso decide típicamente. Referencia: el 5º. |
| **Alertas suprimidas** | Lo que esas IPs generaron **después** del corte. |

### Desglose — por qué no basta el porcentaje

Un agregado esconde concentración, así que se reparte siempre:

- Qué porcentaje de lo suprimido aportan solo 3 IPs (medido: **55-67 %**).
- Mediana de alertas suprimidas por IP frente al máximo (**27 frente a 872**).
- Bloqueos sin efecto medible.
- Los cinco mayores contribuyentes, con nombre.

> Esta sección existe porque la regla metodológica del trabajo es **«ninguna
> métrica agregada sin su desglose por grupo»**. Un «91 % de ataque evitado»
> puede venir de una sola IP muy ruidosa.

### Calidad de las decisiones

**Evidencia que acompaña a cada bloqueo** — describe *qué hay*, no *por qué
decidió el modelo* (es una función aprendida sobre 22 variables; afirmar
causalidad sería mentir):

| Etiqueta | Significado |
|---|---|
| `ENUMERACIÓN` | Probó dos o más cuentas distintas. |
| `ALCANCE LATERAL` | Alcanzó dos o más máquinas. |
| `REPUTACIÓN DE SUBRED` | **Sin evidencia propia**: su /24 ya produjo hostiles. La más delicada. |
| `VOLUMEN` | Ninguna de las anteriores. |

**Margen sobre el umbral** por veredicto, con las ajustadas (< 0,05) marcadas.
Medido: en torno a **la mitad** de las decisiones están al filo.

### Sesgo de ventana

Las IPs que aparecen al final de la ventana no tienen tiempo de acumular
avisos. Medido en una ejecución: **las 9 de 9 sin bloquear** no llegaron a los
20 avisos del último presupuesto. **No se puede afirmar que sean benignas**, y
por tanto la tasa de bloqueo está sesgada a la baja y no debe leerse como
precisión.

---

## 8. Modos de degradación

La aplicación nunca falla en blanco. Cuenta cuántas de las tres fuentes
respondieron:

| Modo | Condición | Qué se ve |
|---|---|---|
| `live` | Las tres responden | Datos reales. |
| `partial` | Una o dos | Banner de aviso; lo que falte, simulado. |
| `demo` | Ninguna | Ocho alertas de ejemplo (`ARG-1001`…). |

> **Cuidado al hacer capturas para la memoria:** un panel en modo `demo` es
> visualmente idéntico a uno en vivo salvo por el banner. Conviene verificar el
> campo `mode` de la respuesta antes de dar una captura por buena.

---

## 9. Simulador local de alertas benignas

En cada refresco se antepone **una alerta benigna sintética**, rotando entre
diez escenarios (fallos de systemd, logs de Docker, flujos de administración).
Nunca se escribe en Wazuh; solo existe en memoria dentro de la respuesta.

Existe porque el tráfico real es casi todo ataque, y sin ningún contraejemplo
el panel no permite comprobar que el sistema distingue algo. Se identifica con
`argos.local-simulator` en el campo de herramienta.

---

## 10. Endpoints

| Ruta | Para qué |
|---|---|
| `GET /api/argos/live` | Alimenta el panel completo. |
| `GET /api/argos/simulation` | Ejecuta el simulacro. `minutes`, `limit`, `source`. |
| `GET /api/argos/dataset` | Exporta alertas en JSONL para análisis. `format=manifest` da solo el balance de clases. |
| `POST /api/argos/mcp-chat` | Consulta en lenguaje natural. **Ver limitación abajo.** |
| `GET /api/wazuh/*` | Acceso directo a agentes, manager y alertas. |

### El asistente conversacional

**No usa un modelo de lenguaje.** Es un comparador de palabras clave: normaliza
el texto, busca términos como «severidad» o «reciente», extrae un número con
una expresión regular y rellena una plantilla con datos reales.

Se llamaba «MCP» en la interfaz, lo que sugería una integración inexistente.
Renombrado a **CONSULTA**, y el mensaje de bienvenida ahora dice explícitamente
que reconoce palabras clave y no es un modelo de lenguaje.

---

## 11. Lo que se corrigió, y lo que sigue siendo limitación

### Corregido

| Elemento | Antes | Ahora |
|---|---|---|
| Barra superior | `MCP · 12 AGENTS`, `SURICATA · RUNNING` fijos | `MANAGER`, `INDEXER`, `ALERTAS` medidos |
| Top targets | `96/87/78/69` decorativos | Recuento real de alertas por agente |
| Correlation sources | Suricata y Zeek siempre a cero | Los cuatro enriquecimientos que sí se aplican |
| Línea temporal | Reparto por posición en la lista | Agrupación por hora real |
| Geolocalización | Puntos sintéticos indistinguibles | Marcados `(aprox.)` y separados en salud |
| Fila `MCP Agents` | Permanentemente `planned` | Retirada |
| Chat «MCP» | Sugería integración MCP | Renombrado `CONSULTA`, con aviso explícito |

### Limitaciones que permanecen, por diseño o por alcance

| Elemento | Situación |
|---|---|
| Suricata y Zeek | **No integrados.** Ya no aparecen en ninguna métrica de panel. El campo `Suricata SID` de la ficha de detalle sigue existiendo y vale siempre `N/A`. |
| MCP | **Nunca existió.** No hay dependencias MCP ni de ningún LLM en el proyecto; el historial de git lo confirma. El chat es y fue siempre un comparador de palabras clave, que funciona. El campo `MCP tool` de la ficha es una etiqueta de tipo de alerta con nombre heredado. |
| Campo `Sensores` | Siempre `Wazuh / AI Engine`. Solo hay una fuente real. |
| Campo `Agente` en la ficha | Duplica «Destino». |
| Bloque CSR-LANL | Visible pero **no interpretable**: el adaptador rellena con cero las familias de datos que Wazuh no produce. Ver sección 3.1. |
| Ventana de la gráfica temporal | Solo cubre lo que quepa en 10.000 alertas (~5 h). |
| Geolocalización aproximada | Sigue existiendo, pero ahora está declarada. |
| Chat | Determinista por palabras clave, no un LLM. |
| `AI Score` de ventana | Satura y no distingue entre atacantes del mismo minuto. Se mantiene junto al riesgo por IP, que sí discrimina. |

## 12. Cómo levantarlo

```bash
# 1. Sidecar: modelos en memoria. Sin él todo funciona, pero a 15 s por refresco.
.venv/Scripts/python.exe deploy/argos_scorer/service.py

# 2. Web
npm run dev            # desarrollo (webpack)
# o
npx next build && npx next start -p 3000    # producción, 3-4x más rápido
```

Si reinicias, **mata los procesos anteriores por PID**: los huérfanos siguen
ocupando el puerto y el nuevo no llega a arrancar, con lo que seguirías viendo
el código antiguo.

---

*Documento generado el 6 de septiembre de 2026 y actualizado tras corregir
los elementos listados en la sección 11. Las cifras marcadas como
medidas proceden de la exportación de 30 días (1.462.265 alertas) y de
mediciones sobre el despliegue en vivo.*
