# ARGOS-SOC IA — Dossier para la memoria del TFM

Documento fuente para redactar la memoria. Reúne **la línea argumental y las
cifras medidas**, que hasta ahora vivían repartidas entre ocho ficheros y, en el
caso de los resultados centrales, únicamente dentro de ficheros JSON.

---

## 0. Cómo usar este documento

**Qué es.** El esqueleto de la memoria: qué se pretendía, qué se midió, qué
salió y qué no se puede afirmar. Cada cifra lleva su procedencia.

**Qué NO es.** No es el inventario de la aplicación. Eso está en
[`METRICAS.md`](METRICAS.md), 1.345 líneas que documentan cada pantalla y cada
métrica del panel. Este dossier lo referencia y no lo duplica.

**Dónde está cada cosa:**

| Fichero | Qué aporta a la memoria |
|---|---|
| **Este dossier** | Hipótesis, método, resultados, límites. El capítulo de resultados sale de aquí. |
| `METRICAS.md` | Qué muestra la aplicación, pantalla a pantalla. El capítulo de la herramienta. |
| `deploy/argos_scorer/README.md` | El porqué de cada decisión del paquete de modelos (§4, R1–R12). |
| `WAZUH.md` | Montaje de la infraestructura: manager, indexer, agentes. |
| `CONTEXT.md` | Historia del proyecto y decisiones de arquitectura. |
| `experiments/results/*.json` | Las cifras crudas de ablación, LOAO y KEV/EPSS. |
| `CSR_LANL_*.md` | La capa experimental de transferencia entre dominios. |

> **Advertencia de honestidad.** La aportación de este trabajo son en buena parte
> **resultados negativos**. Redactar la memoria como si se hubiera construido un
> detector que funciona sería a la vez falso y más débil: lo que se sostiene es
> haber medido *por qué* las cifras iniciales eran un artefacto. La sección 12
> lista las frases que no se pueden escribir.

---

## 1. El problema, la hipótesis y qué ocurrió

### El problema

Un SOC recibe más alertas de las que puede revisar. Medido en este laboratorio:
**~53.000 eventos en 24 h**, unas **37 alertas por minuto**. Ninguna persona
revisa eso. La pregunta del trabajo es si el aprendizaje automático puede
reducir esa carga sin perder los ataques que importan.

### La hipótesis inicial

Entrenar un clasificador binario «¿esta alerta es un ataque?» sobre las alertas
de Wazuh, y usar su probabilidad para priorizar.

### Qué ocurrió

El clasificador alcanzó **ROC-AUC 0,9990**. Y ese número resultó ser **un
artefacto**, no un logro. La sección 3 explica por qué, y es el hallazgo
central del trabajo.

**La línea argumental de la memoria, en una frase:** se construyó el detector
obvio, se midió que su éxito era circular, se rediseñó la pregunta, y se midió
honestamente cuánto queda — que es bastante menos y bastante más interesante.

---

## 2. Los datos

### La infraestructura

Wazuh desplegado con manager, indexer (OpenSearch) y agentes sobre máquinas
reales expuestas a internet, incluido un honeypot. El tráfico es **real y no
solicitado**: no hay simulación de ataques.

| Magnitud | Valor |
|---|---|
| Alertas exportadas para análisis | **1.462.265** |
| Tamaño del volcado | 1,49 GB (JSONL) |
| Periodo | 30 días |
| Tiempo de exportación | 476 s, 0 registros malformados |
| Agentes en el inventario | 20 (4 activos en el momento de medir) |
| Índice | `wazuh-alerts-*`, ~56,5 M documentos |

Producido por `GET /api/argos/dataset` (ver `lib/dataset-export.ts`).

### El problema de las etiquetas

**No hay clase benigna.** Wazuh solo indexa lo que dispara una regla, así que
el volcado contiene ataques y hallazgos de inventario, no tráfico normal. Las
etiquetas se derivaron por **etiquetado débil** (*weak labelling*): agrupando
las reglas que dispararon en familias de ataque, benigno y postura.

Esa decisión es el origen de todo lo que viene después.

---

## 3. El hallazgo central: circularidad

### Qué es la circularidad de etiqueta

Cuando la etiqueta que se quiere predecir se deriva de los mismos datos que se
usan como entrada, el modelo no aprende el fenómeno: **reconstruye la regla que
generó la etiqueta**. La métrica sale excelente y no significa nada.

### Cómo se midió

Una sola columna, `mitre_tagged_ratio`, **reproduce la etiqueta con ROC-AUC
0,9990** — idéntico al modelo completo de 98 variables. El «detector» estaba
descubriendo que las alertas etiquetadas por MITRE son las etiquetadas como
ataque, lo cual es una tautología.

**Consecuencia de diseño:** los campos `rule_*`, `mitre_*` y `decoder_name`
quedan **prohibidos** en todos los modelos del paquete. Hay un guardia de tipos
en `lib/argos-scorer-client.ts` que impide reintroducirlos por descuido.

### La severidad también estaba invertida

Se descartó etiquetar por `rule_level` porque sale del mismo motor **y está
invertido en estos datos**: nivel 14 = hallazgo benigno de Trivy; nivel 5 = la
fuerza bruta real. La regla «nivel ≥ 10 ⇒ ataque» **erraría el 70,8 %** de lo
que captura.

### La huella de máquina: un segundo atajo

Con 54 variables de conducta —sin `agent_id` entre ellas— se predice **qué
agente es con 99,75 % de exactitud**. Cada máquina deja una huella repartida de
forma redundante entre variables correlacionadas: el host escáner tiene
`src_ip_present_ratio` 0,075 y 2.072 alertas por ventana; el honeypot, 0 IPs y
1,5.

Quitar una columna no elimina un confundido distribuido. **Consecuencia
medida:** un modelo global entrenado en unos hosts cae a **MCC 0,000** en otro.

---

## 4. El rediseño: cambiar la pregunta

La pregunta pasó de «¿es esto un ataque?» a **«¿la conducta de esta dirección IP
justifica bloquearla?»**.

### La etiqueta nueva

No viene de ninguna regla. Una IP merece bloqueo si su conducta observada lo
justifica:

- **≥ 5 cuentas distintas probadas**, o
- **≥ 2 máquinas alcanzadas**, o
- **≥ 50 intentos en ≥ 3 ventanas**

Computada de forma **causal** (solo con el pasado) a partir de cinco campos de
hechos: `timestamp`, `agent_id`, `src_ip`, `src_port`, `src_user`/`dst_user`.

### Y se auditó con el mismo método que destapó el problema

La mejor sonda de una sola variable llega a **0,6641** (contra 0,9990 de la
etiqueta débil): **no reconstruible, circularidad rota**.

El efecto es medible y es el argumento más fuerte del trabajo:

| Etiqueta | Traslado entre hosts |
|---|---|
| Débil (derivada de reglas) | MCC **0,000** — colapso total |
| Conductual (esta) | retiene el **65–104 %** |

> **El problema nunca fue el modelo: era la pregunta.** Esa frase resume el TFM.

---

## 5. Metodología de validación

Lo que hace defendible el trabajo no son las cifras, es cómo se obtuvieron.

| Práctica | Qué evita |
|---|---|
| **Particiones temporales**, nunca aleatorias | Una partición aleatoria sobre datos con estructura temporal produce ~0,99 que no se sostiene. Se reprodujo el mismo colapso en **CIC-IDS2017 y UNSW-NB15**. |
| **Validación externa de un solo disparo** | Canalización congelada, una única ejecución contra un segundo entorno, reportada tal cual. Los dos presupuestos están **gastados**. |
| **Contra ground truth real** (CSR-LANL, equipo rojo auténtico) | Comprobar si las variables conductuales sirven fuera del laboratorio. |
| **Ninguna métrica agregada sin desglose por grupo** | Ver §6.3: esta regla nació de un error propio. |
| **MCC además de exactitud** | Con prevalencia del 98,6 %, la exactitud es casi inútil. |

Que el presupuesto de validación externa esté **gastado** es relevante para la
memoria: cualquier afirmación externa nueva exigiría captura nueva. Se dice, no
se esconde.

---

## 6. Resultados medidos

### 6.1 Ablación: cuánto vale el modelo sobre la línea base

Fuente: `experiments/results/shortcut_ablation.json` · 81.589 ventanas,
prevalencia 0,9787, semilla 42.

| Variante | Exactitud | MCC | Ganancia sobre línea base |
|---|---|---|---|
| **A** · 16 variables del modelo activo | 0,9978 | 0,9246 | **+0,0114** |
| **B** · sin identidad de máquina | 0,9978 | 0,9254 | +0,0114 |
| **C** · sin identidad ni motor de reglas | 0,9973 | 0,9092 | +0,0109 |
| **D** · C + sin ventanas de postura | 0,9971 | **0,6813** | **−0,0002** |

**Cómo leerlo, y es incómodo:**

1. La **línea base** —responder siempre «ataque»— acierta el **98,64 %**. El
   modelo llega al 99,78 %: **aporta 1,14 puntos**. Ese es el tamaño real de la
   contribución del aprendizaje automático a esta tarea.
2. **B ≈ A**: quitar la identidad de máquina no cambia nada. Esa variable no
   estaba aportando.
3. **D es el resultado que importa**: al quitar las ventanas de postura, el MCC
   se desploma de 0,909 a **0,681** y la ganancia sobre la línea base pasa a ser
   **negativa**. El modelo deja de ser mejor que responder siempre lo mismo.

### 6.2 Leave-one-agent-out: ¿generaliza a una máquina nueva?

Mismo fichero. Se entrena con todos los agentes menos uno y se prueba en el que
quedó fuera.

| Agente | n test | Prevalencia | Exactitud | MCC | Ganancia |
|---|---|---|---|---|---|
| 000 | 40.958 | 0,9982 | 0,9986 | 0,5874 | +0,0004 |
| 003 | 193 | 0,2176 | 0,9223 | 0,7666 | +0,1399 |
| **011** | 39.279 | 0,9882 | 0,7882 | 0,0904 | **−0,2000** |
| **030** | 1.159 | 0,0958 | 0,9042 | **0,0000** | 0,0000 |

**El modelo no transfiere.** En el agente 011 es **20 puntos peor** que la línea
base. En el 030 el MCC es **exactamente 0**: predice una sola clase.

El único caso bueno (agente 003, +0,14) tiene **193 muestras** — demasiado
pequeño para sostener una afirmación.

### 6.3 El detector de anomalías retirado — y la regla que nació de él

Un autoencoder no supervisado llegó a presentarse como el mejor resultado:
**18,3× sobre el azar**. **Retirado.** Desglosado por agente, cada host estaba
en el azar o por debajo (**0,57×–0,95×**). El agregado venía de que la clase
rara se concentraba en un solo agente: **paradoja de Simpson**. Ajustarlo por
host tampoco funcionó (lift medio 0,73×).

De ese fallo nace la regla que gobierna todo el trabajo y toda la interfaz:
**ninguna métrica agregada sin su desglose por grupo.**

Es material de memoria de primer orden: un error propio, detectado, medido y
convertido en método.

### 6.4 El aprendizaje profundo no aportó ventaja — tres veces

| Arquitectura | Resultado |
|---|---|
| Autoencoder no supervisado | Retirado (§6.3) |
| GRU sobre la secuencia de avisos | **Empate exacto**: AUC 0,9702 vs 0,9703 |
| Transformer de atención (2 bloques, 4 cabezas, ~18.369 parámetros) | **Empate**: recall 0,991 vs 0,990; precisión 0,991 vs 0,993 |

**Tres pruebas, tres empates.** Y en el caso del Transformer la explicación es
interpretable: **la etiqueta cuenta hechos —cuántas cuentas, cuántas máquinas—
y no depende del orden**, que es justo lo que un modelo de secuencia sabría
aprovechar.

Los modelos en producción son **HistGradientBoosting**: igual de buenos, 6,6 MB
en total, sin GPU, inferencia en microsegundos.

> El Transformer se conserva **en modo sombra** por dos motivos que no son la
> detección: da **explicabilidad** (qué avisos pesaron, algo que el modelo
> principal no puede dar) y permite medir el **acuerdo entre dos modelos con
> sesgos inductivos distintos** sobre tráfico real. Acuerdo medido en vivo:
> **79–86 %** según el refresco. **No tiene validación externa.**

### 6.5 El score de ventana satura

Sobre 10.001 alertas cargadas: **13 valores distintos**, con el **96,8 % en
exactamente 100** y media **99,6**. El histograma tenía forma de **U** — la
firma de un clasificador que decide sí o no, no «cuánto».

Consecuencia práctica: promediarlo daba un «nivel de riesgo» que **no describía
a ninguna alerta**. Por eso el panel migró al riesgo por IP (49 valores
distintos, media 91,4).

---

## 7. La contribución que no lleva aprendizaje automático

Fuente: `experiments/results/kev_epss_filter.json`.

Se cruzaron los CVE que reporta el escáner con dos fuentes públicas: **CISA
KEV** (catálogo de vulnerabilidades con explotación real confirmada) y **EPSS**
(probabilidad estimada de explotación en 30 días).

| Magnitud | Valor |
|---|---|
| Alertas de Trivy | 408.956 |
| CVE distintos | **5.839** |
| Con EPSS | 5.827 (12 sin puntuar) |
| **Accionables** (en KEV o EPSS ≥ 0,1) | **24** |
| **Factor de reducción** | **243×** |

Y el dato que da sentido al panel entero: **de los 28 CVE que Trivy marca
CRITICAL, ninguno está en KEV**; uno etiquetado MEDIUM sí. La severidad LOW
tiene un EPSS medio (0,00913) **superior** al de MEDIUM (0,00269).

> **Por qué esto importa para la tesis.** Es el resultado más útil
> operativamente de todo el trabajo —convierte una cola de revisión imposible en
> una lista de una mañana— y **no usa aprendizaje automático**. Responde a la
> pregunta del TFM de forma directa e incómoda: *en este dominio y a esta
> escala, elegir bien una fuente pública de datos aportó más que el modelo*.

---

## 8. El trabajo de honestidad sobre la interfaz

Esto también es contribución, y conviene contarlo: una parte del proyecto
consistió en **auditar el propio panel** y retirar lo que engañaba.

| Elemento | Qué pasaba | Ahora |
|---|---|---|
| `MCP · 12 AGENTS`, `SURICATA · RUNNING` | Escritos a mano, nada medido | Retirados |
| Top targets `96/87/78/69` | Decorativos | Recuento real |
| Línea temporal | Agrupaba por posición en la lista (`index % 8`) | Por hora real |
| Geolocalización | Puntos sintéticos indistinguibles de los reales | Marcados `(aprox.)`; medido: 6,6 % |
| `Correlation sources` | Listaba Suricata y Zeek, siempre a cero | Los cuatro enriquecimientos reales |
| Fila AbuseIPDB | Contaba solo `checked`, marcaba 0 | Cuenta también `cached`: 4.447 |
| KPI `Anomalías IA` | Umbral que cruzaba el 100 % de las alertas | `IPs de riesgo alto`, por dirección |
| Gráfica `Alertas vs IA` | Dos líneas superpuestas idénticas | Columnas apiladas con serie que sí varía |
| Reparto de riesgo | La suma no cuadraba, sin explicación | Declara su cobertura |

El patrón se repite: **métricas que parecían informar y no informaban**. Es
material aprovechable para un apartado sobre diseño honesto de paneles.

---

## 9. Limitaciones

Ordenadas por gravedad. La primera es estructural.

1. **No hay clase benigna real.** Wazuh solo indexa lo que dispara una regla.
   El negativo sale de etiquetado débil más un simulador sintético. **Sin
   benignos reales no se puede afirmar nada sobre falsos positivos**, y un SOC
   se juzga por falsos positivos. Es la precondición de casi todo lo demás.
2. **El modelo no transfiere** a máquinas nuevas (§6.2).
3. **Dominio de validez estrecho:** atacantes **ruidosos** — fuerza bruta,
   escaneo, spraying. **No** detecta a un atacante sigiloso con credenciales
   válidas, y eso está medido, no supuesto.
4. **Presupuesto de validación externa gastado.**
5. **El modo sombra nunca se ha ejecutado.** El corredor existe
   (`deploy/argos_scorer/shadow-run.ts`) pero nada lo lanza y
   `var/argos-scorer/verdicts.jsonl` no existe. Las cifras de acuerdo entre
   modelos son **fotos sueltas, no una serie**.
6. **El Transformer no tiene validación externa.**
7. **Cobertura variable:** la proporción de alertas con IP de origen oscila
   entre el **2 % y el 82 %** según el refresco. Las métricas de riesgo se
   calculan sobre esa base variable.
8. **CSR-LANL no es interpretable en ARGOS:** el adaptador rellena con ceros
   las familias de datos que Wazuh no produce. Se conserva porque documenta un
   intento de transferencia entre dominios que se midió y no funcionó.

---

## 10. Trabajo futuro

`FUTURE_WORK.md` propone una arquitectura de fusión con cinco modelos
especialistas y un `TabTransformer`. **Esa propuesta debe recortarse en la
memoria**, y decirlo es más fuerte que mantenerla: proponer una capa de fusión
sobre modelos cuya clase negativa no existe es diseñar el tejado antes que los
cimientos, y un tribunal lo señalará.

El orden defendible es:

1. **Recuperar la clase benigna.** Activar `logall_json`, indexar
   `wazuh-archives-*` y generar actividad administrativa real durante una
   semana. Es la precondición de todo lo demás.
2. **Repetir la ablación** con benignos reales y medir falsos positivos.
3. **Ejecutar el modo sombra** durante semanas para convertir el acuerdo entre
   modelos en una serie temporal.
4. **Solo entonces**, plantear fusión.

---

## 11. Reproducibilidad: qué comando produce qué cifra

| Cifra | Origen |
|---|---|
| Ablación y LOAO (§6.1, §6.2) | `python experiments/shortcut_ablation.py` → `experiments/results/shortcut_ablation.json` |
| KEV/EPSS, 243× (§7) | `python experiments/kev_epss_filter.py` → `experiments/results/kev_epss_filter.json` |
| Volcado de 1.462.265 alertas (§2) | `GET /api/argos/dataset` |
| Métricas del paquete (§4, §5) | `deploy/argos_scorer/README.md` §2 y §4; registro canónico R1–R13 en el repo de investigación |
| Cifras del panel en vivo (§6.5, §8) | `GET /api/argos/live` |
| Simulacro y políticas | `GET /api/argos/simulation?policy=hgb\|attention\|or\|and` |
| Estado de los modelos | `GET http://127.0.0.1:8973/health` |
| Pruebas del sidecar | `python deploy/argos_scorer/test_service.py` (11 secciones) |

Las cifras del panel **cambian con cada refresco** porque dependen de las 10.000
alertas cargadas en ese momento. Para la memoria conviene **fijar una captura y
fecharla**.

---

## 12. Afirmaciones que NO se pueden escribir

Lista de guardarraíles para quien redacte. Todas están respaldadas por
mediciones de este documento.

| ❌ No escribir | ✅ Escribir en su lugar |
|---|---|
| «El sistema detecta ataques con un 99 % de exactitud» | «Alcanza 99,78 % frente a una línea base de 98,64 %: aporta 1,14 puntos» |
| «El modelo generaliza» | «Se midió que no transfiere: MCC 0,09 y 0,00 en dos de cuatro agentes» |
| «Detecta amenazas avanzadas / APT» | «Dominio medido: atacantes ruidosos —fuerza bruta, escaneo, spraying—» |
| «El Transformer mejora la detección» | «Empata con el modelo principal; aporta explicabilidad, no precisión» |
| «Precisión / pocos falsos positivos» | Nada: **sin clase benigna real no se puede afirmar** |
| «Valida en producción» | «Validación externa de un solo disparo, presupuesto gastado» |
| «Bloquea automáticamente» | «Modo sombra: anota, no ejecuta. El bloqueo real requiere aprobación» |
| «Las alertas CRITICAL son los ataques» | «El 99,6 % de las CRITICAL son hallazgos de inventario; la fuerza bruta vive en LOW» |
| «El AI Score mide si la alerta es un ataque» | «Puntúa un minuto de un agente y satura: 13 valores distintos, 96,8 % en 100» |
| Citar un porcentaje agregado a secas | Citarlo **con su desglose por grupo** — es la regla que gobierna el trabajo |

---

*Documento generado el 8 de septiembre de 2026. Las cifras marcadas con fuente
proceden de los ficheros citados; las del panel en vivo, de mediciones sobre el
despliegue en la fecha indicada.*
