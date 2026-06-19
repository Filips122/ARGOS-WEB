# CSR-LANL Integration In ARGOS Web

Este documento describe como integrar el paquete `ARGOS-CSR-LANL` dentro de ARGOS Web.

## Decision Principal

No sustituir el modelo `LAB_ALERTS`.

Uso recomendado:

```text
LAB_ALERTS binary       -> AI Score principal y Class benign/attack
LAB_ALERTS multiclass   -> Prediccion taxonomica IA
CSR-LANL HGB            -> supervised entity behavior score
CSR-LANL IsolationForest -> entity anomaly enrichment
```

CSR-LANL debe entrar como una segunda capa SOC:

```text
¿La entidad se comporta de forma rara o parecida a comportamiento red-team?
```

No como decision principal de si la alerta Wazuh es ataque.

## Estado Del Paquete

Carpeta:

```text
ARGOS-CSR-LANL/
```

Contenido relevante:

```text
ARGOS-CSR-LANL/
  model_manifest.json
  schemas/model_contract.json
  models/
    hgb_candidate/
      model.joblib
      feature_columns.json
      label_map.json
      results.json
    isoforest_aux/
      model.joblib
      feature_columns.json
      results.json
  scripts/
    score_argos_csr_lanl.py
  docs/
    FINDINGS_AND_PRODUCTION_NOTES.md
```

Decision del paquete:

```text
supervised_score      -> senal principal CSR-LANL
entity_anomaly_score  -> enriquecimiento
context_novelty_score -> enriquecimiento
```

Clasificacion recomendada:

```text
low_signal          -> supervised_score < 0.95
suspicious_entity   -> 0.95 <= supervised_score < 0.9892924292237013
high_risk_entity    -> supervised_score >= 0.9892924292237013
```

## Problema Tecnico A Resolver

El scorer actual de CSR-LANL no recibe alertas Wazuh crudas.

Recibe ventanas ya transformadas a:

```text
209 CSR-LANL identity feature columns
```

Por tanto, ARGOS necesita un adaptador:

```text
Wazuh alerts -> entity windows -> 209 CSR-LANL feature columns -> CSR-LANL scorer
```

## Arquitectura Recomendada

```text
Wazuh API / Wazuh Indexer
  -> normalizacion ARGOS
  -> LAB_ALERTS scorer
       -> ai.score
       -> ai.prediction
       -> ai.taxonomy
  -> CSR-LANL feature adapter
       -> entity/window features
  -> CSR-LANL scorer
       -> ai.csr_lanl.supervised_score
       -> ai.csr_lanl.entity_anomaly_score
       -> ai.csr_lanl.context_novelty_score
       -> ai.csr_lanl.classification
  -> ARGOS UI
```

## Fase 1: Integracion Offline

Objetivo:

Validar que ARGOS puede generar ventanas compatibles y que el scorer funciona.

Pasos:

1. Leer alertas historicas desde Wazuh Indexer.
2. Agrupar por ventana de `1h`.
3. Definir entidad:

```text
entity = agent.id
```

4. Generar un fichero:

```text
tmp/csr_lanl_argos_windows.parquet
```

5. Ejecutar:

```powershell
.venv\Scripts\python.exe ARGOS-CSR-LANL\scripts\score_argos_csr_lanl.py --input tmp\csr_lanl_argos_windows.parquet --out tmp\csr_lanl_enrichments.jsonl
```

6. Revisar:

```text
supervised_score
entity_anomaly_score
context_novelty_score
classification
```

## Fase 2: Feature Adapter

Crear:

```text
models_future/csr_lanl_identity/argos_csr_lanl_features.py
```

Responsabilidad:

Convertir alertas Wazuh en el contrato de 209 columnas.

Inputs:

```json
{
  "hits": [
    {
      "_id": "...",
      "_source": {}
    }
  ]
}
```

Output:

```text
DataFrame con:
entity
window_start
window_end
209 feature columns
```

## Features Que Podemos Generar Desde Wazuh

Desde Wazuh podemos aproximar:

```text
auth_event_count
auth_success_count
auth_fail_count
auth_failure_ratio
unique_src_user_count
unique_dst_user_count
auth_unique_dst_computer_count
active_source_count
total_event_count
has_new_src_user
has_new_dst_computer
day_index
hour_index
minute_of_day
```

Campos Wazuh utiles:

```text
timestamp
rule.id
rule.level
rule.description
rule.groups
agent.id
agent.name
agent.ip
decoder.name
location
data.srcip
data.srcuser
data.dstuser
full_log
```

## Features Que No Tenemos Directamente

CSR-LANL tiene senales de:

```text
flows
dns
process
auth maps
destination ports
process names
```

Si Wazuh no las trae, se rellenaran con `0`.

Esto es aceptable para una primera integracion experimental, pero implica:

```text
El score CSR-LANL no debe usarse como decision operacional final hasta recalibrar con historico ARGOS.
```

## Fase 3: Scorer Runtime

Crear:

```text
models_future/csr_lanl_identity/score_wazuh_csr_lanl.py
```

Responsabilidad:

1. Leer hits Wazuh desde stdin.
2. Construir ventanas `1h` por `agent.id`.
3. Rellenar las 209 columnas.
4. Cargar:

```text
ARGOS-CSR-LANL/models/hgb_candidate/model.joblib
ARGOS-CSR-LANL/models/isoforest_aux/model.joblib
```

5. Devolver JSON:

```json
{
  "results": [
    {
      "id": "alert-id",
      "entity": "025",
      "window_start": "2026-06-09T10:00:00Z",
      "csr_lanl": {
        "supervised_score": 0.91,
        "entity_anomaly_score": 0.82,
        "context_novelty_score": 0.25,
        "classification": "low_signal"
      }
    }
  ]
}
```

## Fase 4: Integracion En `lib/ai-scoring.ts`

Estado actual:

```text
lib/ai-scoring.ts
  -> llama models_examples/score_wazuh_alerts.py
  -> adjunta source.ml.argos
```

Nuevo flujo recomendado:

```text
1. Ejecutar LAB scorer.
2. Ejecutar CSR-LANL scorer.
3. Fusionar por alert id.
4. Adjuntar:

source.ml.argos.csr_lanl = {
  supervised_score,
  entity_anomaly_score,
  context_novelty_score,
  classification,
  entity,
  window_start
}
```

Importante:

No cambiar:

```text
source.ml.argos.prediction
source.ml.argos.risk_score
```

al principio. CSR-LANL es enriquecimiento.

## Fase 5: Normalizacion UI

Modificar:

```text
lib/argos-normalizers.ts
lib/mock-data.ts
components/AttackGlobe.tsx
components/MiniDashboard.tsx
```

Mostrar en detalle de alerta:

```text
CSR-LANL supervised score
Entity anomaly score
Context novelty score
CSR classification
Entity window
```

Ejemplo UI:

```text
CSR-LANL
Entity: 025
Classification: suspicious_entity
Supervised: 91%
Anomaly: 82%
Context novelty: 25%
Window: 1h
```

## Fase 6: Analisis Layer

Anadir futuras graficas:

```text
Top anomalous entities
CSR classification distribution
Entity anomaly over time
LAB vs CSR disagreement
```

Casos interesantes:

```text
LAB attack + CSR high_risk_entity = prioridad alta
LAB attack + CSR low_signal = posible falso positivo conocido
LAB benign + CSR high_risk_entity = entidad rara a revisar
LAB benign + CSR low_signal = bajo riesgo
```

## Fase 7: Recalibracion

Los thresholds actuales vienen de CSR-LANL.

Antes de usarlo como senal fuerte en ARGOS:

1. Guardar historico real de Wazuh/ARGOS.
2. Generar ventanas CSR-like.
3. Ejecutar scorer.
4. Revisar top entidades.
5. Ajustar thresholds:

```text
low_signal
suspicious_entity
high_risk_entity
```

6. Validar con simulaciones y eventos reales.

## Implementacion Minima Recomendada

Primera version en ARGOS:

```text
No fusionar scores.
No cambiar severidad.
No cambiar AI Score principal.
Mostrar CSR-LANL solo en detalle.
```

Campos nuevos:

```ts
attack.ai.csrLanl = {
  supervisedScore: number;
  entityAnomalyScore: number;
  contextNoveltyScore: number;
  classification: 'low_signal' | 'suspicious_entity' | 'high_risk_entity';
  entity: string;
  windowStart: string;
}
```

## Riesgos

1. Feature mismatch:

CSR-LANL fue entrenado con auth, flows, dns y proc. Wazuh puede no tener todo.

2. Domain shift:

CSR-LANL no es ARGOS real. Sus scores deben recalibrarse.

3. Sparse positives:

Las metricas PR-AUC/top-k son mas importantes que accuracy.

4. Interpretacion:

Un score alto significa parecido a comportamiento red-team CSR-LANL, no necesariamente ataque confirmado en ARGOS.

## Conclusion

La integracion correcta es:

```text
CSR-LANL como capa de comportamiento por entidad.
LAB_ALERTS como decision principal de alerta.
CSR-LANL no sustituye ni severidad Wazuh ni AI Score principal.
```

Orden recomendado:

```text
1. Crear feature adapter Wazuh -> CSR-LANL 209 cols.
2. Crear scorer runtime CSR-LANL.
3. Adjuntar ai.csr_lanl en lib/ai-scoring.ts.
4. Mostrarlo en detalle de alerta.
5. Recalibrar thresholds con historico real ARGOS.
6. Solo despues plantear fusion de scores.
```
