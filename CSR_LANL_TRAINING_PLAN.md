# CSR-LANL Training Plan

Este documento define como usar `CSR-LANL` para crear una capa de anomalia por entidad/tiempo que complemente al modelo principal `LAB_ALERTS`.

## Objetivo

Entrenar un modelo que responda:

```text
¿Esta entidad se esta comportando de forma rara respecto a su historico?
```

No sustituye al modelo `LAB_ALERTS binary`. Lo complementa.

Salida esperada en ARGOS:

```json
{
  "entity_anomaly_score": 0.82,
  "entity": "agent-025",
  "window": "1h",
  "prediction": "anomalous",
  "model": "csr_lanl_entity_anomaly"
}
```

## Para Que Sirve

Este modelo puede ayudar en casos donde una alerta individual no parece grave, pero el comportamiento global si es raro.

Ejemplos:

- Usuario que accede a un host que nunca habia usado.
- Host con actividad fuera de horario.
- Agente que genera demasiadas reglas distintas.
- IP origen nueva para una entidad.
- Cambio brusco en frecuencia de eventos.

## Dataset

Dataset recomendado:

```text
CSR-LANL
```

Uso del dataset:

- No se usa como alerta Wazuh directa.
- Se usa para aprender metodologia de comportamiento por entidad.
- El entrenamiento debe crear ventanas temporales por entidad.

## Modelo Recomendado

Primera version:

```text
IsolationForest
```

Motivo:

- No requiere etiquetas perfectas.
- Encaja con deteccion de rareza.
- Es facil de explicar en el TFM.
- Produce un score de anomalia interpretable.

Alternativas futuras:

```text
OneClassSVM
LocalOutlierFactor
Autoencoder tabular
HistGradientBoosting si se dispone de etiquetas fiables
```

## Entidad Principal

Entrenar por entidad temporal.

Opciones:

```text
user
host
source_host
destination_host
user_host_pair
```

Recomendacion inicial:

```text
entity_id = user
window = 1 day
```

Segunda version:

```text
entity_id = host
window = 1 hour
```

## Features A Entrenar

Features por entidad y ventana:

| Feature | Descripcion |
| --- | --- |
| `event_count` | Numero de eventos en la ventana. |
| `unique_src_hosts` | Hosts origen distintos. |
| `unique_dst_hosts` | Hosts destino distintos. |
| `unique_users` | Usuarios distintos asociados a la entidad. |
| `unique_auth_types` | Tipos de autenticacion distintos. |
| `unique_logon_types` | Tipos de logon distintos. |
| `failed_count` | Numero de fallos. |
| `success_count` | Numero de exitos. |
| `failure_ratio` | Fallos / total. |
| `new_dst_host_count` | Destinos nuevos para la entidad. |
| `new_src_host_count` | Origenes nuevos para la entidad. |
| `hour_entropy` | Dispersion horaria. |
| `off_hours_count` | Eventos fuera de horario normal. |
| `day_of_week` | Dia de la semana. |
| `entity_frequency_7d` | Frecuencia reciente de esa entidad. |
| `dst_host_frequency_7d` | Frecuencia reciente de destinos. |

## Target

CSR-LANL puede trabajarse de forma no supervisada.

Target inicial:

```text
No target.
Entrenar IsolationForest con comportamiento mayoritariamente normal.
```

Si el dataset incluye red-team labels o ventanas marcadas:

```text
Usar etiquetas solo para evaluacion.
No entrenar el IsolationForest con las etiquetas de ataque.
```

## Pipeline Recomendado

```text
1. Cargar CSR-LANL raw events.
2. Normalizar columnas.
3. Crear entity_id.
4. Agrupar por ventana temporal.
5. Calcular features.
6. Separar train/val/test por fecha.
7. Entrenar IsolationForest solo con ventanas normales.
8. Calibrar threshold en validacion.
9. Evaluar en test.
10. Exportar artefactos.
```

## Split Temporal

Usar split por fecha, no random.

Ejemplo:

```text
train: primeros 70% dias
val: siguientes 15% dias
test: ultimos 15% dias
```

Motivo:

En SOC importa generalizar hacia el futuro, no mezclar ventanas aleatoriamente.

## Artefactos A Guardar

Estructura recomendada:

```text
models_future/
  csr_lanl_entity_anomaly/
    <run_id>/
      model.joblib
      feature_columns.json
      schema_contract.json
      threshold.json
      metrics.json
      training_config.json
      dataset_profile.json
```

`schema_contract.json` debe incluir:

```json
{
  "dataset": "CSR-LANL",
  "model_type": "entity_anomaly",
  "window_size": "1d",
  "entity_key": "user",
  "feature_columns": [],
  "score_direction": "higher_is_more_anomalous"
}
```

## Metricas

Si hay etiquetas:

```text
ROC-AUC
PR-AUC
Precision@K
Recall@K
Top-K hit rate
False positive rate
```

Si no hay etiquetas:

```text
score distribution
top anomalous entities
manual review
stability by day
```

Metricas recomendadas para TFM:

```text
Precision@10
Precision@50
Recall@top 1%
ROC-AUC si hay labels
```

## Integracion En ARGOS

La integracion no debe cambiar la decision principal del modelo LAB_ALERTS al principio.

Debe anadir una segunda senal:

```json
{
  "ai": {
    "prediction": "attack",
    "score": 0.91,
    "entity_anomaly": {
      "score": 0.82,
      "prediction": "anomalous",
      "entity": "agent-025",
      "window": "1h"
    }
  }
}
```

Uso en la UI:

- Mostrar en detalle de alerta.
- Anadir grafica de entidades anomalas.
- No modificar severidad Wazuh.
- No sustituir `AI Score` principal hasta validar.

## Relacion Con LAB_ALERTS

`LAB_ALERTS binary` responde:

```text
¿La ventana parece ataque o benigna?
```

`CSR-LANL anomaly` responde:

```text
¿La entidad se comporta raro?
```

Ambos scores pueden discrepar.

Casos utiles:

```text
LAB attack alto + anomaly alto = incidente prioritario
LAB attack alto + anomaly bajo = posible falso positivo o patron conocido
LAB attack bajo + anomaly alto = comportamiento raro a revisar
LAB attack bajo + anomaly bajo = bajo riesgo
```

## Primer Experimento

Entrenar:

```text
modelo: IsolationForest
dataset: CSR-LANL
entity_key: user
window_size: 1d
features: comportamiento por usuario y destino
```

Evaluar:

```text
Precision@10
Precision@50
Top anomalous users
Score distribution
```

## Segundo Experimento

Entrenar:

```text
modelo: IsolationForest
dataset: CSR-LANL
entity_key: host
window_size: 1h
features: comportamiento por host origen/destino
```

Objetivo:

Ver si ventanas mas cortas se parecen mas al uso en ARGOS.

## Tercer Experimento

Aplicar la misma metodologia a historico real de Wazuh/ARGOS.

Features equivalentes:

```text
agent_id
src_ip
src_user
rule_id
decoder
location
alert_count
unique_rule_count
unique_src_ip_count
new_rule_count
new_src_ip_count
hour
day_of_week
```

Esto convierte CSR-LANL en base metodologica, pero el modelo final podria entrenarse sobre historico real de ARGOS.

## Comandos Orientativos

Preparar dataset:

```powershell
.venv\Scripts\python.exe CSR_LANL_REFACTOR\prepare_csr_lanl.py --input CSR_LANL\raw --out CSR_LANL_REFACTOR\prepared --entity_key user --window_size 1d
```

Entrenar:

```powershell
.venv\Scripts\python.exe CSR_LANL_REFACTOR\train_entity_anomaly.py --datasets_base CSR_LANL_REFACTOR\prepared --model isoforest --entity_key user --window_size 1d
```

Evaluar:

```powershell
.venv\Scripts\python.exe CSR_LANL_REFACTOR\evaluate_entity_anomaly.py --artifact CSR_LANL_REFACTOR\artifacts\csr_lanl_entity_anomaly\<run_id>
```

## Resultado Esperado

Un modelo que produzca:

```text
entity_anomaly_score
```

y permita enriquecer ARGOS con una segunda pregunta SOC:

```text
No solo si la alerta parece ataque, sino si la entidad esta actuando raro.
```

## Decision Recomendada

Implementar CSR-LANL como modelo futuro de anomalia por entidad.

Orden recomendado:

```text
1. Entrenar CSR-LANL entity anomaly.
2. Exportar modelo a models_future.
3. Crear scorer independiente.
4. Mostrar entity_anomaly_score en detalle de alerta.
5. Repetir metodologia con historico real de Wazuh/ARGOS.
6. Usarlo en una futura capa de fusion.
```
