# STRATEGY_LAB_ALERTS_REFACTOR

## Objetivo

Esta carpeta concentra el contexto necesario para refactorizar LAB-ALERTS hacia un detector SIEM operacional capaz de separar, de forma defendible:

- actividad benigna operacional,
- actividad sospechosa que requiere enriquecimiento o correlacion,
- ataques o incidentes de alta confianza.

El objetivo no es solo mejorar metricas de test, sino construir un pipeline reproducible que preserve el contrato de features, incorpore benignos reales y reduzca falsos positivos en produccion.

## Contexto Copiado

La carpeta se organiza asi:

| Ruta | Contenido | Uso previsto |
|---|---|---|
| `source_pipeline/` | Codigo original de LAB-ALERTS: preparacion, loaders, entrenamiento, metricas y reporting. | Base tecnica para recuperar y refactorizar el feature pipeline. |
| `prepared_dataset/date/LAB-ALERTS/` | Dataset preparado con perfil `operational_no_label_proxy`, columnas, mapas, splits y parquet. | Referencia exacta del dataset usado por el modelo activo. |
| `production_context/training_artifact_20260520_181715/` | Artefacto original entrenado para LAB-ALERTS HGB binario. | Comparacion contra el modelo base y metadatos de entrenamiento. |
| `production_context/model_store_active/` | Artefacto archivado en `PRODUCTION_PIPELINE/model_store`. | Analizar que se conserva y que falta en produccion. |
| `production_context/pipeline_code/` | Inferencia, export SIEM, scoring, threshold optimizer, registry y archive code. | Refactor del contrato produccion-inferencia-SIEM. |
| `production_context/examples/` | Ejemplo SIEM exportado para LAB-ALERTS. | Referencia del formato actual de salida. |
| `production_context/comparisons/` | Comparacion de modelos de produccion. | Contexto de seleccion del modelo activo. |
| `scripts/` | Orquestadores PowerShell relacionados. | Reproducibilidad de entrenamiento y ejecucion. |
| `docs/` | Documentacion previa del dataset y del pipeline de produccion. | Justificacion metodologica y trazabilidad. |
| `raw_source/alerts.json` | Export Wazuh original usado por LAB-ALERTS. | Fuente para reconstruccion del dataset. |

## Diagnostico Actual

El modelo activo `hgb_lab_alerts_binary_date_20260520_181715` tiene buen rendimiento sobre el test preparado, pero no debe considerarse aun un detector operacional robusto.

Problemas principales:

1. El `joblib` conserva que espera 16 features, pero no conserva nombres ni orden semantico.
2. El artefacto archivado de produccion no copia de forma autosuficiente `feature_columns.json`, `feature_profile.json` ni `category_maps.json`.
3. El dataset contiene benignos derivados de alertas operacionales, no una muestra completa de normalidad real.
4. La etiqueta `ATTACK/BENIGN` es una weak label derivada de grupos Wazuh, MITRE, severidad y reglas operacionales.
5. El umbral activo es bajo (`0.0743434343`), seleccionado para F1, no necesariamente para presupuesto SOC o baja tasa de falsos positivos.
6. La salida actual solo permite `attack` o `benign`, sin zona intermedia de sospecha.
7. El pipeline de inferencia existente evalua splits ya preparados; no hay adaptador completo para eventos SIEM crudos en streaming.

## Contrato De Features Que Debe Recuperarse

El perfil activo esperado es `operational_no_label_proxy` con 16 columnas:

```text
alert_count
unique_rule_count
unique_src_ip_count
unique_src_user_count
unique_dst_user_count
unique_decoder_count
unique_program_count
unique_location_count
src_ip_present_count
src_port_present_count
has_new_src_ip
has_new_rule_id
event_hour
event_minute
day_of_week
agent_id_code
```

Acciones requeridas:

1. Convertir el contrato de features en un artefacto versionado y obligatorio.
2. Guardar junto al modelo:
   - `feature_columns.json`,
   - `feature_profile.json`,
   - `category_maps.json`,
   - `split_policy.json`,
   - `prepare_dataset_summary.json`,
   - hash del schema,
   - version del extractor.
3. Validar en inferencia:
   - columnas presentes,
   - orden exacto,
   - tipos numericos,
   - nulos,
   - rangos esperados,
   - codigos categoricos desconocidos.
4. Fallar en modo seguro si el contrato no coincide.
5. Emitir metadatos de diagnostico cuando se use un valor por defecto o categoria desconocida.

## Nuevo Dataset De Validacion Operacional

El siguiente dataset no debe limitarse a alertas etiquetadas como incidentes. Debe incluir benignos reales y ataques claros.

Benignos requeridos:

- logins correctos,
- cambios administrativos autorizados,
- backups,
- actualizaciones de paquetes o sistema,
- keepalives,
- eventos normales Windows,
- eventos normales Linux,
- conexiones internas esperadas,
- reinicios o cambios de servicio planificados,
- eventos de inventario o monitorizacion,
- actividad de mantenimiento fuera y dentro de horario.

Ataques requeridos:

- fuerza bruta SSH o RDP,
- login exitoso posterior a multiples fallos,
- enumeracion o reconocimiento,
- acceso web sospechoso,
- cambios de integridad no autorizados,
- actividad lateral simulada,
- elevacion de privilegios si el lab lo permite,
- ejecucion de comandos anomala,
- eventos con MITRE o reglas Wazuh de alta severidad.

Sospechosos requeridos:

- eventos de severidad media sin evidencia suficiente,
- actividad nueva pero no claramente maliciosa,
- cambios administrativos fuera de horario,
- login correcto desde origen nuevo,
- errores repetidos de servicio,
- actividad interna poco frecuente.

## Politica De Etiquetado Recomendada

Separar etiqueta tecnica y etiqueta SOC:

| Campo | Valores | Proposito |
|---|---|---|
| `ground_truth_binary` | `benign`, `attack` | Evaluacion binaria clasica. |
| `ground_truth_triage` | `benign`, `suspicious`, `attack` | Evaluacion SOC y politica de salida. |
| `scenario_id` | texto controlado | Trazabilidad del ejercicio/lab. |
| `label_source` | `manual`, `scenario`, `rule_proxy`, `analyst_feedback` | Diferenciar verdad fuerte de weak labels. |
| `label_confidence` | `low`, `medium`, `high` | Control academico de incertidumbre. |

La weak label actual puede conservarse como bootstrap, pero no debe ser la unica verdad para produccion.

## Refactor Del Feature Pipeline

Fase 1: extractor reproducible.

- Separar `parse_jsonl`, agregacion por ventana y transformacion final en modulos reutilizables.
- Crear una clase o funcion unica `LabAlertsFeatureExtractor`.
- Parametrizar `window_size`, `group_key`, categoria desconocida y memoria temporal.
- Persistir estado para:
  - `has_new_src_ip`,
  - `has_new_rule_id`,
  - futuras features first-seen.
- Usar siempre el mismo `category_maps.json` en train e inference.
- Codificar categorias desconocidas como `0` y registrar warning.

Fase 2: validacion de contrato.

- Crear `schema_contract.json`.
- Calcular `schema_hash`.
- Validar antes de predecir.
- Incluir prueba que cargue el modelo activo y confirme que el extractor produce exactamente 16 columnas en el orden esperado.

Fase 3: adaptador de produccion.

- Crear inferencia desde eventos Wazuh/SIEM crudos, no solo desde parquet preparado.
- Mantener ventanas de 1 minuto y opcionalmente 5 minutos.
- Emitir eventos enriquecidos, no incidentes automaticos por defecto.

## Reentrenamiento Y Calibracion

Modelos base:

1. HistGradientBoostingClassifier binario.
2. Random Forest o Gradient Boosting como baseline supervisado.
3. Isolation Forest entrenado solo con benignos operacionales.
4. Modelo triage si hay suficientes etiquetas `suspicious`.

Politica recomendada:

- Entrenar con train temporal.
- Calibrar probabilidades en validation operacional.
- Seleccionar thresholds en holdout operacional, no solo por F1.
- Comparar:
  - reglas/Wazuh solo,
  - ML solo,
  - scoring hibrido SIEM + ML + contexto.

Thresholds propuestos:

| Salida | Condicion inicial |
|---|---|
| `benign` | `ai_risk_score < 40` y sin correlacion fuerte |
| `suspicious` | `40 <= ai_risk_score < 75` o novedad/contexto debil |
| `attack` | `ai_risk_score >= 75` o score medio con correlacion fuerte |

Los valores deben recalibrarse con el holdout operacional.

## Nueva Salida SIEM

Sustituir la dependencia exclusiva de `ml.prediction` por tres campos explicitos:

```json
{
  "ai_risk_score": 0,
  "ai_classification": "benign",
  "ai_confidence": 0.0
}
```

Campos recomendados:

| Campo | Descripcion |
|---|---|
| `ai_risk_score` | Riesgo operacional 0-100, combinando probabilidad ML y contexto. |
| `ai_classification` | `benign`, `suspicious` o `attack`. |
| `ai_confidence` | Confianza calibrada de la decision. |
| `ml.score_attack` | Probabilidad o score calibrado de ataque. |
| `ml.threshold_suspicious` | Umbral inferior de sospecha. |
| `ml.threshold_attack` | Umbral superior de ataque. |
| `ml.feature_contract_version` | Version del contrato de features usado. |
| `ml.feature_contract_hash` | Hash verificable del schema. |
| `ml.extractor_version` | Version del extractor. |
| `ml.inference_warnings` | Warnings de schema, categorias desconocidas o imputaciones. |

Regla SOC:

- `benign`: enriquecer o no exportar segun necesidad.
- `suspicious`: exportar como evento/enrichment para correlacion.
- `attack`: exportar como alerta.
- Incidente automatico solo si hay correlacion, alta confianza o politica explicita.

## Evaluacion

Metricas ML:

- precision,
- recall,
- F1,
- PR-AUC,
- ROC-AUC,
- FPR,
- matriz de confusion binaria y triage,
- calibracion: ECE y Brier score.

Metricas SOC:

- alertas por hora y por dia,
- reduccion de alertas redundantes,
- falsos positivos por tipo benigno,
- latencia desde evento a score,
- porcentaje de eventos `suspicious` que escalan a `attack`,
- estabilidad con ventanas streaming,
- impacto de allowlists y supresiones temporales.

Evaluaciones minimas:

1. Test historico LAB-ALERTS actual para compatibilidad.
2. Holdout operacional con benignos reales.
3. Escenarios de ataque controlados.
4. Replay o batch temporal para medir latencia y volumen.
5. Prueba de drift entre dias/sesiones del laboratorio.

## Criterios De Aceptacion

El refactor se considerara listo cuando:

1. El artefacto de modelo sea autosuficiente y contenga contrato de features.
2. La inferencia rechace schemas incompatibles.
3. Exista dataset de validacion con benignos operacionales reales.
4. El modelo no marque todo como `attack` en benignos reales.
5. La salida soporte `benign`, `suspicious` y `attack`.
6. El umbral se seleccione con metricas SOC, no solo F1.
7. Se mida alert rate y false positive rate sobre holdout operacional.
8. El pipeline pueda ejecutarse de forma reproducible desde raw alerts hasta SIEM JSON.

## Roadmap

### Fase 0 - Auditoria

- Confirmar que el modelo activo usa exactamente las 16 columnas copiadas.
- Comparar `training_artifact_20260520_181715` contra `model_store_active`.
- Documentar metadatos ausentes en el archivo de produccion.

### Fase 1 - Contrato

- Crear `schema_contract.json`.
- Copiar contrato y mapas al artefacto archivado.
- Anadir validadores de schema.

### Fase 2 - Dataset Benigno Real

- Definir escenarios benignos.
- Capturar/exportar Wazuh events.
- Etiquetar por `scenario_id`.
- Separar train, validation y holdout temporal.

### Fase 3 - Extractor

- Refactorizar el extractor en modulo reutilizable.
- Implementar modo batch y modo streaming.
- Persistir estado first-seen.

### Fase 4 - Modelado

- Reentrenar HGB binario.
- Entrenar baseline alternativo.
- Entrenar detector anomalico con benignos.
- Calibrar scores.

### Fase 5 - Salida SOC

- Implementar `ai_risk_score`.
- Implementar `ai_classification`.
- Implementar `ai_confidence`.
- Ajustar severidad y `event.kind` segun politica triage.

### Fase 6 - Evaluacion Final

- Comparar reglas solo, ML solo e hibrido.
- Medir precision/recall/F1/PR-AUC.
- Medir alertas por dia, FPR operacional y latencia.
- Redactar resultados con limitaciones, sesgos y deriva.

## Riesgos

| Riesgo | Impacto | Mitigacion |
|---|---|---|
| Benignos insuficientes | Falsos positivos altos | Captura operacional controlada y etiquetado manual. |
| Feature mismatch | Scores invalidos | Contrato obligatorio y validacion previa a predict. |
| Weak labels demasiado cercanas a Wazuh | Resultados optimistas | Mantener etiquetas manuales/scenario para holdout. |
| Umbral optimizado solo por F1 | Exceso de alertas | Seleccion por presupuesto SOC y precision minima. |
| Drift temporal | Degradacion en produccion | Recalibracion y monitorizacion de distribucion. |
| Categorias nuevas | Codigos incorrectos | `Unknown=0`, warnings y metricas de cobertura. |

## Decision Recomendada

No usar LAB-ALERTS activo como detector final hasta completar como minimo:

1. contrato de features autosuficiente,
2. adaptador de inferencia desde eventos SIEM crudos,
3. holdout con benignos operacionales reales,
4. recalibracion de umbrales,
5. salida triage `benign/suspicious/attack`.

Mientras tanto, el modelo actual puede mantenerse como candidato de laboratorio para enriquecimiento, no como generador autonomo de incidentes.
