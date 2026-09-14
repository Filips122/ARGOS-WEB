# Future Work: IA + SIEM/SOC

Este documento resume los modelos recomendados, los datasets asociados y los pasos para evolucionar ARGOS hacia una arquitectura IA más robusta y capaz de generalizar ante alertas no vistas.

## Objetivo

Construir una capa SOC con varios modelos especialistas y una futura capa de fusion que combine sus salidas para producir una decision final:

- `benign`
- `attack`
- `suspicious`
- `final_soc_risk`

La idea no es usar un unico modelo para todos los datasets, sino usar cada dataset en el dominio donde aporta valor.

## Modelos Recomendados

| Modelo | Dataset | Proposito | Uso en ARGOS |
| --- | --- | --- | --- |
| LAB_ALERTS Binary HGB | `LAB_ALERTS` | Clasificar alertas Wazuh/SIEM como `benign` o `attack`. | Modelo principal para `AI Score` y columna `Class`. |
| LAB_ALERTS Multiclass HGB | `LAB_ALERTS` | Clasificar el patron de alerta: `CredentialAccess`, `ServiceFailure`, `OtherAlert`. | Taxonomia IA en el detalle de alerta, no como decision principal. |
| Cowrie Multiclass | `COWRIE` | Clasificar actividad honeypot/SSH. | Enriquecimiento solo si la alerta viene de Cowrie, T-Pot, honeypot o SSH claro. |
| CSR-LANL Anomaly | `CSR-LANL` | Detectar comportamiento raro por entidad, usuario, host o ventana temporal. | Segunda senal SOC: `entity_anomaly_score`. |
| CIC-IDS / UNSW-NB15 / UGR-16 Flow Models | `CIC-IDS-2015`, `UNSW-NB15`, `UGR-16` | Detectar riesgo en trafico de red o flows. | Futuro, cuando ARGOS tenga NetFlow, Zeek, Suricata, firewall logs o features de red reales. |
| Fusion Meta-Model | Salidas de todos los modelos anteriores | Combinar scores especialistas y contexto SOC. | Decision final: `final_soc_risk`, `final_decision`, explicabilidad por fuente. |

## Arquitectura Recomendada

```text
Wazuh alert / SOC event
  -> LAB_ALERTS binary model
       -> attack_score
       -> benign/attack

  -> LAB_ALERTS multiclass model
       -> taxonomy_label
       -> taxonomy_confidence

  -> Cowrie model, solo si aplica
       -> honeypot_taxonomy

  -> CSR-LANL anomaly model
       -> entity_anomaly_score

  -> Network flow models, futuro
       -> network_risk_score

  -> Fusion model
       -> final_soc_risk
       -> final_decision
       -> explanation
```

## Por Que No Usar Un Solo Modelo Con Todos Los Datasets

Los datasets tienen naturalezas distintas:

- `LAB_ALERTS`: alertas SIEM/Wazuh.
- `COWRIE`: honeypot SSH.
- `CIC`, `UNSW`, `UGR`: trafico de red y flows.
- `CSR-LANL`: comportamiento por entidad y tiempo.

Mezclarlos directamente puede crear un modelo incoherente: las features no representan lo mismo y las etiquetas no tienen el mismo significado. Es mejor entrenar modelos especialistas y fusionar sus salidas.

## Paso 1: Consolidar LAB_ALERTS

Estado actual:

- Modelo binario LAB_ALERTS integrado en `models_examples`.
- Modelo multiclass LAB_ALERTS integrado como taxonomia.
- Inferencia por ventanas de `1min` agrupadas por `agent_id`.
- Simulaciones benignas para probar generalizacion.

Siguientes mejoras:

- Anadir benignos reales administrativos:
  - login admin correcto
  - backup
  - update de paquetes
  - MFA reset
  - helpdesk
  - mantenimiento programado
  - actividad de monitorizacion
- Reentrenar LAB_ALERTS con esos benignos.
- Comparar falsos positivos antes/despues.

## Paso 2: Anadir CSR-LANL Como Anomalia De Entidad

Proposito:

Detectar si un usuario, host o agente se comporta de forma rara aunque la alerta individual parezca normal.

Salida esperada:

```json
{
  "entity_anomaly_score": 0.82,
  "entity": "agent-025",
  "window": "1h",
  "reason": "unusual destination or time pattern"
}
```

Uso en ARGOS:

- Mostrar en detalle de alerta.
- Usarlo como senal secundaria, no como decision unica.
- Ayudar a distinguir benignos administrativos normales vs actividad rara.

## Paso 3: Activar Cowrie Solo En Alertas Honeypot

Condicion de activacion:

- `decoder.name` contiene `cowrie`
- `location` contiene `cowrie`
- `agent.name` o `rule.description` menciona honeypot/T-Pot/Cowrie

Salida esperada:

```json
{
  "cowrie_taxonomy": "ssh_command_execution",
  "confidence": 0.91
}
```

Uso:

- Enriquecimiento de detalle.
- No usar como detector general `benign/attack`.

## Paso 4: Preparar Modelos De Red

Datasets:

- `CIC-IDS-2015`
- `UNSW-NB15`
- `UGR-16`

Requisito:

ARGOS necesita eventos de red reales con features tipo:

- `src_ip`
- `dst_ip`
- `src_port`
- `dst_port`
- `protocol`
- `duration`
- `bytes`
- `packets`
- `flags`
- `flow_count`
- `connection_state`

Fuentes posibles:

- Suricata
- Zeek
- NetFlow
- Firewall logs
- Wazuh alerts enriquecidas con datos de red

Uso futuro:

```json
{
  "network_risk_score": 0.77,
  "network_model": "unsw_or_cic_flow_detector",
  "reason": "flow resembles malicious network activity"
}
```

## Paso 5: Crear Modelo De Fusion

Primera version recomendada:

- `LogisticRegression`
- `HistGradientBoostingClassifier`
- `RandomForest`

No empezar directamente con Transformer. Primero hace falta tener datos alineados por ventana.

Inputs del meta-modelo:

- `lab_alerts_attack_score`
- `lab_alerts_prediction`
- `lab_alerts_taxonomy`
- `taxonomy_confidence`
- `cowrie_taxonomy_confidence`
- `entity_anomaly_score`
- `network_risk_score`
- `wazuh_rule_level`
- `hour`
- `agent_id`
- `src_ip_present`
- `internal_or_external_source`

Salida:

```json
{
  "final_soc_risk": 87,
  "final_decision": "attack",
  "explanation": {
    "lab_alerts": "high attack probability",
    "entity_anomaly": "normal",
    "network": "not available"
  }
}
```

## Paso 6: Probar Modelo De Atencion

Cuando existan suficientes datos alineados:

- muchas ventanas reales
- salidas de modelos especialistas
- etiquetas finales revisadas
- benignos administrativos variados

Probar:

- `TabTransformer`
- `FT-Transformer`
- Transformer encoder sobre secuencias de ventanas

Proposito:

Aprender que senal pesa mas segun el contexto.

Ejemplo:

```text
LAB_ALERTS dice attack alto
CSR-LANL dice comportamiento normal
Network dice sin riesgo
Contexto dice horario administrativo normal

Fusion final: suspicious o low-confidence attack, no critical automatico
```

## Experimentos Para La Tesis

Experimento 1:

Comparar Wazuh baseline vs LAB_ALERTS binary.

Experimento 2:

Medir falsos positivos en benignos administrativos no vistos.

Experimento 3:

Reentrenar LAB_ALERTS con benignos administrativos y medir mejora.

Experimento 4:

Anadir CSR-LANL anomaly score como segunda senal.

Experimento 5:

Entrenar meta-modelo de fusion y comparar:

```text
Wazuh solo
LAB_ALERTS solo
LAB_ALERTS + taxonomy
LAB_ALERTS + anomaly
Fusion model
```

## Conclusion Recomendada

La linea mas solida para ARGOS es:

```text
Modelo especialista SIEM primero.
Modelos especialistas por dominio despues.
Capa de fusion al final.
Modelo de atencion solo cuando existan suficientes datos alineados.
```

Esto permite defender que IA + SIEM/SOC es util, pero tambien demostrar sus limites: un modelo entrenado solo con ciertos benignos no generaliza automaticamente a todos los benignos administrativos reales.
