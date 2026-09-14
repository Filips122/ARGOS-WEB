# Models Examples Selection

This folder contains the active model package used by ARGOS web integration with Wazuh alerts.

## Active Models

| role | model_id | inference | threshold | test result |
| --- | --- | --- | --- | --- |
| Primary AI score detector | `hgb_lab_alerts_binary_refactor_date_20260606_194229` | 1-minute windows grouped by `agent_id` | `0.5` | accuracy `0.9884`, macro F1 `0.9878`, ROC-AUC `0.9931` |
| LAB alert taxonomy | `hgb_lab_alerts_multiclass_refactor_date_20260606_194256` | same 1-minute LAB-ALERTS feature contract | `0.5` | accuracy `0.9729`, macro F1 `0.9152` |

## Runtime Strategy

The active LAB model is not a per-alert feature model. It scores behavior aggregated into windows:

1. Read raw Wazuh alerts from the web/API payload.
2. Aggregate alerts by `window_size=1min` and `group_key=agent_id`.
3. Build the 16 operational LAB-ALERTS features from `feature_contract/schema_contract.json`.
4. Predict binary `benign`/`attack` with the primary model.
5. Copy the window score back to each alert that belongs to that window.
6. Add multiclass taxonomy as enrichment, not as the primary attack decision.

This means the table can still show one AI score per alert, but the score represents the alert's 1-minute agent window.

## Validation Command

Run the scorer directly with a raw Wazuh-like payload:

```powershell
Get-Content models_examples\examples\wazuh_window_scoring_payload.json | .venv\Scripts\python.exe models_examples\score_wazuh_alerts.py
```

The web uses the same script through `lib/ai-scoring.ts`.

## Legacy Models

- `hgb_lab_alerts_binary_date_20260520_181715`: replaced. Its web inference used handcrafted alert-level features and an overly low threshold.
- `hgb_cowrie_multiclass_date_20260520_182459`: kept in `model_store` as a future Cowrie/honeypot taxonomy candidate, but not active in the LAB-ALERTS web scorer.

## Contents

- `active_model_registry.json`: local registry for the selected package.
- `lab_alerts_features.py`: shared runtime feature extractor copied from the refactor pipeline.
- `model_store/`: copied model artifacts, metrics, contracts and metadata.
- `policies/soc_alert_policy.production.json`: SOC alert policy used in the production baseline.
- `examples/lab_alert_siem_event.json`: sample ML event shape for SIEM/web enrichment.
