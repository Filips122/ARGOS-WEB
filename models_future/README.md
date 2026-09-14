# Models Future

This folder keeps the models from `models_IA` that are technically useful but not ready for direct per-alert Wazuh scoring in the current ARGOS web flow.

The current production path remains:

- `models_examples`: `LAB-ALERTS` for the main AI score.
- `models_examples`: `COWRIE_FULL` for honeypot taxonomy/enrichment.

## Future Candidates

| model | future use | why not active now |
| --- | --- | --- |
| `gru_cic_day_20260520_145849` | Sequence-based network attack detection | Needs CIC-style sequence windows and PyTorch GRU inference. |
| `hgb_unsw_binary_groupkfold0_20260520_135042` | Tabular network-flow detector | Needs UNSW-like flow features, not raw Wazuh alert fields. |
| `hgb_ugr16_binary_date_20260520_151846_sigmoid_calibrated_20260602_ugr16_sigmoid` | Temporal network baseline | Needs temporal network features and SOC rate limiting due high alert rate. |
| `isoforest_csr_entity_day_20260531_002323_fold0` | Entity-day SOC triage | Needs daily aggregation and top-k triage evaluation. |

## What Was Copied

- `model_store/`: model artifacts, manifests, metadata, metrics and thresholds.
- `policies/`: SOC production policy plus the CIC independent threshold policy.
- `threshold_runs/`: CIC threshold sweeps/evidence.
- `tools/`: Python inference/evaluation helpers from `models_IA`.
- `examples/`: CIC SIEM event example.
- `active_model_registry.json`: local registry with future roles, paths, metrics and requirements.

## Activation Roadmap

1. Keep LAB-ALERTS as the first live AI score for Wazuh alerts.
2. Add a feature extraction service that can emit:
   - Wazuh/SIEM operational features for LAB.
   - Flow/tabular features for UNSW.
   - Temporal features for UGR16.
   - Sequence tensors for CIC GRU.
   - Entity-day aggregates for CSR-LANL.
3. Add adapters per model family:
   - sklearn/joblib adapter for HGB and IsolationForest.
   - PyTorch adapter for CIC GRU.
   - calibrator support for UGR16.
4. Route model outputs through `risk_score`, SOC policy, deduplication and rate limits before showing them as analyst-facing alerts.

## Integration Warning

These models should not be connected directly to the current Wazuh alert normalizer. They answer different questions than `LAB-ALERTS`: network-flow anomaly, sequence attack detection, temporal baseline, or entity-day triage. They become valuable once ARGOS ingests Zeek/Suricata/netflow/authentication aggregates alongside Wazuh.
