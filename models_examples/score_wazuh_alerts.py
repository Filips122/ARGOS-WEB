import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import joblib
import numpy as np
import pandas as pd

from lab_alerts_features import LabAlertsFeatureExtractor, normalize_text


ROOT = Path(__file__).resolve().parent

LAB_MODEL_ID = "hgb_lab_alerts_binary_refactor_date_20260606_194229"
LAB_VERSION = "20260606_194229"
LAB_DIR = ROOT / "model_store" / LAB_MODEL_ID / LAB_VERSION
LAB_MODEL_PATH = LAB_DIR / "model.joblib"
LAB_LABEL_MAP_PATH = LAB_DIR / "label_map.json"
LAB_CONTRACT_PATH = LAB_DIR / "feature_contract" / "schema_contract.json"
LAB_THRESHOLD = 0.5

TAXONOMY_MODEL_ID = "hgb_lab_alerts_multiclass_refactor_date_20260606_194256"
TAXONOMY_VERSION = "20260606_194256"
TAXONOMY_DIR = ROOT / "model_store" / TAXONOMY_MODEL_ID / TAXONOMY_VERSION
TAXONOMY_MODEL_PATH = TAXONOMY_DIR / "model.joblib"
TAXONOMY_LABEL_MAP_PATH = TAXONOMY_DIR / "label_map.json"
TAXONOMY_CONTRACT_PATH = TAXONOMY_DIR / "feature_contract" / "schema_contract.json"


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def invert_label_map(label_map: Dict[str, int]) -> Dict[int, str]:
    return {int(index): str(label) for label, index in label_map.items()}


def attack_class_index(label_map: Dict[str, int]) -> int:
    for label, index in label_map.items():
        if str(label).upper() == "ATTACK":
            return int(index)
    return 1


def risk_score(probability: float) -> int:
    return int(round(max(0.0, min(1.0, probability)) * 100))


def severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def fallback_result(hit: Dict[str, Any], reason: str) -> Dict[str, Any]:
    return {
        "id": hit.get("_id"),
        "model_id": LAB_MODEL_ID,
        "model_version": LAB_VERSION,
        "model_type": "hgb_binary_window",
        "score": 0.0,
        "threshold": LAB_THRESHOLD,
        "prediction": "benign",
        "risk_score": 0,
        "severity": "low",
        "confidence": 0.0,
        "source": "fallback",
        "window": None,
        "warnings": [reason],
    }


def hit_source(hit: Dict[str, Any]) -> Dict[str, Any]:
    source = hit.get("_source") or {}
    return source if isinstance(source, dict) else {}


def build_events(
    hits: List[Dict[str, Any]],
    extractor: LabAlertsFeatureExtractor,
) -> Tuple[pd.DataFrame, Dict[int, Tuple[str, str]]]:
    rows: List[Dict[str, Any]] = []
    hit_keys: Dict[int, Tuple[str, str]] = {}
    for hit_index, hit in enumerate(hits):
        row = extractor._event_row(hit_source(hit), hit_index + 1)
        row["hit_index"] = hit_index
        rows.append(row)

    if not rows:
        return pd.DataFrame(), hit_keys

    events = pd.DataFrame(rows)
    events["event_ts"] = pd.to_datetime(events["timestamp"], errors="coerce", utc=True)
    events = events[events["event_ts"].notna()].copy()
    if events.empty:
        return events, hit_keys

    events["window_start"] = events["event_ts"].dt.floor(extractor.window_size)
    events.sort_values(["event_ts", "line_number"], inplace=True)
    for _, row in events.iterrows():
        key = (str(row["window_start"]), normalize_text(row.get(extractor.group_key)))
        hit_keys[int(row["hit_index"])] = key
    return events, hit_keys


def window_keys(events: pd.DataFrame, group_key: str) -> List[Tuple[str, str]]:
    keys: List[Tuple[str, str]] = []
    grouped = events.groupby(["window_start", group_key], sort=True, dropna=False)
    for (window_start, agent_id), _ in grouped:
        keys.append((str(window_start), normalize_text(agent_id)))
    return keys


def prediction_from_probability(probability: float) -> str:
    return "attack" if probability >= LAB_THRESHOLD else "benign"


def class_probability(model: Any, frame: pd.DataFrame, class_index: int) -> np.ndarray:
    probabilities = model.predict_proba(frame)
    classes = [int(value) for value in getattr(model, "classes_", [])]
    column = classes.index(class_index) if class_index in classes else class_index
    return probabilities[:, column]


def taxonomy_by_window(model: Any, label_map: Dict[str, int], frame: pd.DataFrame, keys: List[Tuple[str, str]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    labels = invert_label_map(label_map)
    probabilities = model.predict_proba(frame)
    classes = [int(value) for value in getattr(model, "classes_", [])]
    taxonomy: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row_index, key in enumerate(keys):
        best_column = int(np.argmax(probabilities[row_index]))
        class_id = int(classes[best_column]) if classes else best_column
        taxonomy[key] = {
            "model_id": TAXONOMY_MODEL_ID,
            "model_version": TAXONOMY_VERSION,
            "label": labels.get(class_id, str(class_id)),
            "confidence": float(probabilities[row_index][best_column]),
        }
    return taxonomy


def score_windows(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    lab_contract = read_json(LAB_CONTRACT_PATH)
    taxonomy_contract = read_json(TAXONOMY_CONTRACT_PATH)
    lab_model = joblib.load(LAB_MODEL_PATH)
    taxonomy_model = joblib.load(TAXONOMY_MODEL_PATH)
    lab_label_map = read_json(LAB_LABEL_MAP_PATH)
    taxonomy_label_map = read_json(TAXONOMY_LABEL_MAP_PATH)

    extractor = LabAlertsFeatureExtractor.from_contract(lab_contract)
    events, hit_keys = build_events(hits, extractor)
    if events.empty:
        return [fallback_result(hit, "missing_or_invalid_timestamp") for hit in hits]

    frame = extractor.aggregate_events(events)
    keys = window_keys(events, extractor.group_key)
    attack_index = attack_class_index(lab_label_map)
    attack_probabilities = class_probability(lab_model, frame, attack_index)

    taxonomy: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if taxonomy_contract.get("schema_hash") == lab_contract.get("schema_hash"):
        taxonomy = taxonomy_by_window(taxonomy_model, taxonomy_label_map, frame, keys)

    by_window: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row_index, key in enumerate(keys):
        probability = float(attack_probabilities[row_index])
        prediction = prediction_from_probability(probability)
        score = risk_score(probability)
        confidence = probability if prediction == "attack" else 1.0 - probability
        by_window[key] = {
            "model_id": LAB_MODEL_ID,
            "model_version": LAB_VERSION,
            "model_type": "hgb_binary_window",
            "score": probability,
            "threshold": LAB_THRESHOLD,
            "prediction": prediction,
            "risk_score": score,
            "severity": severity(score),
            "confidence": float(confidence),
            "source": "model",
            "window": {
                "window_start": key[0],
                "group_key": extractor.group_key,
                "group_value": key[1],
                "window_size": extractor.window_size,
                "schema_hash": lab_contract.get("schema_hash"),
            },
        }
        if key in taxonomy:
            by_window[key]["taxonomy"] = taxonomy[key]
        if extractor.warnings:
            by_window[key]["warnings"] = sorted(set(extractor.warnings))[:20]

    results: List[Dict[str, Any]] = []
    for hit_index, hit in enumerate(hits):
        key = hit_keys.get(hit_index)
        if key is None or key not in by_window:
            results.append(fallback_result(hit, "alert_not_in_valid_window"))
            continue
        result = dict(by_window[key])
        result["id"] = hit.get("_id")
        results.append(result)
    return results


def main() -> None:
    payload = json.load(sys.stdin)
    hits = payload.get("hits", [])
    if not isinstance(hits, list):
        hits = []
    json.dump({"results": score_windows(hits)}, sys.stdout)


if __name__ == "__main__":
    main()
