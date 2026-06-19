#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import random
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
from sklearn.preprocessing import LabelEncoder


def repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "package.json").exists() or (parent / "LAB_ALERTS_REFACTOR").exists():
            return parent
    return Path(__file__).resolve().parents[2]


def resolve_from_root(path: str | Path) -> Path:
    candidate = Path(path).expanduser()
    if candidate.is_absolute():
        return candidate.resolve()
    return (repo_root() / candidate).resolve()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def save_json(path: Path, payload: Dict) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json_optional(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def dataset_summary_path(datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Path:
    base = resolve_from_root(datasets_base) / split_mode / dataset
    if split_mode == "groupkfold" and fold is not None:
        return base / f"fold_{fold}" / "prepare_dataset_summary.json"
    return base / "prepare_dataset_summary.json"


def dataset_profile_reference(datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Dict[str, Any]:
    summary_path = dataset_summary_path(datasets_base, split_mode, dataset, fold)
    summary = read_json_optional(summary_path)
    profile = read_json_optional(summary_path.parent / "feature_profile.json")
    contract = read_json_optional(summary_path.parent / "schema_contract.json")
    if summary is None:
        return {"status": "missing", "path": str(summary_path), "dataset": dataset, "fold": fold}
    return {
        "status": "ok",
        "path": str(summary_path),
        "dataset": summary.get("dataset"),
        "split_mode": split_mode,
        "fold": fold,
        "window_size": summary.get("window_size"),
        "group_key": summary.get("group_key"),
        "feature_profile": summary.get("feature_profile"),
        "feature_profile_description": summary.get("feature_profile_description"),
        "feature_count": summary.get("feature_count"),
        "excluded_feature_count": summary.get("excluded_feature_count"),
        "feature_profile_path": None if profile is None else str(summary_path.parent / "feature_profile.json"),
        "schema_contract_path": None if contract is None else str(summary_path.parent / "schema_contract.json"),
        "schema_hash": None if contract is None else contract.get("schema_hash"),
        "extractor_version": None if contract is None else contract.get("extractor_version"),
    }


def dataset_root(datasets_base: str | Path, split_mode: str, dataset: str, fold: Optional[int] = None) -> Path:
    root = resolve_from_root(datasets_base) / split_mode / dataset
    if split_mode == "groupkfold" and fold is not None:
        return root / f"fold_{fold}"
    return root


def copy_dataset_contract_artifacts(root: Path, split_mode: str, dataset: str, fold: Optional[int] = None, datasets_base: str | Path = "LAB_ALERTS_REFACTOR/prepared_dataset") -> Dict[str, str]:
    source_root = dataset_root(datasets_base, split_mode, dataset, fold)
    copied: Dict[str, str] = {}
    metadata_dir = root / "feature_contract"
    for filename in [
        "feature_columns.json",
        "feature_profile.json",
        "category_maps.json",
        "split_policy.json",
        "prepare_dataset_summary.json",
        "schema_contract.json",
    ]:
        source = source_root / filename
        if source.exists():
            ensure_dir(metadata_dir)
            destination = metadata_dir / filename
            shutil.copy2(source, destination)
            copied[filename] = str(destination)
    save_json(root / "feature_contract_ref.json", copied)
    return copied


def save_dataset_profile_ref(root: Path, split_mode: str, dataset: str, fold: Optional[int] = None, datasets_base: str | Path = "LAB_ALERTS_REFACTOR/prepared_dataset") -> Dict[str, Any]:
    ref = dataset_profile_reference(datasets_base, split_mode, dataset, fold)
    save_json(root / "dataset_profile_ref.json", ref)
    copy_dataset_contract_artifacts(root, split_mode, dataset, fold, datasets_base)
    return ref


def save_run_metadata(root: Path, model_name: str, split_mode: str, run_id: str, dataset: str = "LAB-ALERTS", datasets_base: str | Path = "LAB_ALERTS_REFACTOR/prepared_dataset", run_config: Optional[Dict[str, Any]] = None) -> None:
    payload: Dict[str, Any] = {
        "dataset": dataset,
        "model_name": model_name,
        "split_mode": split_mode,
        "run_id": run_id,
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifact_root": str(root),
        "dataset_profile": dataset_profile_reference(datasets_base, split_mode, dataset),
    }
    if run_config is not None:
        payload["run_config"] = run_config
        if "sample_frac" in run_config:
            payload["sample_frac"] = run_config.get("sample_frac")
    save_json(root / "run_metadata.json", payload)


def artifacts_root(model_name: str, split_mode: str, run_id: Optional[str] = None, dataset: str = "LAB-ALERTS", datasets_base: str | Path = "LAB_ALERTS_REFACTOR/prepared_dataset", run_config: Optional[Dict[str, Any]] = None) -> Path:
    run_id = run_id or now_run_id()
    root = resolve_from_root(f"LAB_ALERTS_REFACTOR/artifacts/{model_name}/{split_mode}/{run_id}")
    ensure_dir(root)
    save_run_metadata(root, model_name, split_mode, run_id, dataset=dataset, datasets_base=datasets_base, run_config=run_config)
    save_dataset_profile_ref(root, split_mode, dataset, datasets_base=datasets_base)
    return root


def fit_label_encoder(y_train: np.ndarray) -> LabelEncoder:
    encoder = LabelEncoder()
    encoder.fit(y_train.astype(str))
    classes = list(map(str, encoder.classes_))
    if len(classes) == 2 and "BENIGN" in classes and "ATTACK" in classes:
        encoder.classes_ = np.array(["BENIGN", "ATTACK"], dtype=encoder.classes_.dtype)
    return encoder


def save_label_encoder(path: Path, encoder: LabelEncoder) -> Dict[str, int]:
    mapping = {str(label): int(index) for index, label in enumerate(encoder.classes_)}
    save_json(path / "label_map.json", mapping)
    return mapping


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    np.random.seed(seed)
