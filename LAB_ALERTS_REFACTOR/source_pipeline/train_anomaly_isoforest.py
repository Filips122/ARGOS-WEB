#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from data_loader import EmptySplitError, load_splits
from metrics import evaluate_anomaly_scores
from reporting import save_anomaly_plots
from train_utils import artifacts_root, now_run_id, save_dataset_profile_ref, save_json


def run_one(split_mode: str, fold: int | None, epochs: int, out_dir, dataset: str, datasets_base: str) -> dict:
    train, val, test = load_splits(
        datasets_base=datasets_base,
        split_mode=split_mode,
        dataset=dataset,
        pipeline="anomaly",
        fold=fold,
    )
    X_train = pd.DataFrame(train.X.astype(np.float32), columns=train.feature_names)
    X_val = pd.DataFrame(val.X.astype(np.float32), columns=val.feature_names)
    X_test = pd.DataFrame(test.X.astype(np.float32), columns=test.feature_names)
    model = IsolationForest(n_estimators=epochs, contamination="auto", random_state=42, n_jobs=-1)
    model.fit(X_train)
    val_scores = -model.score_samples(X_val)
    test_scores = -model.score_samples(X_test)
    val_report = evaluate_anomaly_scores(val.y, val_scores, positive_label="ATTACK")
    test_report = evaluate_anomaly_scores(test.y, test_scores, positive_label="ATTACK")
    save_anomaly_plots(out_dir, "val", val.y, val_scores, positive_label="ATTACK")
    save_anomaly_plots(out_dir, "test", test.y, test_scores, positive_label="ATTACK")
    return {
        "model": model,
        "feature_names": train.feature_names,
        "val": {"roc_auc": val_report.roc_auc, "pr_auc": val_report.pr_auc, "best_f1": val_report.best_f1, "best_threshold": val_report.best_threshold},
        "test": {"roc_auc": test_report.roc_auc, "pr_auc": test_report.pr_auc, "best_f1": test_report.best_f1, "best_threshold": test_report.best_threshold},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split_mode", default="date", choices=["date", "random", "groupkfold"])
    parser.add_argument("--dataset", default="LAB-ALERTS")
    parser.add_argument("--all_folds", action="store_true")
    parser.add_argument("--fold", type=int, default=None)
    parser.add_argument("--n_folds", type=int, default=5)
    parser.add_argument("--epochs", type=int, default=315)
    parser.add_argument("--datasets_base", default="LAB_ALERTS_REFACTOR/prepared_dataset")
    args = parser.parse_args()
    root = artifacts_root(
        "anomaly_isoforest_LAB_ALERTS",
        args.split_mode,
        now_run_id(),
        dataset=args.dataset,
        datasets_base=args.datasets_base,
        run_config={"epochs": args.epochs, "datasets_base": args.datasets_base},
    )
    if args.split_mode != "groupkfold":
        try:
            out = run_one(args.split_mode, None, args.epochs, root, args.dataset, args.datasets_base)
        except (FileNotFoundError, EmptySplitError) as exc:
            raise SystemExit(f"{args.dataset} anomaly split is missing or empty: {exc}")
        joblib.dump(out["model"], root / "model.joblib")
        save_json(root / "model_feature_names.json", {"feature_names": out["feature_names"]})
        save_json(root / "results.json", {"val": out["val"], "test": out["test"], "best_epoch": None})
        save_dataset_profile_ref(root, args.split_mode, args.dataset, datasets_base=args.datasets_base)
        print("Saved:", root)
        return
    folds = range(args.n_folds) if args.all_folds else [0 if args.fold is None else args.fold]
    summary = {}
    for fold in folds:
        fold_dir = root / f"fold_{fold}"
        fold_dir.mkdir(parents=True, exist_ok=True)
        try:
            out = run_one("groupkfold", int(fold), args.epochs, fold_dir, args.dataset, args.datasets_base)
        except (FileNotFoundError, EmptySplitError) as exc:
            summary[f"fold_{fold}"] = {"skipped": True, "reason": str(exc)}
            continue
        joblib.dump(out["model"], fold_dir / "model.joblib")
        save_json(fold_dir / "model_feature_names.json", {"feature_names": out["feature_names"]})
        save_json(fold_dir / "results.json", {"val": out["val"], "test": out["test"], "best_epoch": None})
        save_dataset_profile_ref(fold_dir, "groupkfold", args.dataset, int(fold), datasets_base=args.datasets_base)
        summary[f"fold_{fold}"] = {"val": out["val"], "test": out["test"]}
    save_json(root / "summary.json", summary)
    print("Saved:", root)


if __name__ == "__main__":
    main()
