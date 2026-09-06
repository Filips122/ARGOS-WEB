# -*- coding: utf-8 -*-
"""9.1 Ablacion del atajo + 9.2 generalizacion a maquina no vista.

Reconstruye el frame a nivel de ventana (1 min x agent_id) desde el export de
30 dias y responde dos preguntas que el dossier dejo abiertas:

  9.1  Cuanto rendimiento sobrevive al quitar las vias de atajo:
       - agent_id_code, que identifica la maquina y casi determina la etiqueta
       - las filas de postura (Trivy/SCA), separables por familia de alerta

  9.2  Si el modelo sirve al desplegarse en un servidor del que no hay
       historial: entrenar con N-1 agentes y evaluar sobre el que falta.

Reglas que respeta: particion TEMPORAL, nunca aleatoria; ninguna metrica
agregada sin su desglose por grupo; se reporta PR-AUC y no solo exactitud.

    .venv/Scripts/python.exe experiments/shortcut_ablation.py
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, f1_score, matthews_corrcoef, roc_auc_score

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "argos-alerts_30d.jsonl"
OUT = ROOT / "experiments" / "results"
SEED = 42

# Las 16 del perfil operativo del modelo activo.
FEATURES = [
    "alert_count", "unique_rule_count", "unique_src_ip_count", "unique_src_user_count",
    "unique_dst_user_count", "unique_decoder_count", "unique_program_count",
    "unique_location_count", "src_ip_present_count", "src_port_present_count",
    "has_new_src_ip", "has_new_rule_id", "event_hour", "event_minute", "day_of_week",
    "agent_id_code",
]

# Derivadas del motor de reglas: circularidad (README del scorer, §4.1).
RULE_ENGINE = ["unique_rule_count", "unique_decoder_count", "has_new_rule_id"]
# Identidad de la maquina: confundido distribuido (§4.2).
HOST_IDENTITY = ["agent_id_code"]


def build_windows(limit: int | None = None) -> pd.DataFrame:
    """Agrega el export a ventanas de 1 min x agente, en orden temporal."""
    if not DATASET.exists():
        sys.exit(f"Falta {DATASET}. Generalo con /api/argos/dataset?format=jsonl")

    windows: dict[tuple[str, str], dict] = {}
    seen_ips: set[str] = set()
    seen_rules: set[str] = set()
    agents: dict[str, int] = {}
    rows = 0

    with open(DATASET, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            r = json.loads(line)
            rows += 1
            if limit and rows > limit:
                break

            key = (r["window_start"], r["agent_id"])
            w = windows.get(key)
            if w is None:
                w = windows[key] = {
                    "window_start": r["window_start"], "agent_id": r["agent_id"],
                    "alert_count": 0, "rules": set(), "src_ips": set(), "src_users": set(),
                    "dst_users": set(), "decoders": set(), "programs": set(), "locations": set(),
                    "src_ip_present": 0, "src_port_present": 0,
                    "attack": 0, "benign": 0, "posture": 0,
                }
            w["alert_count"] += 1
            w["rules"].add(r["rule_id"])
            if r["src_ip"]:
                w["src_ips"].add(r["src_ip"]); w["src_ip_present"] += 1
            if r["src_port"]:
                w["src_port_present"] += 1
            if r["src_user"]:
                w["src_users"].add(r["src_user"])
            if r["dst_user"]:
                w["dst_users"].add(r["dst_user"])
            w["decoders"].add(r["decoder_name"])
            if r["program_name"]:
                w["programs"].add(r["program_name"])
            w["locations"].add(r["location"])

            if r["weak_label"] == "ATTACK":
                w["attack"] += 1
            elif r["weak_label"] == "BENIGN":
                w["benign"] += 1
            if r["weak_label_reason"].startswith("posture_group:"):
                w["posture"] += 1

    ordered = sorted(windows.values(), key=lambda w: (w["window_start"], w["agent_id"]))
    out = []
    for w in ordered:
        agent = w["agent_id"]
        if agent not in agents:
            agents[agent] = len(agents) + 1
        new_ip = bool(w["src_ips"] - seen_ips)
        new_rule = bool(w["rules"] - seen_rules)
        seen_ips.update(w["src_ips"]); seen_rules.update(w["rules"])
        ts = pd.Timestamp(w["window_start"])

        # Etiqueta por mayoria, igual que el manifiesto del export.
        if w["attack"] == 0 and w["benign"] == 0:
            label = -1
        else:
            label = 1 if w["attack"] >= w["benign"] else 0

        out.append({
            "window_start": w["window_start"], "agent_id": agent, "label": label,
            "posture_share": w["posture"] / w["alert_count"],
            "alert_count": float(w["alert_count"]),
            "unique_rule_count": float(len(w["rules"])),
            "unique_src_ip_count": float(len(w["src_ips"])),
            "unique_src_user_count": float(len(w["src_users"])),
            "unique_dst_user_count": float(len(w["dst_users"])),
            "unique_decoder_count": float(len(w["decoders"])),
            "unique_program_count": float(len(w["programs"])),
            "unique_location_count": float(len(w["locations"])),
            "src_ip_present_count": float(w["src_ip_present"]),
            "src_port_present_count": float(w["src_port_present"]),
            "has_new_src_ip": float(new_ip),
            "has_new_rule_id": float(new_rule),
            "event_hour": float(ts.hour), "event_minute": float(ts.minute),
            "day_of_week": float(ts.dayofweek),
            "agent_id_code": float(agents[agent]),
        })

    frame = pd.DataFrame(out)
    return frame[frame["label"] >= 0].reset_index(drop=True)


def evaluate(train: pd.DataFrame, test: pd.DataFrame, features: list[str]) -> dict:
    if train["label"].nunique() < 2 or len(test) == 0:
        return {"n_train": len(train), "n_test": len(test), "viable": False}

    model = HistGradientBoostingClassifier(random_state=SEED, class_weight="balanced")
    model.fit(train[features], train["label"])
    proba = model.predict_proba(test[features])[:, 1]
    pred = (proba >= 0.5).astype(int)

    # Linea base de clase mayoritaria: con 98 % de positivos, "di siempre
    # ataque" ya acierta el 98 %. Sin este numero, una exactitud de 0,99 no
    # significa nada.
    positive_rate = float(test["label"].mean())
    baseline = max(positive_rate, 1.0 - positive_rate)
    accuracy = float((pred == test["label"]).mean())

    result = {
        "n_train": len(train), "n_test": len(test), "viable": True,
        "test_positive_rate": round(positive_rate, 4),
        "majority_baseline": round(baseline, 4),
        "accuracy": round(accuracy, 4),
        "gain_over_baseline": round(accuracy - baseline, 4),
        "predicted_positive_rate": round(float(pred.mean()), 4),
        "single_class_prediction": bool(len(set(pred.tolist())) == 1),
        "f1": round(float(f1_score(test["label"], pred, zero_division=0)), 4),
        "mcc": round(float(matthews_corrcoef(test["label"], pred)), 4),
    }
    if test["label"].nunique() > 1:
        result["roc_auc"] = round(float(roc_auc_score(test["label"], proba)), 4)
        result["pr_auc"] = round(float(average_precision_score(test["label"], proba)), 4)
    else:
        result["roc_auc"] = None
        result["pr_auc"] = None
        result["note"] = "test de una sola clase: ROC-AUC y PR-AUC no definidos"
    return result


def temporal_split(frame: pd.DataFrame, ratio: float = 0.7):
    cut = int(len(frame) * ratio)
    return frame.iloc[:cut].copy(), frame.iloc[cut:].copy()


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print("Construyendo ventanas desde el export de 30 dias...", flush=True)
    frame = build_windows()
    print(f"  {len(frame):,} ventanas etiquetadas | positivos {frame['label'].mean():.1%}")
    print(f"  agentes: {sorted(frame['agent_id'].unique())}")
    print()

    report: dict = {"seed": SEED, "windows": len(frame), "positive_rate": round(float(frame["label"].mean()), 4)}

    # ---------- 9.1 ablacion ----------
    print("=" * 74)
    print("9.1  ABLACION DEL ATAJO  (particion temporal 70/30)")
    print("=" * 74)
    train, test = temporal_split(frame)
    print(f"  train {len(train):,} ventanas ({train['label'].mean():.1%} positivos) | "
          f"test {len(test):,} ({test['label'].mean():.1%})")
    print()

    variants = {
        "A · 16 features del modelo activo": FEATURES,
        "B · sin identidad de maquina": [f for f in FEATURES if f not in HOST_IDENTITY],
        "C · sin identidad ni motor de reglas": [f for f in FEATURES if f not in HOST_IDENTITY + RULE_ENGINE],
    }
    ablation = {}
    print(f"  linea base (clase mayoritaria): {max(test['label'].mean(), 1-test['label'].mean()):.4f}")
    print()
    print(f"  {'variante':<38} {'exact.':>7} {'ganan.':>7} {'MCC':>7} {'PR-AUC':>7}")
    print(f"  {'-'*38} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")
    for name, feats in variants.items():
        res = evaluate(train, test, feats)
        ablation[name] = {**res, "features": feats}
        print(f"  {name:<38} {res['accuracy']:>7} {res['gain_over_baseline']:>+7} "
              f"{res['mcc']:>7} {res.get('pr_auc') or '-':>7}")

    # D: sin filas de postura (se rehace la etiqueta sin ellas)
    no_posture = frame[frame["posture_share"] < 0.5].reset_index(drop=True)
    tr2, te2 = temporal_split(no_posture)
    res_d = evaluate(tr2, te2, [f for f in FEATURES if f not in HOST_IDENTITY + RULE_ENGINE])
    ablation["D · C + sin ventanas de postura"] = {**res_d, "windows": len(no_posture)}
    print(f"  {'D · C + sin ventanas de postura':<38} "
          f"{res_d.get('accuracy','-'):>7} {res_d.get('gain_over_baseline','-'):>+7} "
          f"{res_d.get('mcc','-'):>7} {res_d.get('pr_auc') or '-':>7}")
    if not res_d.get("viable"):
        print(f"      -> {res_d.get('note', 'no viable: una sola clase tras quitar la postura')}")
    report["ablation"] = ablation

    # ---------- 9.2 leave-one-agent-out ----------
    print()
    print("=" * 74)
    print("9.2  GENERALIZACION A MAQUINA NO VISTA  (leave-one-agent-out)")
    print("=" * 74)
    feats = [f for f in FEATURES if f not in HOST_IDENTITY]
    loao = {}
    print(f"  {'agente excluido':<12} {'n_test':>8} {'%pos':>7} {'base':>7} {'exact.':>7} "
          f"{'ganan.':>7} {'MCC':>7} {'1clase':>7}")
    print(f"  {'-'*12} {'-'*8} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*7}")
    for agent in sorted(frame["agent_id"].unique()):
        tr = frame[frame["agent_id"] != agent]
        te = frame[frame["agent_id"] == agent]
        res = evaluate(tr, te, feats)
        loao[str(agent)] = res
        if res["viable"]:
            print(f"  {agent:<12} {res['n_test']:>8,} {res['test_positive_rate']*100:>6.1f}% "
                  f"{res['majority_baseline']:>7} {res['accuracy']:>7} "
                  f"{res['gain_over_baseline']:>+7} {res['mcc']:>7} "
                  f"{'SI' if res['single_class_prediction'] else 'no':>7}")
        else:
            print(f"  {agent:<12} {res['n_test']:>8,}       -       -       -       -       -       -")
    report["leave_one_agent_out"] = loao

    path = OUT / "shortcut_ablation.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print()
    print(f"Resultados en {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
