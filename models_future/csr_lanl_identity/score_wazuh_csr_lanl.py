#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
PACKAGE_DIR = ROOT / "ARGOS-CSR-LANL"
HGB_DIR = PACKAGE_DIR / "models" / "hgb_candidate"
ISO_DIR = PACKAGE_DIR / "models" / "isoforest_aux"
CONTRACT_PATH = PACKAGE_DIR / "schemas" / "model_contract.json"

SUSPICIOUS_THRESHOLD = 0.95
HIGH_RISK_THRESHOLD = 0.9892924292237013

NOVELTY_COLUMNS = [
    "has_new_src_user",
    "has_new_dst_computer",
    "has_new_process",
    "has_new_auth_dst_computer",
    "has_new_auth_src_dst_pair",
    "has_new_flow_dst_computer",
    "has_new_flow_dst_port",
    "has_new_flow_src_dst_pair",
    "has_new_flow_src_dst_port_pair",
    "has_new_dns_dst_computer",
    "has_new_dns_src_dst_pair",
    "identity_novelty_signal_count",
]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_feature_columns(path: Path) -> List[str]:
    payload = read_json(path)
    if isinstance(payload, list):
        return [str(item) for item in payload]
    if isinstance(payload, dict) and isinstance(payload.get("feature_columns"), list):
        return [str(item) for item in payload["feature_columns"]]
    raise ValueError(f"Invalid feature column file: {path}")


def normalize_text(value: Any, default: str = "Unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "nan"}:
        return default
    return text


def as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [normalize_text(item, default="") for item in value if normalize_text(item, default="")]
    text = normalize_text(value, default="")
    return [text] if text else []


def pick(source: Dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = source
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                current = None
                break
            current = current[part]
        if current not in (None, ""):
            return current
    return None


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if math.isfinite(parsed) else default


def bucket(value: str, bucket_count: int = 16) -> int:
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()
    return int(digest[:8], 16) % bucket_count


def hit_source(hit: Dict[str, Any]) -> Dict[str, Any]:
    source = hit.get("_source") or {}
    return source if isinstance(source, dict) else {}


def event_row(hit: Dict[str, Any], index: int) -> Dict[str, Any]:
    source = hit_source(hit)
    rule = source.get("rule") or {}
    agent = source.get("agent") or {}
    decoder = source.get("decoder") or {}
    data = source.get("data") or {}
    if not isinstance(data, dict):
        data = {}

    timestamp = normalize_text(source.get("@timestamp") or source.get("timestamp"), default="")
    groups = [item.lower() for item in as_list(rule.get("groups"))]
    description = normalize_text(rule.get("description") or source.get("title") or source.get("full_log"), default="").lower()
    decoder_name = normalize_text(decoder.get("name"), default="").lower()
    src_user = normalize_text(data.get("srcuser") or data.get("username") or source.get("user"), default="")
    dst_user = normalize_text(data.get("dstuser"), default="")
    src_ip = normalize_text(data.get("srcip") or data.get("src_ip") or source.get("srcip"), default="")
    dst_computer = normalize_text(agent.get("name") or agent.get("id"), default="Unknown")
    dst_port = normalize_text(data.get("dstport") or data.get("destination_port"), default="")

    auth_like = any(term in groups for term in ["authentication_failed", "authentication_failures", "sshd", "pam"]) or any(
        term in description for term in ["auth", "login", "password", "credential", "sshd", "mfa"]
    )
    fail_like = any(term in description for term in ["fail", "invalid", "denied", "non-existent", "wrong"])
    success_like = any(term in description for term in ["success", "accepted", "completed"])
    flow_like = bool(src_ip or dst_port)
    proc_like = decoder_name in {"syscheck_registry_value_modified", "syscheck_registry_value_deleted"} or "process" in description
    dns_like = "dns" in decoder_name or "dns" in description

    return {
        "hit_index": index,
        "hit_id": hit.get("_id"),
        "timestamp": timestamp,
        "event_ts": pd.to_datetime(timestamp, errors="coerce", utc=True),
        "entity": normalize_text(agent.get("id") or agent.get("name")),
        "src_user": src_user,
        "dst_user": dst_user,
        "src_ip": src_ip,
        "dst_computer": dst_computer,
        "dst_port": dst_port,
        "decoder": decoder_name,
        "location": normalize_text(source.get("location"), default=""),
        "auth_like": bool(auth_like),
        "fail_like": bool(fail_like),
        "success_like": bool(success_like),
        "flow_like": bool(flow_like),
        "proc_like": bool(proc_like),
        "dns_like": bool(dns_like),
    }


def count_unique_nonempty(values: Iterable[Any]) -> float:
    return float(len({str(value) for value in values if str(value)}))


def empty_feature_row(feature_columns: List[str]) -> Dict[str, float]:
    return {column: 0.0 for column in feature_columns}


def set_bucket_counts(row: Dict[str, float], prefix: str, values: Iterable[str]) -> None:
    for value in values:
        if not value:
            continue
        column = f"{prefix}_bucket_{bucket(value):02d}_count"
        if column in row:
            row[column] += 1.0


def build_windows(hits: List[Dict[str, Any]], feature_columns: List[str]) -> Tuple[pd.DataFrame, Dict[int, Tuple[str, str]]]:
    rows = [event_row(hit, index) for index, hit in enumerate(hits)]
    events = pd.DataFrame(rows)
    hit_keys: Dict[int, Tuple[str, str]] = {}
    if events.empty:
        return pd.DataFrame(columns=["entity", "window_start", "window_end"] + feature_columns), hit_keys

    events = events[events["event_ts"].notna()].copy()
    if events.empty:
        return pd.DataFrame(columns=["entity", "window_start", "window_end"] + feature_columns), hit_keys

    events["window_start"] = events["event_ts"].dt.floor("1h")
    events["window_end"] = events["window_start"] + pd.Timedelta(hours=1)
    window_rows: List[Dict[str, Any]] = []
    seen_by_entity: Dict[str, Dict[str, set[str]]] = {}

    grouped = events.groupby(["window_start", "entity"], sort=True, dropna=False)
    for (window_start, entity), group in grouped:
        entity_text = normalize_text(entity)
        seen = seen_by_entity.setdefault(entity_text, {"src_user": set(), "dst_computer": set(), "process": set(), "dst_port": set(), "src_dst": set()})
        auth = group[group["auth_like"]]
        flow = group[group["flow_like"]]
        proc = group[group["proc_like"]]
        dns = group[group["dns_like"]]
        src_users = [value for value in group["src_user"].astype(str) if value]
        dst_users = [value for value in group["dst_user"].astype(str) if value]
        dst_computers = [value for value in group["dst_computer"].astype(str) if value]
        src_ips = [value for value in group["src_ip"].astype(str) if value]
        dst_ports = [value for value in group["dst_port"].astype(str) if value]
        src_dst_pairs = [f"{src}->{dst}" for src, dst in zip(group["src_ip"].astype(str), group["dst_computer"].astype(str)) if src and dst]

        new_src_users = set(src_users) - seen["src_user"]
        new_dst_computers = set(dst_computers) - seen["dst_computer"]
        new_dst_ports = set(dst_ports) - seen["dst_port"]
        new_src_dst = set(src_dst_pairs) - seen["src_dst"]
        seen["src_user"].update(src_users)
        seen["dst_computer"].update(dst_computers)
        seen["dst_port"].update(dst_ports)
        seen["src_dst"].update(src_dst_pairs)

        row = empty_feature_row(feature_columns)
        total = float(len(group))
        auth_count = float(len(auth))
        fail_count = float(group["fail_like"].sum())
        success_count = float(group["success_like"].sum())
        flow_count = float(len(flow))
        proc_count = float(len(proc))
        dns_count = float(len(dns))
        hour = int(pd.Timestamp(window_start).hour)
        day_index = int(pd.Timestamp(window_start).dayofweek)

        values = {
            "auth_event_count": auth_count,
            "auth_success_count": success_count,
            "auth_fail_count": fail_count,
            "auth_failure_ratio": fail_count / max(auth_count, 1.0),
            "auth_logon_count": auth_count,
            "auth_network_logon_count": auth_count,
            "auth_type_unique_count": count_unique_nonempty(group["decoder"]),
            "logon_type_unique_count": count_unique_nonempty(group["decoder"]),
            "unique_src_user_count": count_unique_nonempty(src_users),
            "unique_dst_user_count": count_unique_nonempty(dst_users),
            "auth_unique_dst_computer_count": count_unique_nonempty(auth["dst_computer"]) if not auth.empty else 0.0,
            "flow_event_count": flow_count,
            "flow_unique_dst_computer_count": count_unique_nonempty(flow["dst_computer"]) if not flow.empty else 0.0,
            "flow_unique_dst_port_count": count_unique_nonempty(dst_ports),
            "flow_tcp_count": flow_count,
            "flow_privileged_dst_port_count": float(sum(safe_float(port) < 1024 for port in dst_ports)),
            "dns_event_count": dns_count,
            "dns_unique_dst_computer_count": count_unique_nonempty(dns["dst_computer"]) if not dns.empty else 0.0,
            "proc_event_count": proc_count,
            "proc_unique_user_count": count_unique_nonempty(proc["src_user"]) if not proc.empty else 0.0,
            "proc_unique_process_count": count_unique_nonempty(proc["decoder"]) if not proc.empty else 0.0,
            "active_source_count": count_unique_nonempty(src_ips),
            "total_event_count": total,
            "auth_to_flow_ratio": auth_count / max(flow_count, 1.0),
            "fail_to_flow_ratio": fail_count / max(flow_count, 1.0),
            "proc_to_auth_ratio": proc_count / max(auth_count, 1.0),
            "has_new_src_user": float(bool(new_src_users)),
            "has_new_dst_computer": float(bool(new_dst_computers)),
            "has_new_auth_dst_computer": float(bool(new_dst_computers and auth_count)),
            "has_new_auth_src_dst_pair": float(bool(new_src_dst and auth_count)),
            "has_new_flow_dst_computer": float(bool(new_dst_computers and flow_count)),
            "has_new_flow_dst_port": float(bool(new_dst_ports and flow_count)),
            "has_new_flow_src_dst_pair": float(bool(new_src_dst and flow_count)),
            "has_new_flow_src_dst_port_pair": float(bool((new_src_dst or new_dst_ports) and flow_count)),
            "has_new_dns_dst_computer": float(bool(new_dst_computers and dns_count)),
            "has_new_dns_src_dst_pair": float(bool(new_src_dst and dns_count)),
            "identity_novelty_signal_count": float(len(new_src_users) + len(new_dst_computers) + len(new_dst_ports) + len(new_src_dst)),
            "day_index": float(day_index),
            "hour_index": float(hour),
            "minute_of_day": float(hour * 60),
        }
        for column, value in values.items():
            if column in row:
                row[column] = value

        set_bucket_counts(row, "auth_dst_computer_id", dst_computers)
        set_bucket_counts(row, "auth_src_dst_pair_id", src_dst_pairs)
        set_bucket_counts(row, "flow_dst_computer_id", dst_computers)
        set_bucket_counts(row, "flow_dst_port_id", dst_ports)
        set_bucket_counts(row, "flow_src_dst_pair_id", src_dst_pairs)
        set_bucket_counts(row, "dns_dst_computer_id", dst_computers)
        set_bucket_counts(row, "dns_src_dst_pair_id", src_dst_pairs)

        row.update({"entity": entity_text, "window_start": window_start, "window_end": window_start + pd.Timedelta(hours=1)})
        window_rows.append(row)

        key = (str(window_start), entity_text)
        for hit_index in group["hit_index"].astype(int).tolist():
            hit_keys[hit_index] = key

    return pd.DataFrame(window_rows), hit_keys


def feature_matrix(frame: pd.DataFrame, feature_columns: List[str]) -> np.ndarray:
    missing = [column for column in feature_columns if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing CSR-LANL feature columns: {missing[:20]}")
    return frame.loc[:, feature_columns].apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=np.float32, copy=True)


def hgb_scores(model: Any, X: np.ndarray) -> np.ndarray:
    proba = model.predict_proba(X)
    if proba.shape[1] == 1:
        return np.zeros(len(X), dtype=np.float64)
    return proba[:, 1].astype(np.float64)


def anomaly_scores(model: Any, X: np.ndarray) -> np.ndarray:
    return (-model.score_samples(X)).astype(np.float64)


def context_novelty_score(frame: pd.DataFrame) -> np.ndarray:
    columns = [column for column in NOVELTY_COLUMNS if column in frame.columns]
    if not columns:
        return np.zeros(len(frame), dtype=np.float64)
    values = frame.loc[:, columns].apply(pd.to_numeric, errors="coerce").fillna(0.0).to_numpy(dtype=np.float64)
    return np.clip(values.sum(axis=1) / max(len(columns), 1), 0.0, 1.0)


def classify(score: float) -> str:
    if score >= HIGH_RISK_THRESHOLD:
        return "high_risk_entity"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious_entity"
    return "low_signal"


def json_ready_timestamp(value: Any) -> str | None:
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if value is None:
        return None
    return str(value)


def score_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hgb_features = load_feature_columns(HGB_DIR / "feature_columns.json")
    iso_features = load_feature_columns(ISO_DIR / "feature_columns.json")
    frame, hit_keys = build_windows(hits, sorted(set(hgb_features + iso_features)))
    if frame.empty:
        return [{"id": hit.get("_id"), "csr_lanl": None} for hit in hits]

    hgb_model = joblib.load(HGB_DIR / "model.joblib")
    iso_model = joblib.load(ISO_DIR / "model.joblib")
    supervised = hgb_scores(hgb_model, feature_matrix(frame, hgb_features))
    anomaly = anomaly_scores(iso_model, feature_matrix(frame, iso_features))
    context = context_novelty_score(frame)

    by_window: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for index, row in frame.reset_index(drop=True).iterrows():
        score = float(supervised[index])
        key = (str(row["window_start"]), str(row["entity"]))
        by_window[key] = {
            "supervised_score": score,
            "entity_anomaly_score": float(anomaly[index]),
            "context_novelty_score": float(context[index]),
            "classification": classify(score),
            "entity": str(row["entity"]),
            "window_start": json_ready_timestamp(row["window_start"]),
            "window_end": json_ready_timestamp(row["window_end"]),
            "model": "csr_lanl_identity_hgb",
            "auxiliary_model": "csr_lanl_identity_isoforest",
            "source": "wazuh_sparse_adapter",
            "warning": "CSR-LANL model was trained on auth/flow/dns/proc windows; ARGOS Wazuh adapter fills unavailable feature families with zero.",
        }

    results: List[Dict[str, Any]] = []
    for index, hit in enumerate(hits):
        key = hit_keys.get(index)
        results.append({"id": hit.get("_id"), "csr_lanl": by_window.get(key) if key else None})
    return results


def main() -> None:
    payload = json.load(sys.stdin)
    hits = payload.get("hits", [])
    if not isinstance(hits, list):
        hits = []
    json.dump({"results": score_hits(hits)}, sys.stdout)


if __name__ == "__main__":
    main()
