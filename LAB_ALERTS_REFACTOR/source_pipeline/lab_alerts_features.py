#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

import numpy as np
import pandas as pd


EXTRACTOR_VERSION = "lab_alerts_feature_extractor_v2"
DEFAULT_UNKNOWN_CODE = 0

FEATURE_COLUMNS = [
    "alert_count",
    "unique_rule_count",
    "unique_src_ip_count",
    "unique_src_user_count",
    "unique_dst_user_count",
    "unique_decoder_count",
    "unique_program_count",
    "unique_location_count",
    "rule_level_mean",
    "rule_level_max",
    "rule_level_sum",
    "rule_level_std",
    "rule_firedtimes_mean",
    "rule_firedtimes_max",
    "rule_firedtimes_sum",
    "level_ge_7_count",
    "level_ge_10_count",
    "mitre_tagged_count",
    "mitre_tagged_ratio",
    "credential_tactic_count",
    "lateral_tactic_count",
    "recon_tactic_count",
    "auth_group_count",
    "sshd_group_count",
    "pam_group_count",
    "invalid_login_group_count",
    "systemd_group_count",
    "syscheck_group_count",
    "web_group_count",
    "docker_group_count",
    "windows_group_count",
    "dpkg_group_count",
    "src_ip_present_count",
    "src_port_present_count",
    "has_new_src_ip",
    "has_new_rule_id",
    "event_hour",
    "event_minute",
    "day_of_week",
    "agent_id_code",
    "decoder_code",
    "program_code",
    "location_code",
]

LABEL_PROXY_EXCLUSIONS = {
    "rule_level_mean": "Wazuh severity is part of the weak-label policy.",
    "rule_level_max": "Wazuh severity is part of the weak-label policy.",
    "rule_level_sum": "Wazuh severity is part of the weak-label policy.",
    "rule_level_std": "Wazuh severity is part of the weak-label policy.",
    "rule_firedtimes_mean": "Rule firing statistics can proxy the generating detection rule.",
    "rule_firedtimes_max": "Rule firing statistics can proxy the generating detection rule.",
    "rule_firedtimes_sum": "Rule firing statistics can proxy the generating detection rule.",
    "level_ge_7_count": "Severity threshold features are close to the weak-label policy.",
    "level_ge_10_count": "Severity threshold features are close to the weak-label policy.",
    "mitre_tagged_count": "MITRE tags are used by the weak-label policy.",
    "mitre_tagged_ratio": "MITRE tags are used by the weak-label policy.",
    "credential_tactic_count": "MITRE tactic counts are used by the weak-label policy.",
    "lateral_tactic_count": "MITRE tactic counts are used by the weak-label policy.",
    "recon_tactic_count": "MITRE tactic counts are used by the weak-label policy.",
    "auth_group_count": "Rule group counts are used by the weak-label policy.",
    "sshd_group_count": "Rule group counts are used by the weak-label policy.",
    "pam_group_count": "Rule group counts are used by the weak-label policy.",
    "invalid_login_group_count": "Rule group counts are used by the weak-label policy.",
    "systemd_group_count": "Rule group counts are used by the weak-label policy.",
    "syscheck_group_count": "Rule group counts are used by the weak-label policy.",
    "web_group_count": "Rule group counts are used by the weak-label policy.",
    "docker_group_count": "Rule group counts are used by the weak-label policy.",
    "windows_group_count": "Rule group counts are used by the weak-label policy.",
    "dpkg_group_count": "Rule group counts are used by the weak-label policy.",
    "decoder_code": "Top decoder category can act as a label proxy.",
    "program_code": "Top program category can act as a label proxy.",
    "location_code": "Top location category can act as a label proxy.",
}

FEATURE_PROFILES = ("full", "operational_no_label_proxy")


def normalize_text(value: object, default: str = "Unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text or text.lower() in {"nan", "none", "null"}:
        return default
    return text


def as_list(value: object) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [normalize_text(item, default="") for item in value if normalize_text(item, default="")]
    text = normalize_text(value, default="")
    return [text] if text else []


def safe_int(value: object, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


def top_value(series: pd.Series, default: str = "Unknown") -> str:
    clean = series.map(lambda value: normalize_text(value, default=default))
    clean = clean[clean != default]
    if clean.empty:
        return default
    return str(clean.value_counts().sort_values(ascending=False).index[0])


def unique_nonempty_count(series: pd.Series) -> float:
    values = series.astype(str)
    return float(values[values != ""].nunique())


def feature_columns_for_profile(profile: str) -> List[str]:
    if profile == "full":
        return list(FEATURE_COLUMNS)
    if profile == "operational_no_label_proxy":
        excluded = set(LABEL_PROXY_EXCLUSIONS)
        return [column for column in FEATURE_COLUMNS if column not in excluded]
    raise ValueError(f"Unsupported feature profile: {profile}")


def feature_profile_payload(profile: str) -> Dict[str, Any]:
    selected = feature_columns_for_profile(profile)
    excluded = {column: reason for column, reason in LABEL_PROXY_EXCLUSIONS.items() if column in FEATURE_COLUMNS and column not in selected}
    return {
        "feature_profile": profile,
        "description": "All engineered LAB-ALERTS features." if profile == "full" else "Operational LAB-ALERTS profile excluding direct weak-label proxy features.",
        "feature_count": len(selected),
        "feature_columns": selected,
        "excluded_feature_count": len(excluded),
        "excluded_features": excluded,
    }


def canonical_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def schema_hash(payload: Dict[str, Any]) -> str:
    clone = dict(payload)
    clone.pop("schema_hash", None)
    return hashlib.sha256(canonical_json(clone).encode("utf-8")).hexdigest()


def schema_contract_payload(
    *,
    dataset: str,
    split_mode: str,
    window_size: str,
    group_key: str,
    feature_profile: str,
    feature_columns: Sequence[str],
    category_maps: Dict[str, Dict[str, int]],
    target_policy: str,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "contract_version": "lab_alerts_schema_contract_v1",
        "extractor_version": EXTRACTOR_VERSION,
        "dataset": dataset,
        "split_mode": split_mode,
        "window_size": window_size,
        "group_key": group_key,
        "feature_profile": feature_profile,
        "feature_count": len(feature_columns),
        "feature_columns": list(feature_columns),
        "dtype": "float32",
        "unknown_category_code": DEFAULT_UNKNOWN_CODE,
        "category_maps": category_maps,
        "target_policy": target_policy,
        "inference_requirements": [
            "Aggregate raw Wazuh alerts by window_size and group_key before prediction.",
            "Use feature_columns in exact order.",
            "Use category_maps from this contract; unknown categories map to 0.",
            "Reject inference if feature_count, feature order, or dtype validation fails.",
        ],
    }
    payload["schema_hash"] = schema_hash(payload)
    return payload


def validate_feature_frame(frame: pd.DataFrame, feature_columns: Sequence[str], expected_hash: str | None = None, contract: Dict[str, Any] | None = None) -> List[str]:
    warnings: List[str] = []
    missing = [column for column in feature_columns if column not in frame.columns]
    if missing:
        raise ValueError(f"Missing LAB-ALERTS features: {missing}")
    actual = list(frame.loc[:, list(feature_columns)].columns)
    if actual != list(feature_columns):
        raise ValueError("LAB-ALERTS feature order mismatch")
    if frame.loc[:, list(feature_columns)].isna().any().any():
        warnings.append("feature_frame_contains_nan")
    if expected_hash and contract and schema_hash(contract) != expected_hash:
        raise ValueError("LAB-ALERTS schema hash mismatch")
    return warnings


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass
class LabAlertsFeatureExtractor:
    feature_columns: Sequence[str]
    category_maps: Dict[str, Dict[str, int]]
    window_size: str = "1min"
    group_key: str = "agent_id"
    seen_src_ips: set[str] = field(default_factory=set)
    seen_rule_ids: set[str] = field(default_factory=set)
    warnings: List[str] = field(default_factory=list)

    @classmethod
    def from_contract(cls, contract: Dict[str, Any]) -> "LabAlertsFeatureExtractor":
        return cls(
            feature_columns=contract["feature_columns"],
            category_maps=contract.get("category_maps", {}),
            window_size=contract.get("window_size", "1min"),
            group_key=contract.get("group_key", "agent_id"),
        )

    def _category_code(self, map_name: str, value: str) -> float:
        mapping = self.category_maps.get(map_name, {})
        normalized = normalize_text(value)
        if normalized not in mapping:
            self.warnings.append(f"unknown_{map_name}:{normalized}")
        return float(mapping.get(normalized, DEFAULT_UNKNOWN_CODE))

    def _event_row(self, alert: Dict[str, Any], line_number: int) -> Dict[str, Any]:
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        decoder = alert.get("decoder") or {}
        predecoder = alert.get("predecoder") or {}
        data = alert.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        return {
            "line_number": line_number,
            "timestamp": normalize_text(alert.get("timestamp") or alert.get("@timestamp"), default=""),
            "rule_id": normalize_text(rule.get("id")),
            "rule_level": safe_int(rule.get("level")),
            "rule_firedtimes": safe_int(rule.get("firedtimes"), default=1),
            "groups": as_list(rule.get("groups")),
            "mitre_tactics": as_list((rule.get("mitre") or {}).get("tactic")),
            "agent_id": normalize_text(agent.get("id")),
            "agent_name": normalize_text(agent.get("name")),
            "agent_ip": normalize_text(agent.get("ip"), default=""),
            "src_ip": normalize_text(data.get("srcip") or data.get("src_ip") or alert.get("srcip"), default=""),
            "src_port": normalize_text(data.get("srcport") or data.get("src_port"), default=""),
            "src_user": normalize_text(data.get("srcuser") or data.get("username"), default=""),
            "dst_user": normalize_text(data.get("dstuser"), default=""),
            "decoder_name": normalize_text(decoder.get("name")),
            "program_name": normalize_text(predecoder.get("program_name"), default=""),
            "location": normalize_text(alert.get("location")),
            "has_src_ip": bool(normalize_text(data.get("srcip") or data.get("src_ip") or alert.get("srcip"), default="")),
            "has_src_port": bool(normalize_text(data.get("srcport") or data.get("src_port"), default="")),
        }

    def transform_alerts(self, alerts: Iterable[Dict[str, Any]]) -> pd.DataFrame:
        rows = [self._event_row(alert, index) for index, alert in enumerate(alerts, start=1)]
        if not rows:
            return pd.DataFrame(columns=list(self.feature_columns))
        events = pd.DataFrame(rows)
        events["event_ts"] = pd.to_datetime(events["timestamp"], errors="coerce", utc=True)
        events = events[events["event_ts"].notna()].copy()
        if events.empty:
            return pd.DataFrame(columns=list(self.feature_columns))
        events.sort_values(["event_ts", "line_number"], inplace=True)
        return self.aggregate_events(events)

    def aggregate_events(self, events: pd.DataFrame) -> pd.DataFrame:
        work = events.copy()
        work["window_start"] = work["event_ts"].dt.floor(self.window_size)
        output_rows: List[Dict[str, Any]] = []
        grouped = work.groupby(["window_start", self.group_key], sort=True, dropna=False)
        for (window_start, agent_id), group in grouped:
            src_ips = {value for value in group["src_ip"].astype(str) if value}
            rule_ids = {value for value in group["rule_id"].astype(str) if value}
            has_new_src_ip = bool(src_ips - self.seen_src_ips)
            has_new_rule_id = bool(rule_ids - self.seen_rule_ids)
            self.seen_src_ips.update(src_ips)
            self.seen_rule_ids.update(rule_ids)
            row = {
                "window_start": window_start,
                "agent_id": normalize_text(agent_id),
                "alert_count": float(len(group)),
                "unique_rule_count": float(group["rule_id"].nunique()),
                "unique_src_ip_count": unique_nonempty_count(group["src_ip"]),
                "unique_src_user_count": unique_nonempty_count(group["src_user"]),
                "unique_dst_user_count": unique_nonempty_count(group["dst_user"]),
                "unique_decoder_count": float(group["decoder_name"].nunique()),
                "unique_program_count": unique_nonempty_count(group["program_name"]),
                "unique_location_count": float(group["location"].nunique()),
                "src_ip_present_count": float(group["has_src_ip"].sum()),
                "src_port_present_count": float(group["has_src_port"].sum()),
                "has_new_src_ip": float(has_new_src_ip),
                "has_new_rule_id": float(has_new_rule_id),
                "event_hour": float(window_start.hour),
                "event_minute": float(window_start.minute),
                "day_of_week": float(window_start.dayofweek),
                "agent_id_code": self._category_code("agent_id", normalize_text(agent_id)),
                "decoder_code": self._category_code("decoder", top_value(group["decoder_name"])),
                "program_code": self._category_code("program", top_value(group["program_name"], default="")),
                "location_code": self._category_code("location", top_value(group["location"])),
            }
            output_rows.append(row)
        frame = pd.DataFrame(output_rows)
        for column in FEATURE_COLUMNS:
            if column not in frame.columns:
                frame[column] = 0.0
            frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(0.0).astype(np.float32)
        validate_feature_frame(frame, self.feature_columns)
        return frame.loc[:, list(self.feature_columns)].copy()
