# -*- coding: utf-8 -*-
"""9.3 Filtrado de vulnerabilidades por explotacion real.

Cruza los hallazgos de Trivy del export de 30 dias con dos fuentes externas:

  CISA KEV   catalogo de vulnerabilidades EXPLOTADAS activamente en la vida real
  EPSS       probabilidad estimada de que un CVE sea explotado en 30 dias

Responde a la pregunta que motiva la seccion 5 del dossier: cuantos de los
miles de CVE que reporta Trivy merecen realmente atencion. Y de paso contrasta
la tesis "severidad declarada != riesgo real" cruzando la severidad que asigna
Trivy contra la pertenencia al catalogo KEV.

    .venv/Scripts/python.exe experiments/kev_epss_filter.py
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "argos-alerts_30d.jsonl"
OUT = ROOT / "experiments" / "results"
KEV_FILE = OUT / "kev.json"
EPSS_FILE = OUT / "epss.csv.gz"

CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}")
SEV_RX = re.compile(r"\[(LOW|MEDIUM|HIGH|CRITICAL)\]")
PKG_RX = re.compile(r"package '([^']+)'")

# Umbral EPSS habitual para "merece accion": 10 % de probabilidad de
# explotacion en 30 dias. Se reportan varios para no depender de uno solo.
EPSS_LEVELS = [0.01, 0.05, 0.1, 0.5]


def scan_trivy() -> tuple[Counter, dict, Counter]:
    """Devuelve alertas por CVE, severidad declarada por CVE y paquetes."""
    if not DATASET.exists():
        sys.exit(f"Falta {DATASET}")

    alerts_per_cve: Counter = Counter()
    severity_of: dict[str, str] = {}
    packages: Counter = Counter()

    with open(DATASET, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if "trivy" not in [g.lower() for g in row["rule_groups"]]:
                continue
            description = row["rule_description"] or ""
            match = CVE_RX.search(description)
            if not match:
                continue
            cve = match.group(0)
            alerts_per_cve[cve] += 1
            sev = SEV_RX.search(description)
            if sev:
                severity_of[cve] = sev.group(1)
            pkg = PKG_RX.search(description)
            if pkg:
                packages[pkg.group(1)] += 1

    return alerts_per_cve, severity_of, packages


def load_kev() -> set[str]:
    data = json.loads(KEV_FILE.read_text(encoding="utf-8"))
    return {v["cveID"] for v in data.get("vulnerabilities", [])}


def load_epss() -> dict[str, float]:
    scores: dict[str, float] = {}
    with gzip.open(EPSS_FILE, "rt", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("#"):
                continue
            reader = csv.DictReader(io.StringIO(line + handle.read()))
            for row in reader:
                try:
                    scores[row["cve"]] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
            break
    return scores


def pct(part: int, whole: int) -> str:
    return f"{part / whole * 100:.2f} %" if whole else "—"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    print("Escaneando hallazgos de Trivy...", flush=True)
    alerts_per_cve, severity_of, packages = scan_trivy()
    cves = set(alerts_per_cve)
    total_alerts = sum(alerts_per_cve.values())

    kev = load_kev()
    epss = load_epss()
    print(f"  {total_alerts:,} alertas de Trivy | {len(cves):,} CVE distintos")
    print(f"  KEV: {len(kev):,} entradas | EPSS: {len(epss):,} CVE puntuados")
    print()

    in_kev = {c for c in cves if c in kev}
    kev_alerts = sum(alerts_per_cve[c] for c in in_kev)
    scored = {c: epss[c] for c in cves if c in epss}
    unscored = len(cves) - len(scored)

    print("=" * 74)
    print("9.3  ¿CUANTOS CVE MERECEN ATENCION DE VERDAD?")
    print("=" * 74)
    print(f"  {'criterio':<44} {'CVE':>8} {'% CVE':>9} {'alertas':>10}")
    print(f"  {'-'*44} {'-'*8} {'-'*9} {'-'*10}")
    print(f"  {'todos los que reporta Trivy':<44} {len(cves):>8,} {'100.00 %':>9} {total_alerts:>10,}")

    rows = {"total": {"cves": len(cves), "alerts": total_alerts}}

    crit_high = {c for c, s in severity_of.items() if s in ("CRITICAL", "HIGH")}
    ch_alerts = sum(alerts_per_cve[c] for c in crit_high)
    print(f"  {'severidad CRITICAL o HIGH segun Trivy':<44} {len(crit_high):>8,} "
          f"{pct(len(crit_high), len(cves)):>9} {ch_alerts:>10,}")
    rows["critical_high"] = {"cves": len(crit_high), "alerts": ch_alerts}

    for level in EPSS_LEVELS:
        sel = {c for c, v in scored.items() if v >= level}
        a = sum(alerts_per_cve[c] for c in sel)
        print(f"  {f'EPSS >= {level:g} (prob. explotacion 30 d)':<44} {len(sel):>8,} "
              f"{pct(len(sel), len(cves)):>9} {a:>10,}")
        rows[f"epss_{level}"] = {"cves": len(sel), "alerts": a}

    print(f"  {'en el catalogo KEV (explotado de verdad)':<44} {len(in_kev):>8,} "
          f"{pct(len(in_kev), len(cves)):>9} {kev_alerts:>10,}")
    rows["kev"] = {"cves": len(in_kev), "alerts": kev_alerts}

    print()
    print(f"  CVE sin puntuacion EPSS: {unscored:,} ({pct(unscored, len(cves))})")

    # ---- la tesis: severidad declarada frente a explotacion real ----
    print()
    print("=" * 74)
    print("SEVERIDAD DECLARADA FRENTE A EXPLOTACION REAL")
    print("=" * 74)
    print(f"  {'severidad Trivy':<16} {'CVE':>8} {'en KEV':>8} {'tasa':>9} {'EPSS medio':>12}")
    print(f"  {'-'*16} {'-'*8} {'-'*8} {'-'*9} {'-'*12}")
    by_sev = defaultdict(list)
    for cve, sev in severity_of.items():
        by_sev[sev].append(cve)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = by_sev.get(sev, [])
        if not group:
            continue
        hits = sum(1 for c in group if c in kev)
        vals = [scored[c] for c in group if c in scored]
        mean = sum(vals) / len(vals) if vals else 0.0
        print(f"  {sev:<16} {len(group):>8,} {hits:>8} {pct(hits, len(group)):>9} {mean:>12.5f}")
        rows[f"sev_{sev}"] = {"cves": len(group), "in_kev": hits, "epss_mean": round(mean, 5)}

    # ---- lo que un analista revisaria de verdad ----
    print()
    print("=" * 74)
    print("COLA DE REVISION REAL  (en KEV, o EPSS >= 0,1)")
    print("=" * 74)
    actionable = sorted(
        in_kev | {c for c, v in scored.items() if v >= 0.1},
        key=lambda c: (-(c in kev), -scored.get(c, 0.0)),
    )
    act_alerts = sum(alerts_per_cve[c] for c in actionable)
    print(f"  {len(actionable)} CVE de {len(cves):,}  ({pct(len(actionable), len(cves))})")
    print(f"  cubren {act_alerts:,} alertas de {total_alerts:,}  ({pct(act_alerts, total_alerts)})")
    print(f"  reduccion de la cola de revision: x{len(cves)/max(len(actionable),1):.0f}")
    print()
    print(f"  {'CVE':<18} {'KEV':>5} {'EPSS':>8} {'alertas':>9}  severidad Trivy")
    for cve in actionable[:15]:
        print(f"  {cve:<18} {'SI' if cve in kev else 'no':>5} {scored.get(cve, 0.0):>8.5f} "
              f"{alerts_per_cve[cve]:>9,}  {severity_of.get(cve, '?')}")

    report = {
        "generated_from": DATASET.name,
        "trivy_alerts": total_alerts,
        "distinct_cves": len(cves),
        "kev_catalog_size": len(kev),
        "epss_scored": len(scored),
        "epss_unscored": unscored,
        "filters": rows,
        "actionable": {
            "criterion": "en KEV o EPSS >= 0.1",
            "cves": len(actionable),
            "alerts": act_alerts,
            "reduction_factor": round(len(cves) / max(len(actionable), 1), 1),
            "list": [
                {
                    "cve": c,
                    "in_kev": c in kev,
                    "epss": round(scored.get(c, 0.0), 5),
                    "alerts": alerts_per_cve[c],
                    "trivy_severity": severity_of.get(c),
                }
                for c in actionable
            ],
        },
    }
    path = OUT / "kev_epss_filter.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print()
    print(f"Resultados en {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
