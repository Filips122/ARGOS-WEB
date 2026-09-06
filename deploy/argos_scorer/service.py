# -*- coding: utf-8 -*-
"""Sidecar HTTP del ARGOS Scorer.

Proceso de larga vida, duenyo unico de los tres puntuadores y de su estado.
Escucha solo en 127.0.0.1: no se expone fuera de la maquina.

Existe porque el patron de la web (un proceso Python por peticion) es
incompatible con un puntuador de flujo: medido, produce 128 veredictos sobre 26
IPs frente a 28 sobre 28, reemitiendo la misma orden de bloqueo en cada ciclo y
decidiendo siempre con evidencia truncada al lote.

Garantias que implementa este fichero:

  - Cursor y estado en UNA escritura atomica (temp + os.replace). No pueden
    divergir: un reinicio reanuda siempre en un punto consistente.
  - Deduplicacion por evento (alert_id) antes de tocar el perfil de la IP. Sin
    ella, un reenvio inflaria n_alerts y desplazaria el presupuesto K, que se
    elige justo con n = len(events).
  - La cola reciente de alert_id se persiste con el estado, de modo que tras un
    reinicio se pueden distinguir los documentos indexados tarde (legitimos, hay
    que aceptarlos) de los reenviados (duplicados, hay que descartarlos).
  - El estado se guarda tras cada tramo, ANTES de responder 200, para que el
    cursor del lado Node nunca vaya por delante de lo persistido.

La semilla del paquete (state/live_state.json) se copia al primer arranque y
nunca se escribe: example.py sigue siendo reproducible.

Uso:
    python service.py [--host 127.0.0.1] [--port 8973] [--state-dir ../../var/argos-scorer]
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import pandas as pd  # noqa: E402

from argos_scorer import ActivityScorer, EarlyBlockScorer, WindowBlockScorer  # noqa: E402
from argos_scorer.features import LiveState, early_ip_features  # noqa: E402

STATE_VERSION = 1
# Cubre ~14 h a nuestro caudal (~1 alerta/s), muy por encima de cualquier
# ventana de reenvio realista (retroceso de 60 s mas un tramo de 1.000).
LRU_MAX = 50_000
# Lo que sobrevive al reinicio. Solo tiene que cubrir el retroceso del cursor.
LRU_PERSIST = 5_000

# Campos de modelo. alert_id y sort viajan en el sobre, nunca en el vector.
MODEL_FIELDS = (
    "timestamp", "window_start", "agent_id",
    "src_ip", "src_port", "src_user", "dst_user",
    "geo_country", "geo_city", "geo_lat", "geo_lon",
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Puntuadores del panel (LAB-ALERTS y CSR-LANL)
#
# Viven en models_examples/ y models_future/, fuera de este paquete. La web los
# lanzaba con spawnSync en CADA peticion: 9,34 s + 6,60 s por refresco, con el
# panel sondeando cada 5 s. Importados una vez en este proceso bajan a 1,53 s y
# 2,36 s, porque no se paga arranque de interprete ni carga de modelos.
# ---------------------------------------------------------------------------

_PANEL_SCORERS: Dict[str, Any] = {}


def _panel_scorers(project_root: Path) -> Dict[str, Any]:
    """Importa los dos modulos una sola vez. Un fallo en uno no tumba al otro."""
    if _PANEL_SCORERS:
        return _PANEL_SCORERS

    for relative in ("models_examples", "models_future/csr_lanl_identity"):
        candidate = str(project_root / relative)
        if candidate not in sys.path:
            sys.path.append(candidate)

    for key, module_name in (("lab", "score_wazuh_alerts"), ("csr", "score_wazuh_csr_lanl")):
        try:
            _PANEL_SCORERS[key] = __import__(module_name)
        except Exception as error:  # noqa: BLE001
            print(f"[argos-scorer] no se pudo importar {module_name}: {error}", flush=True)
            _PANEL_SCORERS[key] = None

    return _PANEL_SCORERS


def _flatten_hit(hit: Dict[str, Any]) -> Dict[str, Any]:
    """Aplana un hit anidado de Wazuh a los 11 campos del scorer.

    Espeja la precedencia de campos de toDatasetRecord en lib/dataset-export.ts:
    la cuenta probada viaja en data.srcuser o data.dstuser, no en data.username,
    que en esta instalacion no existe.
    """
    source = hit.get("_source") or {}
    data = source.get("data") if isinstance(source.get("data"), dict) else {}
    agent = source.get("agent") or {}
    geo = source.get("GeoLocation") or {}
    net_source = source.get("source") or {}

    def first(*values: Any) -> str:
        for value in values:
            text = str(value).strip() if value is not None else ""
            if text and text.lower() not in {"nan", "none", "null"}:
                return text
        return ""

    timestamp = first(source.get("@timestamp"), source.get("timestamp"))
    window_start = ""
    if timestamp:
        try:
            text = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
            moment = datetime.fromisoformat(text)
            window_start = moment.replace(second=0, microsecond=0).isoformat()
        except ValueError:
            window_start = ""

    location = geo.get("location")
    lat = lon = None
    if isinstance(location, (list, tuple)) and len(location) >= 2:
        lon, lat = location[0], location[1]
    elif isinstance(location, dict):
        lat, lon = location.get("lat"), location.get("lon")

    return {
        "timestamp": timestamp,
        "window_start": window_start,
        "agent_id": first(agent.get("id")),
        "src_ip": first(data.get("srcip"), data.get("src_ip"), source.get("srcip"), net_source.get("ip")),
        "src_port": first(data.get("srcport"), data.get("src_port"), net_source.get("port")),
        "src_user": first(data.get("srcuser"), data.get("username"), (source.get("user") or {}).get("name")),
        "dst_user": first(data.get("dstuser")),
        "geo_country": first(geo.get("country_name"), geo.get("country_code2")),
        "geo_city": first(geo.get("city_name")),
        "geo_lat": lat,
        "geo_lon": lon,
    }


def classify_evidence(evidence: Dict[str, Any]) -> str:
    """Describe QUE evidencia acompanya al veredicto, no por que decidio el modelo.

    El modelo es una funcion aprendida sobre 22 variables: no se puede afirmar
    que "disparo por X". Lo que si se puede decir con honestidad es cual de los
    criterios de conducta del §4.4 esta presente, que es lo que el analista
    necesita para revisar la decision. Un bloqueo apoyado solo en la reputacion
    de la subred es el mas delicado y por eso se distingue.
    """
    users = int(evidence.get("usuarios_probados", 0) or 0)
    agents = int(evidence.get("maquinas_alcanzadas", 0) or 0)
    subnet = float(evidence.get("reputacion_subred_24", 0.0) or 0.0)

    if users >= 2:
        return "enumeracion"
    if agents >= 2:
        return "lateral"
    if subnet > 0:
        return "reputacion"
    return "volumen"


class StateStore:
    """Cursor + LiveState + cola reciente de alert_id en un solo fichero.

    Un unico os.replace() por guardado: o se ve el estado anterior completo o el
    nuevo completo, nunca un JSON truncado. Escribir en sitio dejaria el sidecar
    arrancando en frio, con el efecto medido de P(BLOCK) 0,05 frente a 0,99.
    """

    def __init__(self, path: Path, seed: Path):
        self.path = path
        self.seed = seed
        self.generation = 0
        self.cursor: Optional[List[Any]] = None
        self.recent_ids: List[str] = []
        self.live_state: LiveState

    def load(self) -> str:
        if self.path.exists():
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            if int(payload.get("version", 0)) != STATE_VERSION:
                raise SystemExit(
                    f"Estado {self.path} con version {payload.get('version')}, "
                    f"se esperaba {STATE_VERSION}. Migrar o retirar el fichero."
                )
            self.generation = int(payload.get("generation", 0))
            self.cursor = payload.get("cursor")
            self.recent_ids = list(payload.get("recent_alert_ids") or [])
            self.live_state = LiveState.from_json(json.dumps(payload["live_state"]))
            return "runtime"

        if not self.seed.exists():
            # Arrancar en frio degrada los puntuadores de ventana sin avisar.
            # Preferimos no arrancar a arrancar mal.
            raise SystemExit(
                f"No hay estado propio en {self.path} ni semilla en {self.seed}. "
                "El sidecar no arranca en frio."
            )

        self.live_state = LiveState.from_json(self.seed.read_text(encoding="utf-8"))
        return "seed"

    def save(self, live_state: LiveState, cursor: Optional[List[Any]], recent_ids: List[str]) -> int:
        self.generation += 1
        payload = {
            "version": STATE_VERSION,
            "generation": self.generation,
            "saved_at": utcnow(),
            "cursor": cursor,
            "recent_alert_ids": recent_ids[-LRU_PERSIST:],
            "live_state": json.loads(live_state.to_json()),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # El temporal va en el MISMO directorio: os.replace solo es atomico
        # dentro del mismo sistema de ficheros.
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".state-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self.cursor = cursor
        return self.generation


class ScorerService:
    def __init__(self, models_dir: Path, state_dir: Path):
        self.lock = threading.Lock()
        self.store = StateStore(state_dir / "state.json", models_dir.parent / "state" / "live_state.json")
        origin = self.store.load()

        state = self.store.live_state
        # Ruta centinela inexistente: queremos que load() NO lea ningun estado,
        # porque el nuestro ya viene de StateStore. Ojo, os.devnull no sirve:
        # en Windows Path("nul").exists() es True y read_text() devuelve "".
        no_state = models_dir / "__sidecar_owns_state__.json"
        self.early = EarlyBlockScorer.load(models_dir, state_path=no_state)
        self.early.state = state
        self.window = WindowBlockScorer.load(models_dir, state=state)
        self.activity = ActivityScorer.load(models_dir, state=state)

        # LRU sembrado con lo que sobrevivio al reinicio. La regla del usuario
        # ("sort <= cursor -> aceptar solo si no esta en la cola persistida")
        # es exactamente esto: rechazar si y solo si el id esta en el LRU.
        self.seen: "OrderedDict[str, None]" = OrderedDict((i, None) for i in self.store.recent_ids)

        self.project_root = models_dir.parent.parent.parent
        self.started_at = utcnow()
        self.state_origin = origin
        self.counters = {
            "batches": 0, "events_in": 0, "accepted": 0,
            "duplicates": 0, "late_behind_cursor": 0, "verdicts": 0,
        }

    # ---- deduplicacion ----
    def _remember(self, alert_id: str) -> None:
        self.seen[alert_id] = None
        self.seen.move_to_end(alert_id)
        while len(self.seen) > LRU_MAX:
            self.seen.popitem(last=False)

    def _classify(self, alert_id: str, sort: Optional[List[Any]]) -> str:
        if alert_id in self.seen:
            return "duplicate"
        if self.store.cursor is not None and sort is not None:
            try:
                if list(sort) <= list(self.store.cursor):
                    # No esta en la cola persistida: es un documento indexado
                    # tarde, no un reenvio. Se acepta.
                    return "late_behind_cursor"
            except TypeError:
                pass
        return "new"

    # ---- ingesta ----
    def ingest_batch(self, batch: List[Dict[str, Any]]) -> Dict[str, Any]:
        verdicts: List[Dict[str, Any]] = []
        accepted = duplicates = late = 0
        cursor = self.store.cursor

        with self.lock:
            for item in batch:
                alert_id = str(item.get("alert_id") or "")
                sort = item.get("sort")
                if not alert_id:
                    raise ValueError("cada evento necesita alert_id")

                verdict_kind = self._classify(alert_id, sort)
                if verdict_kind == "duplicate":
                    duplicates += 1
                    continue
                if verdict_kind == "late_behind_cursor":
                    late += 1

                alert = {k: item.get("alert", {}).get(k) for k in MODEL_FIELDS}
                verdict = self.early.ingest(alert)
                self._remember(alert_id)
                accepted += 1

                if verdict:
                    verdict["alert_id"] = alert_id
                    verdict["state_generation"] = self.store.generation + 1
                    verdicts.append(verdict)

                if sort is not None and (cursor is None or list(sort) > list(cursor)):
                    cursor = list(sort)

            # Guardar ANTES de responder: si morimos aqui, el lado Node no ha
            # avanzado su cursor y reenviara este tramo.
            generation = self.store.save(self.early.state, cursor, list(self.seen.keys()))

            self.counters["batches"] += 1
            self.counters["events_in"] += len(batch)
            self.counters["accepted"] += accepted
            self.counters["duplicates"] += duplicates
            self.counters["late_behind_cursor"] += late
            self.counters["verdicts"] += len(verdicts)

        return {
            "accepted": accepted,
            "duplicates": duplicates,
            "late_behind_cursor": late,
            "verdicts": verdicts,
            "cursor": cursor,
            "state_generation": generation,
        }

    def ip_risk(self, hits: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Riesgo por DIRECCION IP segun su conducta acumulada.

        Complemento al score de ventana del panel, que puntua un minuto de un
        agente y reparte el mismo numero entre todas sus alertas: en el trafico
        medido, el 100 % de las ventanas contienen mas de una IP distinta, asi
        que ese score no distingue entre atacantes.

        Puntuador EFIMERO sembrado desde la semilla, como /simulate: repetible y
        sin tocar el estado vivo.
        """
        state = LiveState.from_json(self.store.seed.read_text(encoding="utf-8"))
        scorer = EarlyBlockScorer(
            self.early.models, self.early.thresholds, self.early.feature_order, state
        )

        flat = [_flatten_hit(hit) for hit in hits]
        flat.sort(key=lambda a: a["timestamp"])

        verdicts: Dict[str, Dict[str, Any]] = {}
        for alert in flat:
            verdict = scorer.ingest(alert)
            if verdict:
                verdicts[verdict["ip"]] = verdict

        # Una prediccion por presupuesto, no una por IP: sklearn cobra mas por
        # llamada que por fila. Con 369 IPs baja de ~2,8 s a decimas.
        by_budget: Dict[int, List[Tuple[str, Dict[str, float]]]] = {}
        rows_by_ip: Dict[str, Dict[str, float]] = {}
        for ip, profile in scorer.profiles.items():
            events = profile["events"]
            budget = max((k for k in scorer.models if k <= len(events)), default=None)
            if budget is None:
                continue
            row = early_ip_features(events[:budget], profile["context"])
            rows_by_ip[ip] = early_ip_features(events, profile["context"])
            by_budget.setdefault(budget, []).append((ip, row))

        scores: Dict[str, float] = {}
        for budget, entries in by_budget.items():
            frame = pd.DataFrame(
                [[float(row.get(name, 0.0)) for name in scorer.feature_order] for _, row in entries],
                columns=scorer.feature_order,
            )
            probabilities = scorer.models[budget].predict_proba(frame)[:, 1]
            for (ip, _), probability in zip(entries, probabilities):
                scores[ip] = float(probability)

        out: Dict[str, Any] = {}
        for ip, profile in scorer.profiles.items():
            score = scores.get(ip)
            if score is None:
                continue
            verdict = verdicts.get(ip)
            events = profile["events"]
            row = rows_by_ip[ip]
            out[ip] = {
                "score": round(float(score), 4),
                "blocked": verdict is not None,
                "decided_at_alert": verdict["decided_at_alert"] if verdict else None,
                "threshold": verdict["threshold"] if verdict else None,
                "alerts_seen": len(events),
                "evidence": {
                    "usuarios_probados": int(row["n_users"]),
                    "maquinas_alcanzadas": int(row["n_agents"]),
                    "avisos": len(events),
                    "reputacion_subred_24": round(float(row.get("sub24_hostile_ratio", 0.0)), 3),
                },
            }
            out[ip]["evidence_kind"] = classify_evidence(out[ip]["evidence"])
        return out

    def score_panel(self, hits: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Puntua alertas Wazuh anidadas con los modelos del panel.

        Devuelve las dos listas por separado y sus errores: la web las adjunta
        igual que hacia con los subprocesos, y si uno falla el otro sigue.
        """
        scorers = _panel_scorers(self.project_root)
        result: Dict[str, Any] = {"argos": None, "csr_lanl": None, "ip_risk": None, "errors": {}}

        try:
            result["ip_risk"] = self.ip_risk(hits)
        except Exception as error:  # noqa: BLE001
            result["errors"]["ip_risk"] = f"{type(error).__name__}: {error}"

        with self.lock:
            lab = scorers.get("lab")
            if lab is not None:
                try:
                    result["argos"] = lab.score_windows(hits)
                except Exception as error:  # noqa: BLE001
                    result["errors"]["argos"] = f"{type(error).__name__}: {error}"
            else:
                result["errors"]["argos"] = "modulo no disponible"

            csr = scorers.get("csr")
            if csr is not None:
                try:
                    result["csr_lanl"] = csr.score_hits(hits)
                except Exception as error:  # noqa: BLE001
                    result["errors"]["csr_lanl"] = f"{type(error).__name__}: {error}"
            else:
                result["errors"]["csr_lanl"] = "modulo no disponible"

        return result

    def simulate(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Reproduce un lote completo con un puntuador EFIMERO.

        Sembrado desde la semilla y descartado al terminar: no toca el estado
        vivo, no avanza el cursor y da el mismo resultado cada vez que se ejecuta
        con la misma entrada. Es un simulacro, no ingesta.
        """
        state = LiveState.from_json(self.store.seed.read_text(encoding="utf-8"))
        sim = EarlyBlockScorer(self.early.models, self.early.thresholds, self.early.feature_order, state)

        ordered = sorted(alerts, key=lambda a: str(a.get("timestamp") or ""))
        verdicts: List[Dict[str, Any]] = []
        decided_at: Dict[str, int] = {}
        seen_after: Dict[str, int] = {}
        alerts_per_ip: Dict[str, int] = {}
        ips_seen: List[str] = []

        for index, raw in enumerate(ordered):
            alert = {k: raw.get(k) for k in MODEL_FIELDS}
            ip = str(alert.get("src_ip") or "")
            if ip:
                if ip not in alerts_per_ip:
                    ips_seen.append(ip)
                alerts_per_ip[ip] = alerts_per_ip.get(ip, 0) + 1
                # Todo lo que esa IP genera DESPUES del corte es lo que un
                # bloqueo real habria suprimido.
                if ip in decided_at:
                    seen_after[ip] = seen_after.get(ip, 0) + 1

            verdict = sim.ingest(alert)
            if verdict:
                verdict["alert_index"] = index
                verdict["timestamp"] = raw.get("timestamp")
                decided_at[verdict["ip"]] = index
                verdicts.append(verdict)

        for verdict in verdicts:
            verdict["prevented_alerts"] = seen_after.get(verdict["ip"], 0)
            verdict["margin"] = round(verdict["score"] - verdict["threshold"], 4)
            verdict["evidence_kind"] = classify_evidence(verdict["evidence"])

        with_origin = len(ips_seen)
        cuts = sorted(v["decided_at_alert"] for v in verdicts)
        total_prevented = sum(seen_after.values())

        # --- desglose del agregado (README §4.3: ninguna metrica agregada sin
        # su desglose por grupo; el 94 % global puede venir de una sola IP) ---
        by_impact = sorted(verdicts, key=lambda v: -v["prevented_alerts"])
        prevented_sorted = [v["prevented_alerts"] for v in by_impact]
        top3 = sum(prevented_sorted[:3])
        concentration = {
            "top3_prevented": top3,
            "top3_share": round(top3 / total_prevented, 4) if total_prevented else 0.0,
            "median_prevented_per_ip": (
                prevented_sorted[len(prevented_sorted) // 2] if prevented_sorted else 0
            ),
            "max_prevented": prevented_sorted[0] if prevented_sorted else 0,
            "zero_effect_blocks": sum(1 for value in prevented_sorted if value == 0),
            "top_contributors": [
                {"ip": v["ip"], "prevented_alerts": v["prevented_alerts"], "decided_at_alert": v["decided_at_alert"]}
                for v in by_impact[:5]
            ],
        }

        margins = sorted(v["margin"] for v in verdicts)
        kinds: Dict[str, int] = {}
        for verdict in verdicts:
            kinds[verdict["evidence_kind"]] = kinds.get(verdict["evidence_kind"], 0) + 1

        # --- censura por borde de ventana: una IP que aparece al final no tiene
        # tiempo de acumular avisos, asi que la tasa de bloqueo va sesgada a la
        # baja. Es el mismo efecto del §6.4 del paquete. ---
        last_budget = max(self.early.models) if self.early.models else 20
        unblocked = [ip for ip in ips_seen if ip not in decided_at]
        censored = [ip for ip in unblocked if alerts_per_ip.get(ip, 0) < last_budget]

        return {
            "total_alerts": len(ordered),
            "ips_with_network_origin": with_origin,
            "blocked": len(verdicts),
            "block_rate": round(len(verdicts) / with_origin, 4) if with_origin else 0.0,
            "median_cut": cuts[len(cuts) // 2] if cuts else None,
            "prevented_alerts": total_prevented,
            "prevented_ratio": round(total_prevented / len(ordered), 4) if ordered else 0.0,
            "concentration": concentration,
            "margins": {
                "min": margins[0] if margins else None,
                "median": margins[len(margins) // 2] if margins else None,
                "tight_count": sum(1 for value in margins if value < 0.05),
                "tight_threshold": 0.05,
            },
            "evidence_kinds": kinds,
            "censoring": {
                "unblocked": len(unblocked),
                "censored": len(censored),
                "last_budget": last_budget,
                "note": (
                    "IPs sin bloquear que no alcanzaron el ultimo presupuesto: no se puede "
                    "afirmar que sean benignas, solo que la ventana termino antes."
                ),
            },
            "verdicts": verdicts,
        }

    def score_window(self, alerts: List[Dict[str, Any]], agent_id: str) -> Dict[str, Any]:
        clean = [{k: a.get(k) for k in MODEL_FIELDS} for a in alerts]
        with self.lock:
            return {
                "window": self.window.score(clean, agent_id),
                "activity": self.activity.score(clean, agent_id),
            }

    def health(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "started_at": self.started_at,
            "state_origin": self.state_origin,
            "state_generation": self.store.generation,
            "cursor": self.store.cursor,
            "lru_size": len(self.seen),
            "lru_max": LRU_MAX,
            "lru_persisted": min(len(self.seen), LRU_PERSIST),
            "tracked_ips": len(self.early.profiles),
            "blocked_ips": len(self.early.blocked),
            "counters": dict(self.counters),
        }

    def shutdown_save(self) -> None:
        with self.lock:
            self.store.save(self.early.state, self.store.cursor, list(self.seen.keys()))


def make_handler(service: ScorerService):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # silencio: el registro util es el de veredictos
            pass

        def _send(self, code: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> Any:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                self._send(200, service.health())
            elif self.path == "/cursor":
                self._send(200, {"cursor": service.store.cursor,
                                 "state_generation": service.store.generation})
            else:
                self._send(404, {"error": "ruta desconocida"})

        def do_POST(self):  # noqa: N802
            try:
                payload = self._read_json()
                if self.path == "/ingest":
                    batch = payload.get("batch") or []
                    if not isinstance(batch, list):
                        raise ValueError("batch debe ser una lista")
                    self._send(200, service.ingest_batch(batch))
                elif self.path == "/score":
                    hits = payload.get("hits") or []
                    if not isinstance(hits, list):
                        raise ValueError("hits debe ser una lista")
                    self._send(200, service.score_panel(hits))
                elif self.path == "/simulate":
                    alerts = payload.get("alerts") or []
                    if not isinstance(alerts, list):
                        raise ValueError("alerts debe ser una lista")
                    self._send(200, service.simulate(alerts))
                elif self.path == "/window":
                    self._send(200, service.score_window(
                        payload.get("alerts") or [], str(payload.get("agent_id") or "?")))
                else:
                    self._send(404, {"error": "ruta desconocida"})
            except Exception as error:  # noqa: BLE001
                self._send(400, {"error": type(error).__name__, "detail": str(error)})

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description="Sidecar HTTP del ARGOS Scorer")
    parser.add_argument("--host", default=os.environ.get("ARGOS_SCORER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("ARGOS_SCORER_PORT", "8973")))
    parser.add_argument("--models-dir", default=str(HERE / "models"))
    parser.add_argument("--state-dir", default=os.environ.get(
        "ARGOS_SCORER_STATE_DIR", str(HERE.parent.parent / "var" / "argos-scorer")))
    args = parser.parse_args()

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit(f"El sidecar solo escucha en loopback; recibido --host {args.host}")

    started = time.perf_counter()
    service = ScorerService(Path(args.models_dir), Path(args.state_dir))
    server = ThreadingHTTPServer((args.host, args.port), make_handler(service))

    def stop(signum, _frame):
        service.shutdown_save()
        print(f"[argos-scorer] senal {signum}: estado guardado, saliendo", flush=True)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    print(
        f"[argos-scorer] escuchando en http://{args.host}:{args.port} "
        f"| estado: {service.state_origin} gen={service.store.generation} "
        f"| LRU sembrado: {len(service.seen)} "
        f"| arranque: {(time.perf_counter() - started) * 1000:.0f} ms",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        service.shutdown_save()


if __name__ == "__main__":
    main()
