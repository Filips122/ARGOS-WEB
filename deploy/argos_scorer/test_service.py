# -*- coding: utf-8 -*-
"""Prueba del sidecar: dedup, atomicidad, y supervivencia al reinicio."""
import json, os, shutil, subprocess, sys, time, urllib.request
from pathlib import Path

HERE = Path(r"c:\Users\xfeli\Desktop\TFM\ARGOS-GIT\ARGOS-WEB\deploy\argos_scorer")
PY = Path(r"c:\Users\xfeli\Desktop\TFM\ARGOS-GIT\ARGOS-WEB\.venv\Scripts\python.exe")
STATE = Path(os.environ["TEMP"]) / "argos-sidecar-test"
PORT = 8979
BASE = f"http://127.0.0.1:{PORT}"

def call(path, payload=None):
    req = urllib.request.Request(BASE + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def start():
    p = subprocess.Popen([str(PY), str(HERE / "service.py"), "--port", str(PORT),
                          "--state-dir", str(STATE)],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(120):
        try:
            call("/health"); return p
        except Exception:
            if p.poll() is not None:
                print("SIDECAR MURIO:\n", p.stdout.read()); sys.exit(1)
            time.sleep(0.25)
    raise SystemExit("no arranco")

def stop(p):
    p.terminate()
    try: p.wait(timeout=15)
    except subprocess.TimeoutExpired: p.kill()

shutil.rmtree(STATE, ignore_errors=True)
alerts = [json.loads(l) for l in open(HERE / "sample_alerts.jsonl", encoding="utf-8") if l.strip()]
F = ("timestamp","window_start","agent_id","src_ip","src_port","src_user","dst_user",
     "geo_country","geo_city","geo_lat","geo_lon")

def env(i, a, ts_ms=None):
    return {"alert_id": f"A{i:05d}", "sort": [ts_ms if ts_ms else 1_700_000_000_000 + i, f"A{i:05d}"],
            "alert": {k: a.get(k) for k in F}}

print("=" * 68)
print("1) ARRANQUE EN LIMPIO (debe copiar la semilla)")
p = start()
h = call("/health")
print(f"   origen del estado : {h['state_origin']}")
print(f"   LRU sembrado      : {h['lru_size']}")
print(f"   cursor            : {h['cursor']}")

print()
print("2) INGESTA DE 300 EVENTOS")
r1 = call("/ingest", {"batch": [env(i, a) for i, a in enumerate(alerts[:300])]})
print(f"   aceptados={r1['accepted']} duplicados={r1['duplicates']} veredictos={len(r1['verdicts'])}")
print(f"   cursor -> {r1['cursor']}  gen={r1['state_generation']}")

print()
print("3) REENVIO DEL MISMO TRAMO (dedup en caliente)")
r2 = call("/ingest", {"batch": [env(i, a) for i, a in enumerate(alerts[:300])]})
print(f"   aceptados={r2['accepted']} duplicados={r2['duplicates']} veredictos={len(r2['verdicts'])}")
assert r2["accepted"] == 0 and r2["duplicates"] == 300, "el dedup en caliente fallo"
print("   OK: 300/300 descartados, ningun perfil contaminado")

h = call("/health")
ips_before, gen_before = h["tracked_ips"], h["state_generation"]
print(f"   IPs con perfil: {ips_before}")

print()
print("4) MATAR Y REARRANCAR (estado + cursor + LRU deben sobrevivir)")
stop(p)
saved = json.loads((STATE / "state.json").read_text(encoding="utf-8"))
print(f"   fichero: gen={saved['generation']} cursor={saved['cursor']}")
print(f"   alert_id persistidos: {len(saved['recent_alert_ids'])}")
print(f"   claves: {sorted(saved.keys())}")
p = start()
h = call("/health")
print(f"   tras reinicio: origen={h['state_origin']} gen={h['state_generation']} LRU={h['lru_size']}")
print(f"   cursor recuperado: {h['cursor']}")
assert h["state_origin"] == "runtime", "no cargo su propio estado"
assert h["cursor"] == saved["cursor"], "cursor no sobrevivio"
assert h["tracked_ips"] == 0, "profiles no deberia persistir (es diseno del paquete)"

print()
print("5) EL ESCENARIO QUE MOTIVA EL LRU PERSISTIDO")
print("   5a) reenvio tras reinicio de ids YA vistos y por detras del cursor")
r3 = call("/ingest", {"batch": [env(i, a) for i, a in enumerate(alerts[:50])]})
print(f"       aceptados={r3['accepted']} duplicados={r3['duplicates']}")
assert r3["duplicates"] == 50, "el LRU persistido no rechazo el reenvio tras reinicio"
print("       OK: descartados por estar en la cola persistida")

print("   5b) documento INDEXADO TARDE: id nuevo, sort por detras del cursor")
late = {"alert_id": "LATE-0001", "sort": [1_700_000_000_005, "LATE-0001"],
        "alert": {k: alerts[7].get(k) for k in F}}
r4 = call("/ingest", {"batch": [late]})
print(f"       aceptados={r4['accepted']} tarde={r4['late_behind_cursor']} duplicados={r4['duplicates']}")
assert r4["accepted"] == 1 and r4["late_behind_cursor"] == 1, "el documento tardio se perdio"
print("       OK: aceptado y contabilizado como late_behind_cursor")

print()
print("6) PUNTUACION DE VENTANA")
from collections import defaultdict
g = defaultdict(list)
for a in alerts: g[(a["window_start"], a["agent_id"])].append(a)
k = list(g)[0]
w = call("/window", {"alerts": g[k], "agent_id": k[1]})
print(f"   P(BLOCK)={w['window']['block_score']}  familia={w['activity']['family']}"
      f"  attack_score={w['activity']['attack_score']}  desconocida={w['activity']['is_unknown']}")
assert w["window"]["block_score"] > 0.9, "estado frio? P(BLOCK) deberia ser alto con estado caliente"

print()
print("7) RECHAZO DE ARRANQUE SIN ESTADO NI SEMILLA")
stop(p)
bad = subprocess.run([str(PY), str(HERE / "service.py"), "--port", "8988",
                      "--state-dir", str(STATE / "vacio"),
                      "--models-dir", str(STATE / "no-models")],
                     capture_output=True, text=True, timeout=60)
print(f"   codigo de salida={bad.returncode}  (debe ser != 0)")
assert bad.returncode != 0

print()
print("8) RECHAZO DE HOST NO-LOOPBACK")
bad2 = subprocess.run([str(PY), str(HERE / "service.py"), "--host", "0.0.0.0", "--port", "8989"],
                      capture_output=True, text=True, timeout=60)
print(f"   codigo de salida={bad2.returncode}  mensaje: {bad2.stderr.strip().splitlines()[-1][:70] if bad2.stderr.strip() else ''}")
assert bad2.returncode != 0

shutil.rmtree(STATE, ignore_errors=True)
print()
print("=" * 68)
print("TODAS LAS COMPROBACIONES PASAN")
