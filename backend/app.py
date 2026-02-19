from flask import Flask, request, jsonify
from flask_cors import CORS
from backend.store import STORE
from backend.config import CONFIG
from ids.runtime.predictor_v2 import IDSRuntimeV2
import time

app = Flask(__name__)
CORS(app)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/api/config")
def get_config():
    return CONFIG

@app.post("/api/config")
def set_config():
    data = request.get_json(force=True) or {}
    # allow updating thresholds + toggles
    for k in ("tau_low", "tau_high", "enable_rules"):
        if k in data:
            CONFIG[k] = data[k]
    return CONFIG

@app.post("/api/event")
def ingest_event():
    ev = request.get_json(force=True) or {}
    # accept event contract from collector/predictor
    STORE.add(ev)
    return {"ok": True}

@app.get("/api/attacks")
def get_attacks():
    limit = int(request.args.get("limit", 200))
    return jsonify(STORE.get_events(limit=limit))

@app.get("/api/stats")
def get_stats():
    return STORE.get_stats()

# =========================
# NEW: ingest raw flow -> predict -> store
# =========================
IDS = IDSRuntimeV2(tau_low=0.2, tau_high=0.95)  
@app.post("/api/ingest")
def api_ingest():
    payload = request.get_json(force=True, silent=True) or {}
    flow = payload.get("flow", payload)  # cho phép gửi {flow:{...}} hoặc gửi thẳng {...}

    out = IDS.predict_flow(flow)
    # optional: attach ground-truth nếu tool replay gửi kèm
    if "gt_label" in payload: out["gt_label"] = payload["gt_label"]
    if "gt_attack" in payload: out["gt_attack"] = payload["gt_attack"]

    out["ts"] = float(payload.get("ts", time.time()))
    STORE.add(out)
    return jsonify({"ok": True})

@app.post("/api/ingest_bulk")
def api_ingest_bulk():
    payload = request.get_json(force=True, silent=True) or {}
    items = payload.get("items", [])
    ts0 = float(payload.get("ts0", time.time()))

    n = 0
    for idx, it in enumerate(items):
        flow = it.get("flow", it)
        out = IDS.predict_flow(flow)
        if "gt_label" in it: out["gt_label"] = it["gt_label"]
        if "gt_attack" in it: out["gt_attack"] = it["gt_attack"]

        out["ts"] = float(it.get("ts", ts0 + idx * 0.001))
        STORE.add(out)
        n += 1

    return jsonify({"ok": True, "ingested": n})


if __name__ == "__main__":
    # http://127.0.0.1:5000
    app.run(host="0.0.0.0", port=5000, debug=False)
