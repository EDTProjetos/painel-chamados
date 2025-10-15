import os, time, json, hashlib, requests
from functools import wraps
from flask import Flask, jsonify, request, Response, render_template, session
from flask_cors import CORS

# ===== Airtable =====
AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Disparos")
AIRTABLE_API = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
HEADERS = {"Authorization": f"Bearer {AIRTABLE_TOKEN}", "Content-Type": "application/json"}

# ===== App / Auth =====
APP_USER = os.getenv("APP_USER", "energia")
APP_PASS = os.getenv("APP_PASS", "energia1")

app = Flask(__name__, template_folder="templates")
# Em produção (Fly) use HTTPS → cookie seguro por padrão
app.config.update(
    SECRET_KEY=os.getenv("APP_SECRET", "change-this-in-prod"),
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "1") == "1"),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
)
# Se site e API estiverem no MESMO host (recomendado), CORS é irrelevante;
# deixamos habilitado com suporte a credenciais por segurança.
CORS(app, supports_credentials=True)

# ===== Helpers =====
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("auth_ok"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

def fetch_all():
    records, params = [], {
        "pageSize": 100,
        "sort[0][field]": "AtualizadoEm",
        "sort[0][direction]": "desc",
    }
    while True:
        r = requests.get(AIRTABLE_API, headers=HEADERS, params=params, timeout=30)
        r.raise_for_status()
        payload = r.json()
        records.extend(payload.get("records", []))
        if "offset" not in payload:
            break
        params["offset"] = payload["offset"]

    out = []
    for rec in records:
        f = rec.get("fields", {})
        out.append({
            "id": rec["id"],
            "tipo": f.get("Tipo", ""),
            "tempo": f.get("Tempo", ""),
            "potes": f.get("Potes", ""),
            "horario": f.get("Horário", ""),   # <-- com acento
            "status": f.get("Status", ""),
            "atualizadoEm": f.get("AtualizadoEm", ""),
        })
    return out

def hash_data(data):
    return hashlib.md5(
        json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()

# ===== Views =====
@app.route("/")
def serve_index():
    return render_template("index.html")

@app.get("/healthz")
def health():
    return jsonify({"ok": True})

# ----- Auth API -----
@app.post("/api/login")
def api_login():
    b = request.json or {}
    u = (b.get("username") or "").strip()
    p = (b.get("password") or "").strip()
    if u == APP_USER and p == APP_PASS:
        session["auth_ok"] = True
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "invalid_credentials"}), 401

@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})

# ----- Data API -----
@app.get("/api/disparos")
def get_disparos():
    try:
        data = fetch_all()
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": "upstream_airtable_error", "detail": str(e)}), 502

@app.post("/api/disparos")
@require_auth
def create_disparo():
    b = request.json or {}
    fields = {
        "Tipo": b.get("tipo", ""),
        "Tempo": b.get("tempo", 0),
        "Potes": b.get("potes", 0),
        "Horário": b.get("horario", "08:00"),  # <-- com acento
        "Status": b.get("status", "Em andamento"),
        "AtualizadoEm": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    r = requests.post(AIRTABLE_API, headers=HEADERS, json={"fields": fields}, timeout=30)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.patch("/api/disparos/<rid>")
@require_auth
def update_disparo(rid):
    b = request.json or {}
    fields = {}
    if "status"  in b: fields["Status"]   = b["status"]
    if "horario" in b: fields["Horário"]  = b["horario"]  # <-- com acento
    if "tipo"    in b: fields["Tipo"]     = b["tipo"]
    if "tempo"   in b: fields["Tempo"]    = b["tempo"]
    if "potes"   in b: fields["Potes"]    = b["potes"]
    if fields:          fields["AtualizadoEm"] = time.strftime("%Y-%m-%d %H:%M:%S")

    r = requests.patch(f"{AIRTABLE_API}/{rid}", headers=HEADERS, json={"fields": fields}, timeout=30)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

# ----- SSE robusto -----
@app.get("/api/stream")
def stream():
    def gen():
        last_hash = None
        # reconexão rápida (2s)
        yield "retry: 2000\n\n"
        while True:
            try:
                data = fetch_all()
                h = hash_data(data)
                if last_hash != h:
                    last_hash = h
                    yield f"data: {json.dumps({'type':'snapshot','records':data})}\n\n"
                else:
                    yield "event: ping\ndata: {}\n\n"
            except Exception:
                # Em erro (Airtable flutuando), não manda snapshot vazio
                yield "event: ping\ndata: {}\n\n"
            time.sleep(5)

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",  # desativa buffering em alguns proxies
        "Connection": "keep-alive",
    }
    return Response(gen(), mimetype="text/event-stream", headers=headers)

# ===== Main =====
if __name__ == "__main__":
    assert AIRTABLE_TOKEN and AIRTABLE_BASE_ID, "Configure AIRTABLE_TOKEN e AIRTABLE_BASE_ID"
    app.run(host="0.0.0.0", port=8080, debug=True)
