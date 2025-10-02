import os, time, json, hashlib, requests
from functools import wraps
from datetime import timedelta
from flask import Flask, jsonify, request, Response, render_template, session
from flask_cors import CORS

# ===== Airtable =====
AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Disparos")

# Table name codificado p/ suportar espaços/acentos
TABLE_ENC = requests.utils.quote(AIRTABLE_TABLE_NAME, safe="")
AIRTABLE_API = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{TABLE_ENC}"

HEADERS = {"Authorization": f"Bearer {AIRTABLE_TOKEN}", "Content-Type": "application/json"}

# Reaproveita conexões HTTP (menos latência) e define timeout padrão
REQ = requests.Session()
REQ.headers.update(HEADERS)
DEFAULT_TIMEOUT = 12

# ===== App / Auth =====
APP_USER = os.getenv("APP_USER", "energia")
APP_PASS = os.getenv("APP_PASS", "energia1")

app = Flask(__name__, template_folder="templates")
app.config.update(
    SECRET_KEY=os.getenv("APP_SECRET", "change-this-in-prod"),
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "1") == "1"),  # em dev use 0
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=int(os.getenv("SESSION_DAYS", "7"))),
)
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
    """Lê tudo do Airtable e normaliza campos."""
    records, params = [], {
        "pageSize": 100,
        "sort[0][field]": "AtualizadoEm",   # pode ser Last modified time
        "sort[0][direction]": "desc",
    }
    while True:
        r = REQ.get(AIRTABLE_API, params=params, timeout=DEFAULT_TIMEOUT)
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
            "id": rec.get("id"),
            "tipo": f.get("Tipo", ""),
            "tempo": f.get("Tempo", ""),
            "potes": f.get("Potes", ""),
            "horario": f.get("Horário", ""),   # campo com acento no Airtable
            "status": f.get("Status", ""),
            "atualizadoEm": f.get("AtualizadoEm", ""),
        })
    return out

def hash_data(data):
    return hashlib.md5(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

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
        session.permanent = True
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
        "Horário": b.get("horario", "08:00"),   # com acento
        "Status": b.get("status", "Em andamento"),
        # NÃO escreve em 'AtualizadoEm' (se for calculado, dá 422)
    }
    r = REQ.post(AIRTABLE_API, json={"fields": fields}, timeout=DEFAULT_TIMEOUT)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.patch("/api/disparos/<rid>")
@require_auth
def update_disparo(rid):
    b = request.json or {}
    fields = {}
    if "status"  in b: fields["Status"]   = b["status"]
    if "horario" in b: fields["Horário"]  = b["horario"]   # com acento
    if "tipo"    in b: fields["Tipo"]     = b["tipo"]
    if "tempo"   in b: fields["Tempo"]    = b["tempo"]
    if "potes"   in b: fields["Potes"]    = b["potes"]
    # NÃO escreve em 'AtualizadoEm'

    r = REQ.patch(f"{AIRTABLE_API}/{rid}", json={"fields": fields}, timeout=DEFAULT_TIMEOUT)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

# ----- SSE robusto -----
@app.get("/api/stream")
def stream():
    def gen():
        last_hash = None
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
                yield "event: ping\ndata: {}\n\n"
            time.sleep(5)

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return Response(gen(), mimetype="text/event-stream", headers=headers)

# ===== Main =====
if __name__ == "__main__":
    assert AIRTABLE_TOKEN and AIRTABLE_BASE_ID, "Configure AIRTABLE_TOKEN e AIRTABLE_BASE_ID"
    app.run(host="0.0.0.0", port=8080, debug=True)
