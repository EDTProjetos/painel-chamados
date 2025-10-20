import os, time, json, hashlib, logging, requests
from functools import wraps
from datetime import timedelta, datetime

from flask import Flask, jsonify, request, Response, render_template, session
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("app")

# ===== Airtable =====
AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Disparos")

if not AIRTABLE_TOKEN or not AIRTABLE_BASE_ID:
    log.warning("Faltam secrets AIRTABLE_TOKEN ou AIRTABLE_BASE_ID.")

TABLE_ENC = requests.utils.quote(AIRTABLE_TABLE_NAME or "Disparos", safe="")
AIRTABLE_API = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{TABLE_ENC}"

REQ = requests.Session()
REQ.headers.update({
    "Authorization": f"Bearer {AIRTABLE_TOKEN}",
    "Content-Type": "application/json",
})

DEFAULT_TIMEOUT = int(os.getenv("AIRTABLE_TIMEOUT", "12"))
MAX_RETRIES = int(os.getenv("AIRTABLE_MAX_RETRIES", "4"))

# ===== App / Auth =====
APP_USER = os.getenv("APP_USER", "energia")
APP_PASS = os.getenv("APP_PASS", "energia1")

app = Flask(__name__, template_folder="templates")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config.update(
    SECRET_KEY=os.getenv("APP_SECRET", "change-this-in-prod"),
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "1") == "1"),
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

def md5(obj) -> str:
    return hashlib.md5(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

def _airtable_request(method: str, url: str, **kwargs) -> requests.Response:
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    backoff = 0.6
    for _ in range(1, MAX_RETRIES + 1):
        try:
            resp = REQ.request(method, url, timeout=timeout, **kwargs)
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                try: wait = float(ra) if ra else backoff
                except: wait = backoff
                log.warning("Airtable 429; aguardando %.2fs", wait)
                time.sleep(wait); backoff = min(backoff*2, 6); continue
            if 500 <= resp.status_code < 600:
                log.warning("Airtable %s; retry em %.2fs", resp.status_code, backoff)
                time.sleep(backoff); backoff = min(backoff*2, 6); continue
            return resp
        except requests.RequestException as e:
            log.warning("Erro de rede Airtable (%s). Retry em %.2fs", e, backoff)
            time.sleep(backoff); backoff = min(backoff*2, 6)
    return REQ.request(method, url, timeout=timeout, **kwargs)

def _normalize_records(records):
    out = []
    for rec in records:
        f = rec.get("fields", {}) or {}
        out.append({
            "id": rec.get("id"),
            "tipo": f.get("Tipo", ""),
            "tempo": f.get("Tempo", 0),
            "potes": f.get("Potes", 0),
            "volume": f.get("Volume", 0),
            "horario": f.get("Horário", ""),
            "status": f.get("Status", ""),
            "template": f.get("Template", ""),
            "atualizadoEm": f.get("AtualizadoEm", ""),
            "data": f.get("Data", ""),
        })
    return out

def _fetch_all_from_airtable():
    records = []
    params = {
        "pageSize": 100,
        "sort[0][field]": "AtualizadoEm",
        "sort[0][direction]": "desc",
    }
    while True:
        r = _airtable_request("GET", AIRTABLE_API, params=params)
        if not r.ok:
            r.raise_for_status()
        payload = r.json()
        records.extend(payload.get("records", []))
        if "offset" not in payload: break
        params["offset"] = payload["offset"]
    return _normalize_records(records)

_LAST_SNAPSHOT = []
_LAST_HASH = ""
_LAST_FETCH_TS = 0.0
_SNAPSHOT_TTL = float(os.getenv("SNAPSHOT_TTL", "6.0"))

def get_snapshot(force: bool = False):
    global _LAST_SNAPSHOT, _LAST_HASH, _LAST_FETCH_TS
    now = time.time()
    if not force and (now - _LAST_FETCH_TS) < _SNAPSHOT_TTL and _LAST_SNAPSHOT:
        return _LAST_SNAPSHOT, False
    try:
        data = _fetch_all_from_airtable()
        _LAST_SNAPSHOT = data
        _LAST_HASH = md5(data)
        _LAST_FETCH_TS = time.time()
        return data, False
    except Exception as e:
        log.warning("Falha snapshot Airtable: %s", e)
        return _LAST_SNAPSHOT, True

# ===== Views =====
@app.after_request
def add_headers(resp):
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp

@app.route("/")
def index():
    return render_template("index.html")

@app.get("/healthz")
def health():
    return jsonify(ok=True)

# ---- Auth ----
@app.post("/api/login")
def api_login():
    b = request.json or {}
    if (b.get("username") or "").strip() == APP_USER and (b.get("password") or "").strip() == APP_PASS:
        session["auth_ok"] = True
        session.permanent = True
        return jsonify(ok=True)
    return jsonify(ok=False, error="invalid_credentials"), 401

@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify(ok=True)

# ---- Data ----
@app.get("/api/disparos")
def api_disparos():
    data, stale = get_snapshot(force=False)
    resp = jsonify(data)
    resp.headers["X-Data-Stale"] = "1" if stale else "0"
    return resp

@app.post("/api/disparos")
@require_auth
def create_disparo():
    b = request.json or {}
    
    today_str = datetime.utcnow().strftime('%Y-%m-%d')

    try:
        fields = {
            "Tipo": b.get("tipo", ""),
            "Tempo": int(b.get("tempo", 0)),
            "Potes": int(b.get("potes", 0)),
            "Volume": int(b.get("volume", 0)),
            "Horário": b.get("horario", "08:00"),
            "Status": b.get("status", "Em andamento"),
            # LINHA REMOVIDA: Não enviamos mais 'AtualizadoEm'
            "Data": b.get("data", today_str)
        }
    except (ValueError, TypeError) as e:
        log.error(f"Erro de tipo de dado ao criar disparo: {e}")
        return jsonify({"error": "invalid_data_type", "message": "Os campos de tempo, potes e volume devem ser números inteiros."}), 400

    
    if "template" in b and b["template"]:
        fields["Template"] = b["template"]

    r = _airtable_request("POST", AIRTABLE_API, json={"fields": fields}, params={"typecast":"true"})
    
    if r.ok:
        try: get_snapshot(force=True)
        except: pass
    else:
        log.error(f"Airtable respondeu com {r.status_code}: {r.text}")

    return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.patch("/api/disparos/<rid>")
@require_auth
def update_disparo(rid):
    b = request.json or {}
    fields = {}
    if "status" in b:   fields["Status"] = b["status"]
    if "horario" in b:  fields["Horário"] = b["horario"]
    if "tipo" in b:     fields["Tipo"] = b["tipo"]
    if "tempo" in b:    fields["Tempo"] = int(b.get("tempo", 0))
    if "potes" in b:    fields["Potes"] = int(b.get("potes", 0))
    if "volume" in b:   fields["Volume"] = int(b.get("volume", 0))
    if "template" in b: fields["Template"] = b["template"] or ""
    if "data" in b:     fields["Data"] = b.get("data")


    r = _airtable_request("PATCH", f"{AIRTABLE_API}/{rid}", json={"fields": fields}, params={"typecast":"true"})
    if r.ok:
        try: get_snapshot(force=True)
        except: pass
    return (r.text, r.status_code, {"Content-Type": "application/json"})


@app.delete("/api/disparos/<rid>")
@require_auth
def delete_disparo(rid):
    r = _airtable_request("DELETE", f"{AIRTABLE_API}/{rid}")
    if r.ok:
        try: get_snapshot(force=True)
        except: pass
    return (r.text, r.status_code, {"Content-Type": "application/json"})

# ---- SSE ----
@app.get("/api/stream")
def stream():
    def gen():
        last_hash = None
        yield "retry: 3000\n\n"
        while True:
            data, stale = get_snapshot(force=True)
            h = md5(data)
            if h != last_hash:
                last_hash = h
                payload = json.dumps({"type":"snapshot","records":data,"stale":stale}, ensure_ascii=False)
                yield f"data: {payload}\n\n"
            else:
                yield "event: ping\ndata: {}\n\n"
            time.sleep(3)

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    }
    return Response(gen(), mimetype="text/event-stream", headers=headers)

# ===== Main =====
if __name__ == "__main__":
    assert AIRTABLE_TOKEN and AIRTABLE_BASE_ID, "Configure AIRTABLE_TOKEN e AIRTABLE_BASE_ID"
    app.run(host="0.0.0.0", port=8080, debug=True)
