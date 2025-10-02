import os, time, json, hashlib, requests
from functools import wraps
from datetime import timedelta
from flask import Flask, jsonify, request, Response, render_template, session
from flask_cors import CORS

# =============== Airtable ===============
AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Disparos")

# codifica nome da tabela (suporta espaço/acentos)
TABLE_ENC = requests.utils.quote(AIRTABLE_TABLE_NAME, safe="")
AIRTABLE_API = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{TABLE_ENC}"

HEADERS = {"Authorization": f"Bearer {AIRTABLE_TOKEN}", "Content-Type": "application/json"}

# Reaproveita conexões e define timeout padrão
REQ = requests.Session()
REQ.headers.update(HEADERS)
DEFAULT_TIMEOUT = 12
MAX_RETRIES = 4

# =============== App / Auth ===============
APP_USER = os.getenv("APP_USER", "energia")
APP_PASS = os.getenv("APP_PASS", "energia1")

app = Flask(__name__, template_folder="templates")
app.config.update(
    SECRET_KEY=os.getenv("APP_SECRET", "change-this-in-prod"),
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "1") == "1"),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=int(os.getenv("SESSION_DAYS", "7"))),
)
CORS(app, supports_credentials=True)

# =============== Helpers ===============
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("auth_ok"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

def md5(obj) -> str:
    return hashlib.md5(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

def _airtable_request(method: str, url: str, **kwargs):
    """Faz request ao Airtable com retry/backoff (429/5xx/timeout)."""
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    backoff = 0.6
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = REQ.request(method, url, timeout=timeout, **kwargs)
            # 429: respeita Retry-After se vier
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                try:
                    wait = float(ra) if ra else backoff
                except Exception:
                    wait = backoff
                time.sleep(wait)
                backoff = min(backoff * 2, 6)
                continue
            # 5xx: tenta de novo
            if 500 <= resp.status_code < 600:
                time.sleep(backoff)
                backoff = min(backoff * 2, 6)
                continue
            return resp
        except requests.RequestException:
            time.sleep(backoff)
            backoff = min(backoff * 2, 6)
    # última tentativa (sem mascarar erro)
    return REQ.request(method, url, timeout=timeout, **kwargs)

def _normalize_records(records):
    out = []
    for rec in records:
        f = rec.get("fields", {})
        out.append({
            "id": rec.get("id"),
            "tipo": f.get("Tipo", ""),
            "tempo": f.get("Tempo", ""),
            "potes": f.get("Potes", ""),
            "horario": f.get("Horário", ""),  # campo no Airtable com acento
            "status": f.get("Status", ""),
            "atualizadoEm": f.get("AtualizadoEm", ""),
        })
    return out

def _fetch_all_from_airtable():
    """Lê tudo do Airtable (pagina por pagina) com robustez."""
    records = []
    params = {
        "pageSize": 100,
        "sort[0][field]": "AtualizadoEm",   # ideal ser 'Last modified time' no Airtable
        "sort[0][direction]": "desc",
    }
    while True:
        r = _airtable_request("GET", AIRTABLE_API, params=params)
        if not r.ok:
            # Levanta para caller decidir fallback
            r.raise_for_status()
        payload = r.json()
        records.extend(payload.get("records", []))
        if "offset" not in payload:
            break
        params["offset"] = payload["offset"]
    return _normalize_records(records)

# Cache de snapshot na memória (serve como “plano B” se Airtable cair)
_LAST_SNAPSHOT = []
_LAST_HASH = ""
_LAST_FETCH_TS = 0.0
_SNAPSHOT_TTL = 8.0  # segundos

def get_snapshot(force: bool = False):
    """Retorna (data, is_stale). Atualiza do Airtable se TTL expirou."""
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
    except Exception:
        # fallback: devolve último snapshot bom (stale) para não quebrar o front
        return _LAST_SNAPSHOT, True

# =============== Views ===============
@app.route("/")
def serve_index():
    return render_template("index.html")

@app.get("/healthz")
def health():
    return jsonify({"ok": True})

# ---- Auth ----
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

# ---- Data ----
@app.get("/api/disparos")
def get_disparos():
    data, stale = get_snapshot(force=False)
    # Nunca 502 aqui — se Airtable falhar, devolvemos o último snapshot
    resp = jsonify(data)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Data-Stale"] = "1" if stale else "0"
    return resp

@app.post("/api/disparos")
@require_auth
def create_disparo():
    b = request.json or {}
    fields = {
        "Tipo": b.get("tipo", ""),
        "Tempo": b.get("tempo", 0),
        "Potes": b.get("potes", 0),
        "Horário": b.get("horario", "08:00"),
        "Status": b.get("status", "Em andamento"),
    }
    r = _airtable_request("POST", AIRTABLE_API, json={"fields": fields})
    # força refresh do cache se deu certo
    if r.ok:
        try:
            get_snapshot(force=True)
        except Exception:
            pass
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.patch("/api/disparos/<rid>")
@require_auth
def update_disparo(rid):
    b = request.json or {}
    fields = {}
    if "status"  in b: fields["Status"]   = b["status"]
    if "horario" in b: fields["Horário"]  = b["horario"]
    if "tipo"    in b: fields["Tipo"]     = b["tipo"]
    if "tempo"   in b: fields["Tempo"]    = b["tempo"]
    if "potes"   in b: fields["Potes"]    = b["potes"]
    r = _airtable_request("PATCH", f"{AIRTABLE_API}/{rid}", json={"fields": fields})
    if r.ok:
        try:
            get_snapshot(force=True)
        except Exception:
            pass
    return (r.text, r.status_code, {"Content-Type": "application/json"})

# ---- SSE: envia snapshot quando mudar ----
@app.get("/api/stream")
def stream():
    def gen():
        last_hash = None
        # reconexão rápida
        yield "retry: 3000\n\n"
        while True:
            data, _stale = get_snapshot(force=False)
            h = md5(data)
            if h != last_hash:
                last_hash = h
                payload = json.dumps({"type": "snapshot", "records": data}, ensure_ascii=False)
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

# =============== Main ===============
if __name__ == "__main__":
    assert AIRTABLE_TOKEN and AIRTABLE_BASE_ID, "Configure AIRTABLE_TOKEN e AIRTABLE_BASE_ID"
    app.run(host="0.0.0.0", port=8080, debug=True)
