import os
import time
import json
import hashlib
import logging
import requests
from functools import wraps
from datetime import timedelta

from flask import Flask, jsonify, request, Response, render_template, session
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

# ====================== LOGGING ======================
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("app")

# ====================== AIRTABLE =====================
AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Disparos")

if not AIRTABLE_TOKEN or not AIRTABLE_BASE_ID:
    # Em produção o gunicorn já aborta; em dev mostramos erro claro
    log.warning("Faltam secrets AIRTABLE_TOKEN ou AIRTABLE_BASE_ID.")

# Codifica nome da tabela (suporta espaço/acentos)
TABLE_ENC = requests.utils.quote(AIRTABLE_TABLE_NAME or "Disparos", safe="")
AIRTABLE_API = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{TABLE_ENC}"

HEADERS = {
    "Authorization": f"Bearer {AIRTABLE_TOKEN}",
    "Content-Type": "application/json",
}

# Reaproveita conexões HTTP + headers fixos
REQ = requests.Session()
REQ.headers.update(HEADERS)
DEFAULT_TIMEOUT = int(os.getenv("AIRTABLE_TIMEOUT", "12"))
MAX_RETRIES = int(os.getenv("AIRTABLE_MAX_RETRIES", "4"))

# ====================== APP / AUTH ===================
APP_USER = os.getenv("APP_USER", "energia")
APP_PASS = os.getenv("APP_PASS", "energia1")

app = Flask(__name__, template_folder="templates")

# Corrige scheme/host/port atrás do proxy (Fly)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

app.config.update(
    SECRET_KEY=os.getenv("APP_SECRET", "change-this-in-prod"),
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "1") == "1"),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=int(os.getenv("SESSION_DAYS", "7"))),
)

# Se front e API forem mesmo host, CORS é irrelevante.
# Deixamos ligado com credenciais (ok também se usar domínio separado).
CORS(app, supports_credentials=True)

# ===================== HELPERS =======================

def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("auth_ok"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

def md5(obj) -> str:
    return hashlib.md5(
        json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()

def _airtable_request(method: str, url: str, **kwargs) -> requests.Response:
    """
    Chama o Airtable com retry/backoff para 429/5xx/timeouts,
    respeitando 'Retry-After' quando presente.
    """
    timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
    backoff = 0.6
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = REQ.request(method, url, timeout=timeout, **kwargs)
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                try:
                    wait = float(ra) if ra else backoff
                except Exception:
                    wait = backoff
                log.warning("Airtable 429; aguardando %.2fs", wait)
                time.sleep(wait)
                backoff = min(backoff * 2, 6)
                continue
            if 500 <= resp.status_code < 600:
                log.warning("Airtable %s; retry em %.2fs", resp.status_code, backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 6)
                continue
            return resp
        except requests.RequestException as e:
            log.warning("Erro de rede para Airtable (%s). Retry em %.2fs", e, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 6)
    # Última tentativa (deixa erro estourar p/ caller tratar)
    return REQ.request(method, url, timeout=timeout, **kwargs)

def _normalize_records(records):
    # Converte payload do Airtable para o modelo esperado no front
    out = []
    for rec in records:
        f = rec.get("fields", {}) or {}
        out.append(
            {
                "id": rec.get("id"),
                "tipo": f.get("Tipo", ""),
                "tempo": f.get("Tempo", ""),
                "potes": f.get("Potes", ""),
                "horario": f.get("Horário", ""),  # campo com acento no Airtable
                "status": f.get("Status", ""),
                "atualizadoEm": f.get("AtualizadoEm", ""),
            }
        )
    return out

def _fetch_all_from_airtable():
    """Lê tudo do Airtable (paginado) com robustez / ordenado por 'AtualizadoEm'."""
    records = []
    params = {
        "pageSize": 100,
        "sort[0][field]": "AtualizadoEm",  # ideal: Last modified time ou campo de data
        "sort[0][direction]": "desc",
    }
    while True:
        r = _airtable_request("GET", AIRTABLE_API, params=params)
        if not r.ok:
            # deixa o caller decidir o fallback (cache)
            r.raise_for_status()
        payload = r.json()
        records.extend(payload.get("records", []))
        if "offset" not in payload:
            break
        params["offset"] = payload["offset"]
    return _normalize_records(records)

# ---- Snapshot em memória (evita quebrar front se Airtable oscilar) ----
_LAST_SNAPSHOT = []
_LAST_HASH = ""
_LAST_FETCH_TS = 0.0
_SNAPSHOT_TTL = float(os.getenv("SNAPSHOT_TTL", "8.0"))  # segundos

def get_snapshot(force: bool = False):
    """
    Retorna (data, is_stale). Atualiza do Airtable se TTL expirou.
    Em erro, devolve último snapshot bom (stale=True).
    """
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
        log.warning("Falha ao atualizar snapshot do Airtable: %s", e)
        return _LAST_SNAPSHOT, True

# ===================== VIEWS =========================

@app.after_request
def add_common_headers(resp):
    # Evita cache cliente/proxy para rotas da API
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp

@app.route("/")
def serve_index():
    return render_template("index.html")

@app.get("/healthz")
def health():
    # Útil p/ checagens do Fly
    return jsonify({"ok": True})

# ---------- Auth ----------
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

# ---------- Data ----------
@app.get("/api/disparos")
def get_disparos():
    data, stale = get_snapshot(force=False)
    resp = jsonify(data)
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
        "Horário": b.get("horario", "08:00"),  # campo com acento
        "Status": b.get("status", "Em andamento"),
    }
    r = _airtable_request("POST", AIRTABLE_API, json={"fields": fields})
    if r.ok:
        # Atualiza cache (best effort)
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
    if "status" in b:
        fields["Status"] = b["status"]
    if "horario" in b:
        fields["Horário"] = b["horario"]  # campo com acento
    if "tipo" in b:
        fields["Tipo"] = b["tipo"]
    if "tempo" in b:
        fields["Tempo"] = b["tempo"]
    if "potes" in b:
        fields["Potes"] = b["potes"]

    r = _airtable_request("PATCH", f"{AIRTABLE_API}/{rid}", json={"fields": fields})
    if r.ok:
        try:
            get_snapshot(force=True)
        except Exception:
            pass
    return (r.text, r.status_code, {"Content-Type": "application/json"})

# ---------- SSE (stream) ----------
@app.get("/api/stream")
def stream():
    def gen():
        last_hash = None
        # reconexão rápida
        yield "retry: 3000\n\n"
        while True:
            # força leitura real do Airtable para pegar deleções externas rapidamente
            data, stale = get_snapshot(force=True)
            h = md5(data)
            if h != last_hash:
                last_hash = h
                payload = json.dumps(
                    {"type": "snapshot", "records": data, "stale": stale},
                    ensure_ascii=False
                )
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

# ===================== MAIN =========================
if __name__ == "__main__":
    assert AIRTABLE_TOKEN and AIRTABLE_BASE_ID, "Configure AIRTABLE_TOKEN e AIRTABLE_BASE_ID"
    # Em produção rode com GUNICORN (ver Dockerfile/README).
    app.run(host="0.0.0.0", port=8080, debug=True)
