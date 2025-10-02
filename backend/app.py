import os, time, json, hashlib, requests
from functools import wraps
from datetime import timedelta
from flask import Flask, jsonify, request, Response, render_template, session
from flask_cors import CORS

# ===================== Airtable =====================
AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Disparos")
AIRTABLE_SORT_FIELD = os.getenv("AIRTABLE_SORT_FIELD", "AtualizadoEm")  # se não existir, caímos sem sort

# Tabela codificada p/ suportar espaço/acentos
TABLE_ENC = requests.utils.quote(AIRTABLE_TABLE_NAME, safe="")
AIRTABLE_API = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{TABLE_ENC}"

HEADERS = {
    "Authorization": f"Bearer {AIRTABLE_TOKEN}",
    "Content-Type": "application/json",
}

# Session HTTP com pool e retries (429/5xx)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REQ = requests.Session()
REQ.headers.update(HEADERS)

_retry = Retry(
    total=5,
    read=5,
    connect=3,
    backoff_factor=0.6,                     # 0.6s, 1.2s, 2.4s, ...
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset(["GET", "POST", "PATCH"]),
    respect_retry_after_header=True,
)
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=10, pool_maxsize=20)
REQ.mount("https://", _adapter)
REQ.mount("http://", _adapter)

DEFAULT_TIMEOUT = 12  # segundos

# ===================== App / Auth =====================
APP_USER = os.getenv("APP_USER", "energia")
APP_PASS = os.getenv("APP_PASS", "energia1")

app = Flask(__name__, template_folder="templates")
app.config.update(
    SECRET_KEY=os.getenv("APP_SECRET", "change-this-in-prod"),
    # Produção (HTTPS/Fly): COOKIE_SECURE=1 | Local: COOKIE_SECURE=0
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "1") == "1"),
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=timedelta(days=int(os.getenv("SESSION_DAYS", "7"))),
    JSON_AS_ASCII=False,
    TEMPLATES_AUTO_RELOAD=True,
)
# Se site e API estiverem no MESMO host (recomendado), CORS quase não é usado;
# Mantemos habilitado com credenciais para não atrapalhar cenários alternativos.
CORS(app, supports_credentials=True)

# ===================== Helpers =====================
def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("auth_ok"):
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

# Campos que pediremos ao Airtable (reduz payload)
SELECT_FIELDS = ["Tipo", "Tempo", "Potes", "Horário", "Horario", "Status", "AtualizadoEm"]

def _normalize_fields(f):
    """Normaliza um registro do Airtable para o formato do front."""
    # Aceita 'Horário' (com acento) ou 'Horario' (sem acento)
    horario = f.get("Horário", None)
    if horario is None:
        horario = f.get("Horario", "")

    return {
        "tipo": f.get("Tipo", ""),
        "tempo": f.get("Tempo", ""),
        "potes": f.get("Potes", ""),
        "horario": horario,
        "status": f.get("Status", ""),
        "atualizadoEm": f.get("AtualizadoEm", ""),
    }

def fetch_all():
    """Lê tudo do Airtable de forma resiliente e normaliza campos."""
    records = []
    params = {
        "pageSize": 100,
        "fields[]": SELECT_FIELDS,  # só retorna o que precisamos
        "sort[0][field]": AIRTABLE_SORT_FIELD,
        "sort[0][direction]": "desc",
    }

    def _do_request(_params):
        """Executa GET paginado. Se 422 por sort inválido, reenvia sem sort."""
        recs = []
        p = dict(_params)
        while True:
            r = REQ.get(AIRTABLE_API, params=p, timeout=DEFAULT_TIMEOUT)
            if r.status_code == 422 and "sort" in p:
                # Campo de sort não existe: remove sort e tenta fluxo sem sort
                p.pop("sort[0][field]", None)
                p.pop("sort[0][direction]", None)
                continue
            r.raise_for_status()
            payload = r.json()
            recs.extend(payload.get("records", []))
            if "offset" not in payload:
                break
            p["offset"] = payload["offset"]
        return recs

    records = _do_request(params)

    out = []
    for rec in records:
        f = rec.get("fields", {}) or {}
        out.append({
            "id": rec.get("id"),
            **_normalize_fields(f),
        })
    return out

def hash_data(data):
    return hashlib.md5(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

# ===================== Views =====================
@app.route("/")
def serve_index():
    return render_template("index.html")

@app.get("/healthz")
def health():
    return jsonify({"ok": True})

# -------- Auth API --------
@app.post("/api/login")
def api_login():
    b = request.json or {}
    u = (b.get("username") or "").strip()
    p = (b.get("password") or "").strip()
    if u == APP_USER and p == APP_PASS:
        session["auth_ok"] = True
        session.permanent = True  # respeita PERMANENT_SESSION_LIFETIME
        return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "invalid_credentials"}), 401

@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})

# -------- Data API --------
@app.get("/api/disparos")
def get_disparos():
    try:
        data = fetch_all()
        return jsonify(data)
    except requests.HTTPError as e:
        # Erro vindo do Airtable (com status)
        return jsonify({"error": "airtable_http_error", "status": e.response.status_code, "detail": e.response.text}), 502
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
        # Use SEMPRE o nome real do campo no Airtable. Aqui suportamos com acento.
        "Horário": b.get("horario", "08:00"),
        "Status": b.get("status", "Em andamento"),
        # NÃO escreva 'AtualizadoEm' se for campo calculado ou "Last modified time"
    }
    try:
        r = REQ.post(AIRTABLE_API, json={"fields": fields}, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except requests.HTTPError as e:
        return (e.response.text, 502, {"Content-Type": "application/json"})

@app.patch("/api/disparos/<rid>")
@require_auth
def update_disparo(rid):
    b = request.json or {}
    fields = {}
    if "status"  in b: fields["Status"]  = b["status"]
    if "horario" in b: fields["Horário"] = b["horario"]   # campo com acento
    if "tipo"    in b: fields["Tipo"]    = b["tipo"]
    if "tempo"   in b: fields["Tempo"]   = b["tempo"]
    if "potes"   in b: fields["Potes"]   = b["potes"]
    if not fields:
        return jsonify({"ok": True, "skipped": True})

    try:
        r = REQ.patch(f"{AIRTABLE_API}/{rid}", json={"fields": fields}, timeout=DEFAULT_TIMEOUT)
        r.raise_for_status()
        return (r.text, r.status_code, {"Content-Type": "application/json"})
    except requests.HTTPError as e:
        return (e.response.text, 502, {"Content-Type": "application/json"})

# -------- SSE robusto --------
@app.get("/api/stream")
def stream():
    def gen():
        last_hash = None
        # reconexão rápida do EventSource
        yield "retry: 2000\n\n"
        while True:
            try:
                data = fetch_all()
                h = hash_data(data)
                if last_hash != h:
                    last_hash = h
                    payload = json.dumps({"type":"snapshot","records":data}, ensure_ascii=False)
                    yield f"data: {payload}\n\n"
                else:
                    # keep-alive/heartbeat
                    yield "event: ping\ndata: {}\n\n"
            except Exception:
                # Não derruba a UI nem envia snapshot vazio
                yield "event: ping\ndata: {}\n\n"
            time.sleep(5)

    headers = {
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",  # desativa buffering em alguns proxies
        "Connection": "keep-alive",
    }
    return Response(gen(), mimetype="text/event-stream", headers=headers)

# ===================== Main =====================
if __name__ == "__main__":
    assert AIRTABLE_TOKEN and AIRTABLE_BASE_ID, "Configure AIRTABLE_TOKEN e AIRTABLE_BASE_ID"
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=True)
