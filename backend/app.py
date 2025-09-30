import os, time, json, hashlib, requests
from flask import Flask, jsonify, request, Response, render_template
from flask_cors import CORS

AIRTABLE_TOKEN = os.getenv("AIRTABLE_TOKEN")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")
AIRTABLE_TABLE_NAME = os.getenv("AIRTABLE_TABLE_NAME", "Disparos")
AIRTABLE_API = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_TABLE_NAME}"
HEADERS = {"Authorization": f"Bearer {AIRTABLE_TOKEN}", "Content-Type": "application/json"}

# agora ele sabe procurar o index.html dentro da pasta templates
app = Flask(__name__, template_folder="templates")
CORS(app)

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
            "horario": f.get("Horario", ""),
            "status": f.get("Status", ""),
            "atualizadoEm": f.get("AtualizadoEm", ""),
        })
    return out

def hash_data(data):
    return hashlib.md5(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

# 🔹 Rota raiz -> renderiza o index.html da pasta templates
@app.route("/")
def serve_index():
    return render_template("index.html")

# 🔹 API
@app.get("/api/disparos")
def get_disparos():
    data = fetch_all()
    return jsonify(data)

@app.post("/api/disparos")
def create_disparo():
    b = request.json or {}
    fields = {
        "Tipo": b.get("tipo", ""),
        "Tempo": b.get("tempo", 0),
        "Potes": b.get("potes", 0),
        "Horario": b.get("horario", "08:00"),
        "Status": b.get("status", "Em andamento"),
    }
    r = requests.post(AIRTABLE_API, headers=HEADERS, json={"fields": fields}, timeout=30)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.patch("/api/disparos/<rid>")
def update_disparo(rid):
    b = request.json or {}
    fields = {}
    if "status" in b: fields["Status"] = b["status"]
    if "horario" in b: fields["Horario"] = b["horario"]
    if "tipo" in b: fields["Tipo"] = b["tipo"]
    if "tempo" in b: fields["Tempo"] = b["tempo"]
    if "potes" in b: fields["Potes"] = b["potes"]
    r = requests.patch(f"{AIRTABLE_API}/{rid}", headers=HEADERS, json={"fields": fields}, timeout=30)
    return (r.text, r.status_code, {"Content-Type": "application/json"})

@app.get("/api/stream")
def stream():
    def gen():
        last_hash = None
        data = fetch_all()
        last_hash = hash_data(data)
        yield f"data: {json.dumps({'type':'snapshot','records':data})}\n\n"
        while True:
            time.sleep(5)
            data = fetch_all()
            h = hash_data(data)
            if h != last_hash:
                last_hash = h
                yield f"data: {json.dumps({'type':'snapshot','records':data})}\n\n"
            else:
                yield "event: ping\ndata: {}\n\n"
    return Response(gen(), mimetype="text/event-stream")

if __name__ == "__main__":
    assert AIRTABLE_TOKEN and AIRTABLE_BASE_ID, "Configure AIRTABLE_TOKEN e AIRTABLE_BASE_ID"
    app.run(host="0.0.0.0", port=8080, debug=True)
