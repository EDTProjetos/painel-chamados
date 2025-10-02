FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# copie os requirements do seu projeto
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# copie o código (ajuste o caminho se seu app.py estiver em /backend)
COPY backend/ /app/

# porta usada no Fly
ENV PORT=8080

# ---- Gunicorn configurado p/ SSE ----
# -k gthread: worker com threads (não bloqueia o loop)
# --threads 8: 8 threads por worker
# -w 1: 1 worker (pode aumentar depois)
# --timeout 0: nunca mata conexões longas (SSE)
# --keep-alive 75: reduz resets ociosos
CMD ["gunicorn", "-k", "gthread", "-w", "1", "--threads", "8", "--timeout", "0", "--keep-alive", "75", "-b", "0.0.0.0:8080", "app:app"]
