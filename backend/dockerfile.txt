FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
ENV PORT=8080

CMD exec gunicorn app:app -k gevent --bind 0.0.0.0:$PORT --workers 1 --timeout 120
