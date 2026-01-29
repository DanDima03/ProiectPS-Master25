FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server ./server

ENV PYTHONPATH=/app/server
CMD ["uvicorn", "server.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
