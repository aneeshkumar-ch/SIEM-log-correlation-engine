FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
ENV ES_HOST=http://127.0.0.1:9200
ENV KIBANA_HOST=http://127.0.0.1:5601
ENV COLLECTOR_POLL_SECONDS=2
ENV CORRELATION_INTERVAL_SECONDS=10
ENV ENABLE_COLLECTOR=true
ENV ENABLE_SCHEDULER=true

EXPOSE 777

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "777"]
