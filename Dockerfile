FROM python:3.12-slim

WORKDIR /app

# Install system deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl procps && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy agent code (modular v9)
COPY config.py .
COPY providers.py .
COPY prompts.py .
COPY loki.py .
COPY k8s_engine.py .
COPY docker_engine.py .
COPY pdbs.py .
COPY rollback.py .
COPY cost.py .
COPY notifications.py .
COPY observability.py .
COPY prometheus.py .
COPY k8s_events.py .
COPY approval.py .
COPY email_reader.py .
COPY storage.py .
COPY circuit_breaker.py .
COPY agent.py .
COPY watchdog.sh .
RUN chmod +x watchdog.sh

# Run as non-root
RUN useradd -m -r agent && chown -R agent:agent /app
USER agent

CMD ["./watchdog.sh"]
