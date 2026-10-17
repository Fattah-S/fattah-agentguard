# Fattah AgentGuard — security monitoring for AI coding agents
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    STREAM_DELAY=0.2

WORKDIR /app

# Dependencies first, so code changes don't re-install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x start.sh \
 && useradd --create-home --uid 10001 agentguard \
 && chown -R agentguard:agentguard /app
USER agentguard

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen('http://localhost:%s/healthz' % os.environ.get('PORT','8080'))" || exit 1

CMD ["./start.sh"]
