FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY divineapi_horoscope_numerology_mcp/ ./divineapi_horoscope_numerology_mcp/
COPY server.py ./

RUN pip install --no-cache-dir ".[http]"

ENV MCP_TRANSPORT=http

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/mcp')" || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
