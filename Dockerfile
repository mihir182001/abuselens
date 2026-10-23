FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY sql ./sql
RUN pip install --no-cache-dir -e .
ENV ABUSELENS_DB=/data/abuselens.duckdb ABUSELENS_MODEL_DIR=/data/models
EXPOSE 8000
CMD ["uvicorn", "abuselens.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
