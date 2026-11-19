FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS dependencies
WORKDIR /app/ml
RUN python -m pip install --no-cache-dir uv==0.13.7
COPY ml/pyproject.toml ml/uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app/ml PATH=/app/ml/.venv/bin:$PATH
WORKDIR /app
COPY --from=dependencies /app/ml/.venv/ /app/ml/.venv/
COPY contracts/ contracts/
COPY ml/netwatch_ml/ ml/netwatch_ml/
USER 65532:65532
CMD ["python", "-m", "netwatch_ml.serving", "--host", "0.0.0.0", "--port", "8000"]
