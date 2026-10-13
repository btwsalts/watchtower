FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps . \
    && useradd --create-home --uid 10001 watchtower \
    && mkdir -p /app/data \
    && chown -R watchtower:watchtower /app

USER watchtower
EXPOSE 8000
CMD ["uvicorn", "watchtower.main:app", "--host", "0.0.0.0", "--port", "8000"]
