FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -m guard && mkdir -p /app/data && chown guard:guard /app/data
COPY --chown=guard:guard . .
USER guard
CMD ["python", "server.py"]
