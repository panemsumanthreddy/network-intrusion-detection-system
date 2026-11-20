FROM node:22-alpine AS frontend
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home monitor
COPY nids/ nids/
COPY model/ model/
COPY demo/ demo/
COPY --from=frontend /web/dist web/dist
USER monitor
CMD ["waitress-serve", "--listen=0.0.0.0:8000", "--threads=16", "--call", "nids.api:create_app"]
