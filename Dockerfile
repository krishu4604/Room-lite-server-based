FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
COPY server/licensing/requirements.txt /app/licensing/requirements.txt
RUN pip install --no-cache-dir -r /app/licensing/requirements.txt
COPY server/licensing /app/licensing
COPY server/backend /app/backend
EXPOSE 8080
CMD ["python", "-m", "licensing.remote_bootstrap"]
