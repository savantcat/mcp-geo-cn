FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1 GEO_SEARX_URL=""
EXPOSE 8767
CMD ["python", "server.py", "--transport", "http", "--host", "0.0.0.0", "--port", "8767", "--stateless"]
