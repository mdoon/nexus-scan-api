FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    wget curl unzip ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# nuclei の最新バージョンを自動取得
RUN LATEST=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name' | tr -d 'v') \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v${LATEST}/nuclei_${LATEST}_linux_amd64.zip" \
       -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip

# nuclei テンプレートを事前取得
RUN nuclei -update-templates -silent || true

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/index.py .
COPY index.html .

EXPOSE 8080
CMD ["sh", "-c", "uvicorn index:app --host 0.0.0.0 --port ${PORT:-8080}"]
 
