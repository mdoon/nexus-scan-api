# ── ベースイメージ ───────────────────────────────────
FROM python:3.11-slim

# 必要パッケージ
RUN apt-get update && apt-get install -y \
    wget curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# nuclei バイナリをGitHubリリースから直接取得
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.9_linux_amd64.zip \
    -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /tmp/nuclei \
    && mv /tmp/nuclei/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei /tmp/nuclei.zip

# nuclei テンプレートを事前取得
RUN nuclei -update-templates -silent || true

# Python 依存
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリ
COPY api/index.py .
COPY index.html .

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn index:app --host 0.0.0.0 --port ${PORT}"]
 
