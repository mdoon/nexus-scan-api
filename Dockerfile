# ── ステージ1: nuclei バイナリをビルド ──────────────
FROM golang:1.22-alpine AS nuclei-builder
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
 
# ── ステージ2: 本番イメージ ──────────────────────────
FROM python:3.11-slim
 
# nuclei バイナリをコピー
COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei
 
# nuclei テンプレートを更新（起動前に一度だけ）
RUN nuclei -update-templates -silent || true
 
# Python 依存をインストール
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
 
# アプリをコピー
COPY api/index.py .
COPY index.html .
 
# ポート（Railway は PORT 環境変数を自動設定）
ENV PORT=8000
EXPOSE 8000
 
CMD ["sh", "-c", "uvicorn index:app --host 0.0.0.0 --port ${PORT}"]
 
