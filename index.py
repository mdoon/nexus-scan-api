from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import ssl
import socket
import datetime
import urllib.parse
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 本番: ["https://mdoon.github.io"] に変更推奨
    allow_methods=["POST"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url

def get_hostname(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or ""

def check_ssl(hostname: str) -> list:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_str = cert.get("notAfter", "")
                expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_dt - datetime.datetime.utcnow()).days
                if days_left < 0:
                    findings.append({"severity": "critical", "title": "SSL証明書期限切れ", "desc": f"証明書はすでに期限切れ（{abs(days_left)}日超過）。", "cve": "CWE-295"})
                elif days_left < 30:
                    findings.append({"severity": "medium", "title": "SSL証明書期限切れ間近", "desc": f"有効期限まで残り{days_left}日。早急に更新してください。", "cve": "N/A"})
                else:
                    findings.append({"severity": "info", "title": "SSL証明書は有効", "desc": f"有効期限まで残り{days_left}日。問題なし。", "cve": "N/A"})
                tls_ver = ssock.version()
                if tls_ver in ("TLSv1", "TLSv1.1"):
                    findings.append({"severity": "high", "title": f"古いTLSバージョン ({tls_ver})", "desc": "TLS 1.0/1.1は非推奨。TLS 1.2以上を強制してください。", "cve": "CWE-326"})
                else:
                    findings.append({"severity": "info", "title": f"TLSバージョン: {tls_ver} ✓", "desc": "安全なTLSバージョンを使用しています。", "cve": "N/A"})
    except ssl.SSLCertVerificationError:
        findings.append({"severity": "critical", "title": "SSL証明書の検証失敗", "desc": "証明書が信頼できません。自己署名または不正な証明書の可能性があります。", "cve": "CWE-295"})
    except Exception:
        findings.append({"severity": "info", "title": "SSL接続不可（HTTPのみ）", "desc": "HTTPS接続に失敗しました。HTTPSが未対応の可能性があります。", "cve": "N/A"})
    return findings

def check_headers(headers: dict) -> list:
    findings = []
    h = {k.lower(): v for k, v in headers.items()}
    checks = [
        ("content-security-policy", "high", "Content-Security-Policy 未設定", "CSPヘッダーがありません。XSSやデータインジェクション攻撃のリスクが高まります。", "CWE-1021"),
        ("strict-transport-security", "medium", "HSTS 未設定", "HTTPダウングレード攻撃に脆弱です。max-age=31536000以上を推奨します。", "CWE-319"),
        ("x-frame-options", "medium", "X-Frame-Options 未設定", "クリックジャッキング攻撃を防ぐヘッダーがありません。", "CWE-1021"),
        ("x-content-type-options", "low", "X-Content-Type-Options 未設定", "MIMEスニッフィング攻撃を防ぐnosniffの設定がありません。", "CWE-16"),
        ("referrer-policy", "low", "Referrer-Policy 未設定", "リファラ情報が外部サイトに漏洩する可能性があります。", "CWE-200"),
        ("permissions-policy", "low", "Permissions-Policy 未設定", "カメラ・マイク等のブラウザAPIアクセス制限が設定されていません。", "N/A"),
    ]
    for header_name, severity, title, desc, cve in checks:
        if header_name not in h:
            findings.append({"severity": severity, "title": title, "desc": desc, "cve": cve})
        else:
            findings.append({"severity": "info", "title": f"{header_name} ✓ 設定済み", "desc": f"値: {h[header_name][:100]}", "cve": "N/A"})

    csp = h.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp:
            findings.append({"severity": "medium", "title": "CSP: unsafe-inline 許可", "desc": "インラインスクリプトが実行可能です。XSS防御が弱まります。", "cve": "CWE-79"})
        if "unsafe-eval" in csp:
            findings.append({"severity": "medium", "title": "CSP: unsafe-eval 許可", "desc": "eval()が実行可能です。コードインジェクションリスクがあります。", "cve": "CWE-79"})

    cors = h.get("access-control-allow-origin", "")
    if cors == "*":
        findings.append({"severity": "high", "title": "CORSワイルドカード設定", "desc": "任意オリジンからのクロスオリジン読み取りが可能です。", "cve": "CWE-942"})

    server = h.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({"severity": "low", "title": "Serverヘッダーにバージョン情報漏洩", "desc": f"「{server[:80]}」が公開されています。", "cve": "CWE-200"})

    powered = h.get("x-powered-by", "")
    if powered:
        findings.append({"severity": "low", "title": "X-Powered-By ヘッダー露出", "desc": f"「{powered[:80]}」が公開されています。フレームワーク情報の隠蔽を推奨します。", "cve": "CWE-200"})

    return findings

def check_cookies(response) -> list:
    findings = []
    set_cookie_headers = [v for k, v in response.headers.items() if k.lower() == "set-cookie"]
    for cookie_str in set_cookie_headers:
        lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip()[:40]
        issues = []
        if "secure" not in lower: issues.append("Secureフラグ欠如")
        if "httponly" not in lower: issues.append("HttpOnlyフラグ欠如")
        if "samesite" not in lower: issues.append("SameSiteフラグ欠如")
        if issues:
            findings.append({"severity": "medium", "title": f"Cookie設定不備: {name}", "desc": f"{', '.join(issues)}。セッション情報の盗取リスクがあります。", "cve": "CWE-614"})
        else:
            findings.append({"severity": "info", "title": f"Cookie ✓ フラグ設定済み: {name}", "desc": "Secure / HttpOnly / SameSite が適切に設定されています。", "cve": "N/A"})
    return findings

def check_xss_passive(headers: dict, body: str) -> list:
    findings = []
    h = {k.lower(): v for k, v in headers.items()}

    xss_prot = h.get("x-xss-protection", "")
    if not xss_prot:
        findings.append({"severity": "medium", "title": "X-XSS-Protection 未設定", "desc": "ブラウザ組み込みのXSSフィルターを有効化するヘッダーがありません。", "cve": "CWE-79"})
    elif xss_prot.startswith("0"):
        findings.append({"severity": "medium", "title": "X-XSS-Protection が無効化", "desc": "ブラウザのXSSフィルターが明示的に無効になっています。", "cve": "CWE-79"})
    else:
        findings.append({"severity": "info", "title": "X-XSS-Protection ✓ 設定済み", "desc": f"値: {xss_prot}", "cve": "N/A"})

    inline_scripts = re.findall(r"<script(?![^>]*src)[^>]*>", body, re.IGNORECASE)
    if len(inline_scripts) > 5:
        findings.append({"severity": "low", "title": f"インラインスクリプト多用 ({len(inline_scripts)}箇所)", "desc": "インラインscriptタグが多数検出されました。CSPによる制御が困難になります。", "cve": "CWE-79"})

    dangerous_js = []
    if re.search(r"document\.write\s*\(", body): dangerous_js.append("document.write()")
    if re.search(r"\beval\s*\(", body): dangerous_js.append("eval()")
    if re.search(r"innerHTML\s*=", body): dangerous_js.append("innerHTML 直接代入")
    if re.search(r"outerHTML\s*=", body): dangerous_js.append("outerHTML 直接代入")
    if dangerous_js:
        findings.append({"severity": "medium", "title": f"XSS高リスクなJS検出: {', '.join(dangerous_js)}", "desc": "XSSに悪用されやすいJavaScript APIがページ内で検出されました。入力値のサニタイズを確認してください。", "cve": "CWE-79"})

    password_inputs = re.findall(r'<input[^>]*type=["\']?password["\']?[^>]*>', body, re.IGNORECASE)
    for inp in password_inputs:
        if "autocomplete" not in inp.lower():
            findings.append({"severity": "low", "title": "パスワードフィールドにautocomplete未設定", "desc": "autocomplete=\"off\"が設定されていません。ブラウザへの平文保存リスクがあります。", "cve": "CWE-522"})
            break

    return findings

def check_sqli_passive(body: str, url: str) -> list:
    findings = []

    sql_error_patterns = [
        (r"you have an error in your sql syntax", "MySQLエラーメッセージ露出"),
        (r"warning: mysql_", "MySQL警告メッセージ露出"),
        (r"unclosed quotation mark after the character string", "SQL Serverエラー露出"),
        (r"pg_query\(\).*error", "PostgreSQLエラー露出"),
        (r"sqlite3\.operationalerror", "SQLiteエラー露出"),
        (r"microsoft ole db provider for sql server", "MSSQL OLEDBエラー露出"),
        (r"ora-[0-9]{4,}", "Oracleエラーコード露出"),
    ]
    for pattern, label in sql_error_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({"severity": "critical", "title": f"SQLエラーメッセージ露出: {label}", "desc": "レスポンスにSQLエラーが含まれています。DB構造が攻撃者に推測されるリスクがあります。", "cve": "CWE-209"})
            break

    debug_patterns = [
        (r"stack trace:", "スタックトレース露出"),
        (r"at \w+\.\w+\(.*\.java:\d+\)", "Javaスタックトレース露出"),
        (r"traceback \(most recent call last\)", "Pythonトレースバック露出"),
        (r"parse error.*on line \d+", "PHPパースエラー露出"),
        (r"<b>fatal error</b>", "PHPファタルエラー露出"),
    ]
    for pattern, label in debug_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({"severity": "high", "title": f"デバッグ情報露出: {label}", "desc": "レスポンスに内部エラー情報が含まれています。システム構造が推測されるリスクがあります。", "cve": "CWE-209"})
            break

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    numeric_params = [k for k, v in params.items() if any(val.isdigit() for val in v)]
    if numeric_params:
        findings.append({"severity": "low", "title": f"数値型クエリパラメータ検出: {', '.join(numeric_params[:3])}", "desc": "数値型URLパラメータはSQLiのターゲットになりやすい。プリペアドステートメントの使用を推奨します。", "cve": "CWE-89"})

    forms = re.findall(r"<form[^>]*>.*?</form>", body, re.IGNORECASE | re.DOTALL)
    for form in forms:
        has_csrf = bool(re.search(r'name=["\'](_token|csrf|authenticity_token|__RequestVerificationToken)["\']', form, re.IGNORECASE))
        method = re.search(r'method=["\']?(\w+)', form, re.IGNORECASE)
        if method and method.group(1).upper() == "POST" and not has_csrf:
            findings.append({"severity": "high", "title": "CSRFトークン未検出のPOSTフォーム", "desc": "POSTフォームにCSRFトークンが見つかりません。クロスサイトリクエストフォージェリ攻撃に脆弱な可能性があります。", "cve": "CWE-352"})
            break

    return findings

def check_https_redirect(original_url: str, final_url: str) -> list:
    findings = []
    if original_url.startswith("https://") and not final_url.startswith("https://"):
        findings.append({"severity": "high", "title": "HTTPSからHTTPへのダウングレード", "desc": "最終リダイレクト先がHTTPになっています。通信が平文で送信されます。", "cve": "CWE-319"})
    elif original_url.startswith("http://") and final_url.startswith("https://"):
        findings.append({"severity": "info", "title": "HTTP→HTTPSリダイレクト ✓", "desc": "HTTPアクセスが自動的にHTTPSにリダイレクトされています。", "cve": "N/A"})
    return findings

def calc_risk_score(findings: list) -> int:
    weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    score = sum(weights.get(f["severity"], 0) for f in findings)
    return min(score, 100)

@app.post("/api/scan")
async def scan(req: ScanRequest):
    url = normalize_url(req.url)
    hostname = get_hostname(url)
    all_findings = []
    logs = []

    logs.append({"text": f"[INIT] ターゲット解決中: {hostname}", "type": "info"})
    logs.append({"text": "[SSL] TLS証明書を検査中...", "type": "info"})
    ssl_findings = check_ssl(hostname)
    all_findings.extend(ssl_findings)
    logs.append({"text": f"[SSL] {len(ssl_findings)}件の結果", "type": "ok"})

    logs.append({"text": "[HTTP] ページを取得中...", "type": "info"})
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NexusScan/1.0; security-audit)"},
            verify=False
        ) as client:
            response = await client.get(url)

        final_url = str(response.url)
        body = response.text
        headers = dict(response.headers)
        logs.append({"text": f"[HTTP] ステータス: {response.status_code} | {len(body)}bytes 取得", "type": "ok"})

        all_findings.extend(check_https_redirect(url, final_url))

        logs.append({"text": "[HDR] セキュリティヘッダーを解析中...", "type": "info"})
        hdr_findings = check_headers(headers)
        all_findings.extend(hdr_findings)
        logs.append({"text": f"[HDR] {len(hdr_findings)}件の結果", "type": "ok"})

        logs.append({"text": "[COOKIE] Cookieフラグを検査中...", "type": "info"})
        cookie_findings = check_cookies(response)
        all_findings.extend(cookie_findings)
        logs.append({"text": f"[COOKIE] {len(cookie_findings)}件の結果", "type": "ok"})

        logs.append({"text": "[XSS] クロスサイトスクリプティングリスクを解析中...", "type": "info"})
        xss_findings = check_xss_passive(headers, body)
        all_findings.extend(xss_findings)
        logs.append({"text": f"[XSS] {len(xss_findings)}件の結果", "type": "ok"})

        logs.append({"text": "[SQLI] SQLインジェクションリスクを解析中...", "type": "info"})
        sqli_findings = check_sqli_passive(body, final_url)
        all_findings.extend(sqli_findings)
        logs.append({"text": f"[SQLI] {len(sqli_findings)}件の結果", "type": "ok"})

    except httpx.ConnectError:
        logs.append({"text": "[ERROR] 接続失敗: サイトに到達できませんでした", "type": "error"})
        all_findings.append({"severity": "critical", "title": "サイトへの接続失敗", "desc": "URLに到達できませんでした。URLが正しいか、サイトが稼働しているか確認してください。", "cve": "N/A"})
    except httpx.TimeoutException:
        logs.append({"text": "[ERROR] タイムアウト: レスポンスが遅すぎます", "type": "error"})
        all_findings.append({"severity": "medium", "title": "レスポンスタイムアウト", "desc": "10秒以内にレスポンスがありませんでした。", "cve": "N/A"})
    except Exception as e:
        logs.append({"text": f"[ERROR] 予期しないエラー: {str(e)[:60]}", "type": "error"})

    issue_count = sum(1 for f in all_findings if f["severity"] != "info")
    risk_score = calc_risk_score(all_findings)
    logs.append({"text": f"[DONE] スキャン完了 — {issue_count}件の問題を検出 | スコア: {risk_score}/100", "type": "ok"})

    return {"url": url, "risk_score": risk_score, "findings": all_findings, "logs": logs}

@app.get("/")
def root():
    return {"status": "NEXUS SCAN API online"}
