# utils.py
from __future__ import annotations

import html
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTP_TIMEOUT = 12
TOOL_VERSION = "1.1.0"


@dataclass
class Finding:
    name: str
    category: str
    severity: str
    cvss: float
    vector: str
    description: str
    evidence: str
    risk: str
    mitigation: list[str]
    references: list[str] = field(default_factory=list)
    cve: str | None = None


@dataclass
class ScanContext:
    analyst: str
    target_input: str
    mode: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    normalized_target: str = ""
    domain: str | None = None
    host: str = ""
    base_url: str | None = None
    ip_addresses: set[str] = field(default_factory=set)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    whois: dict[str, Any] = field(default_factory=dict)
    subdomains: dict[str, dict[str, Any]] = field(default_factory=dict)
    certificates: list[dict[str, Any]] = field(default_factory=list)
    technologies: set[str] = field(default_factory=set)
    google_dorks: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    traceroute: str = ""
    crawl: dict[str, Any] = field(default_factory=lambda: {
        "urls": [], "forms": [], "scripts": [], "api_endpoints": [],
        "comments": [], "sitemap": [], "emails": [], "js_secrets": [],
    })
    sensitive_paths: list[dict[str, Any]] = field(default_factory=list)
    service_notes: list[dict[str, Any]] = field(default_factory=list)
    cves: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tested_payloads: list[str] = field(default_factory=list)
    raw_outputs: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}

# Keys are passed verbatim as the first arg to add_finding() across all modules.
# DO NOT rename keys without updating every call site.
RISK_MAP: dict[str, tuple[float, str, str, str, list[str]]] = {
    # ── Critical ─────────────────────────────────────────────────────────────
    "Anonymous FTP login": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Anonymous FTP login permits unauthenticated file read and potentially write access.",
        ["Disable anonymous FTP logins.", "Restrict FTP to named service accounts.", "Replace FTP with SFTP or FTPS enforcing certificate or key authentication."],
    ),
    "Unauthenticated Redis": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Redis accepted commands without authentication, allowing full data access and potential RCE via CONFIG SET.",
        ["Set requirepass or define ACL users in redis.conf.", "Bind Redis to 127.0.0.1 or a private management interface.", "Block TCP/6379 at the perimeter firewall."],
    ),
    "Unauthenticated MongoDB": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "MongoDB allows unauthenticated access, exposing all databases to enumeration and modification.",
        ["Enable --auth in mongod.conf.", "Create role-based users; revoke default open roles.", "Restrict 27017 to trusted source IPs."],
    ),
    "Unauthenticated Elasticsearch": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Elasticsearch cluster APIs are reachable without credentials, exposing all indices and cluster state.",
        ["Enable Elastic security (xpack.security.enabled: true).", "Require TLS and basic auth or PKI for all API calls.", "Place Elasticsearch behind a private network or API gateway."],
    ),
    "Docker API open": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "The Docker daemon TCP API is reachable without TLS mutual authentication, allowing full container and host compromise.",
        ["Disable TCP API unless required (remove -H tcp://0.0.0.0:2375).", "If remote API is needed, enforce TLS client certificate authentication.", "Firewall TCP/2375 and 2376 to management hosts only."],
    ),
    "SMBv1": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "SMBv1 is enabled and is associated with critical RCE vulnerabilities (EternalBlue/WannaCry).",
        ["Disable SMBv1 via Set-SmbServerConfiguration -EnableSMB1Protocol $false.", "Apply MS17-010 patches on all Windows hosts.", "Block TCP/445 and UDP/137-138 at the network boundary."],
    ),
    "Telnet open": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Telnet transmits credentials and session data in cleartext over the network.",
        ["Disable the telnetd service.", "Replace with OpenSSH using key-based authentication.", "Block TCP/23 inbound at the perimeter firewall."],
    ),
    "SQL Injection": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "User-controlled input appears to influence SQL query structure, enabling data exfiltration, authentication bypass, or database write access.",
        ["Replace string concatenation with parameterized queries or prepared statements.", "Apply input validation with strict allowlists.", "Enforce database least-privilege: application accounts should not have DROP or FILE permissions."],
    ),
    "Command Injection": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Input is passed unsanitized to a shell or system call, allowing arbitrary OS command execution.",
        ["Never pass user input to shell functions (os.system, exec, popen, subprocess with shell=True).", "Use parameterized API calls where possible.", "Apply server-side allowlist validation on all inputs used in system calls."],
    ),
    "RCE via SSTI": (
        9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Server-side template injection allows arbitrary expression evaluation, leading to remote code execution.",
        ["Use sandboxed template engines (e.g., Jinja2 SandboxedEnvironment).", "Never render user-supplied strings as templates.", "Apply WAF rules to detect template syntax in inputs."],
    ),
    # ── High ─────────────────────────────────────────────────────────────────
    "XXE Injection": (
        8.6, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
        "The XML parser may resolve external entities, enabling file disclosure or SSRF.",
        ["Disable DOCTYPE declarations and external entity resolution in the XML parser.", "Use a hardened parser (defusedxml for Python).", "Reject unexpected XML content types at the WAF or API gateway."],
    ),
    "SSRF": (
        8.6, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "A URL parameter appears to be fetched server-side, potentially reaching internal services or cloud metadata endpoints.",
        ["Allowlist permitted outbound destinations.", "Block 169.254.169.254 and RFC-1918 ranges in egress firewall rules.", "Use a dedicated outbound proxy with URL filtering for server-side fetch operations."],
    ),
    "LFI": (
        7.5, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A path parameter may be used to read arbitrary local files from the server.",
        ["Normalize file paths and resolve to an absolute base before use.", "Use opaque file identifiers instead of user-supplied paths.", "Deny path traversal sequences (../, ..\\) and PHP wrappers at the application layer."],
    ),
    "RDP NLA disabled": (
        8.1, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "RDP is accessible without Network Level Authentication, exposing the pre-authentication attack surface.",
        ["Enable NLA via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services.", "Patch all RDP services.", "Restrict RDP source IPs with firewall rules or VPN requirement."],
    ),
    "Exposed config": (
        7.5, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A sensitive configuration file is served by the web server, potentially exposing credentials or internal architecture.",
        ["Remove configuration files from the web root.", "Rotate all credentials visible in the exposed file immediately.", "Add deny rules in the web server config for .env, .ini, .yml, .json, .php config extensions."],
    ),
    "Git repo exposed": (
        7.5, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A .git directory or config file is accessible via HTTP, enabling source code and history reconstruction.",
        ["Remove .git from the web root entirely.", "Deploy only build artifacts to production servers.", "Use a web server deny rule: location ~* /\\.git { deny all; }"],
    ),
    "Unauthenticated Memcached": (
        7.5, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "Memcached responded to stats commands without authentication, exposing cached data and server internals.",
        ["Bind Memcached to 127.0.0.1.", "Block TCP/11211 and UDP/11211 at the perimeter.", "If public exposure is required, add SASL authentication."],
    ),
    "Open Redirect": (
        6.1, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "A redirect parameter can be set to an external domain, enabling phishing attacks.",
        ["Allowlist permitted redirect destinations.", "Use relative paths for internal redirects.", "Reject scheme-relative (//evil.com) and absolute external URLs in redirect parameters."],
    ),
    # ── Medium ───────────────────────────────────────────────────────────────
    "XSS Reflected": (
        6.1, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "User input is reflected into the HTML response without contextual encoding, enabling script injection.",
        ["Apply context-aware output encoding (HTML, attribute, JS, URL).", "Implement a strict Content-Security-Policy disallowing unsafe-inline.", "Use a framework with automatic escaping (e.g., Jinja2 autoescaping, React JSX)."],
    ),
    "XSS Stored": (
        8.0, "High", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
        "User-supplied data stored in the application is rendered without encoding, allowing persistent script execution.",
        ["Encode all stored data on output, not on input.", "Apply CSP to limit script execution to trusted origins.", "Sanitize rich-text input using an allowlist-based HTML sanitizer."],
    ),
    "Sensitive file exposed": (
        5.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "A sensitive or administrative path was discovered and returned a non-404 response.",
        ["Remove files not intended for public access from the web root.", "Restrict access using server-level access controls.", "Review the content of each exposed path for credential or data leakage."],
    ),
    "Outdated SSH version": (
        5.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "The SSH daemon version is below the recommended minimum and may be affected by published vulnerabilities.",
        ["Upgrade to the latest OpenSSH release.", "Disable weak MACs and ciphers (MD5, CBC, arcfour) in sshd_config.", "Restrict SSH access by source IP in /etc/hosts.allow or firewall rules."],
    ),
    "Open CORS": (
        5.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "The Access-Control-Allow-Origin header is set to wildcard (*), permitting cross-origin reads from any domain.",
        ["Replace wildcard origin with an explicit allowlist of trusted domains.", "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.", "Review all API endpoints for unintended CORS exposure."],
    ),
    "Weak TLS": (
        5.9, "Medium", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A deprecated SSL/TLS protocol version or weak cipher suite was detected.",
        ["Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1.", "Configure a modern cipher suite (TLS_AES_256_GCM, ECDHE variants).", "Validate configuration with SSL Labs (ssllabs.com/ssltest) or testssl.sh."],
    ),
    "Missing HSTS": (
        4.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "HTTP Strict-Transport-Security is absent, allowing protocol downgrade attacks.",
        ["Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload", "Test the header on all HTTPS endpoints.", "Submit to the HSTS preload list after confirming all subdomains support HTTPS."],
    ),
    "Missing CSP": (
        4.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "No Content-Security-Policy header was found, reducing the browser's defence against XSS.",
        ["Define a CSP header with at minimum: default-src 'self'.", "Use Content-Security-Policy-Report-Only with a report-uri endpoint before enforcement.", "Progressively tighten the policy to remove unsafe-inline and unsafe-eval."],
    ),
    "Zone Transfer allowed": (
        5.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "AXFR zone transfer succeeded, exposing the full DNS zone contents.",
        ["Restrict AXFR to authorised secondary name server IPs in named.conf: allow-transfer { <secondary>; };", "Audit publicly visible DNS records for sensitive hostnames.", "Monitor name server configuration in version control."],
    ),
    "SMTP open relay": (
        5.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "The SMTP server relays mail from unauthenticated external senders.",
        ["Require SMTP AUTH for outbound relaying.", "Restrict relaying to authenticated users or trusted internal IP ranges.", "Monitor the mail queue and delivery logs for spam abuse."],
    ),
    "SMTP User Enumeration": (
        5.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "The SMTP server responds differently to valid vs invalid VRFY/EXPN queries, enabling username enumeration.",
        ["Disable VRFY and EXPN commands: smtpd_disable_vrfy_command = yes in Postfix.", "Return a uniform response code (252) regardless of whether the address is valid.", "Rate-limit SMTP connections by source IP."],
    ),
    # ── Low ─────────────────────────────────────────────────────────────────
    "Missing X-Frame-Options": (
        3.1, "Low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "X-Frame-Options is absent, leaving the page vulnerable to UI redress (clickjacking) attacks.",
        ["Add X-Frame-Options: DENY or SAMEORIGIN.", "Prefer the CSP frame-ancestors directive for more granular control.", "Test the header with the OWASP Clickjacking tester."],
    ),
    "Missing X-Content-Type-Options": (
        3.1, "Low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "The X-Content-Type-Options: nosniff header is absent, allowing MIME-type sniffing in some browsers.",
        ["Add X-Content-Type-Options: nosniff to all responses.", "Ensure all resources are served with accurate Content-Type headers."],
    ),
    "Missing Referrer-Policy": (
        3.1, "Low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "No Referrer-Policy header is set, potentially leaking URL path information to third-party origins.",
        ["Set Referrer-Policy: strict-origin-when-cross-origin or stricter.", "Use no-referrer for pages handling sensitive query parameters."],
    ),
    "Cookie missing HttpOnly": (
        3.1, "Low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "A session or authentication cookie is accessible to JavaScript, increasing risk if XSS is present.",
        ["Set the HttpOnly attribute on all session and authentication cookies.", "Audit cookies using browser dev tools to confirm the flag is applied."],
    ),
    "Cookie missing Secure": (
        3.1, "Low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "A cookie lacks the Secure attribute and may be transmitted over unencrypted HTTP connections.",
        ["Set the Secure attribute on all cookies.", "Ensure the application is served exclusively over HTTPS."],
    ),
    "SSL expiring soon": (
        5.3, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "The TLS certificate expires within 30 days and may cause trust errors if not renewed.",
        ["Renew the certificate immediately.", "Implement automated renewal using Let's Encrypt / Certbot or an ACME client.", "Set up monitoring alerts at 30, 14, and 7 days before expiry."],
    ),
    # ── Info ─────────────────────────────────────────────────────────────────
    "Server header disclosure": (
        2.6, "Info", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "The Server or X-Powered-By header discloses version information that aids targeted exploitation.",
        ["Suppress detailed Server headers in web server config (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).", "Keep all disclosed software versions patched and current."],
    ),
    "Subdomain found": (
        0.0, "Info", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "A live subdomain was discovered via DNS resolution or certificate transparency.",
        ["Inventory the subdomain in an asset register.", "Confirm ownership and intended public exposure.", "Decommission or redirect subdomains that are no longer in use."],
    ),
    "Technology fingerprint": (
        0.0, "Info", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "A technology fingerprint was detected via headers, HTML patterns, or response signatures.",
        ["Track detected technologies in an asset inventory.", "Apply vendor security patches on the release schedule.", "Consider suppressing version-specific identifiers in production."],
    ),
    "Missing SPF": (
        3.1, "Low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "No SPF TXT record was found; the domain can be spoofed in email From headers.",
        ["Publish an SPF TXT record listing all authorised sending IPs/services.", "End the record with ~all (softfail) initially, then -all (hardfail).", "Test the record with MXToolbox SPF checker."],
    ),
    "Missing DMARC": (
        3.1, "Low", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "No DMARC record was found at _dmarc.<domain>; emails can bypass SPF/DKIM alignment enforcement.",
        ["Publish a DMARC TXT record: v=DMARC1; p=none; rua=mailto:dmarc@<domain>", "After reviewing aggregate reports, move to p=quarantine then p=reject.", "Use a DMARC monitoring service (Postmark, Valimail) to analyse alignment issues."],
    ),
    "JS Secret Detected": (
        6.8, "Medium", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A potential secret, API key, or token was found in a JavaScript file served by the application.",
        ["Rotate any exposed credentials immediately.", "Move secrets to server-side environment variables or a secrets manager (Vault, AWS Secrets Manager).", "Add pre-commit hooks (git-secrets, trufflehog) to prevent future leaks."],
    ),
    "Email Address Harvested": (
        2.0, "Info", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Email addresses were found in page content or HTTP responses, useful for phishing enumeration.",
        ["Obfuscate displayed email addresses (CSS, JS, or image-based rendering).", "Use contact forms instead of mailto links where possible.", "Inform discovered addresses of the potential phishing risk."],
    ),
}


def normalize_target(target: str) -> dict[str, str | None]:
    raw = target.strip()
    parsed = urlparse(raw if re.match(r"^[a-zA-Z]+://", raw) else f"http://{raw}")
    host = parsed.hostname or raw.split("/")[0]
    base_url = None
    if parsed.scheme in {"http", "https"} and host:
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        base_url = f"{parsed.scheme}://{netloc}"
    domain = None if is_ip(host) else host.lower().strip(".")
    return {"raw": raw, "host": host, "domain": domain, "base_url": base_url}


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value.strip())
    return slug.strip("-") or "analyst"


def html_escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def add_warning(ctx: ScanContext, console: Any, message: str) -> None:
    ctx.warnings.append(message)
    if console:
        console.print(f"[yellow]Warning:[/] {message}")


def add_finding(
    ctx: ScanContext,
    key: str,
    evidence: str,
    category: str | None = None,
    name: str | None = None,
    description: str | None = None,
    risk: str | None = None,
    mitigation: list[str] | None = None,
    references: list[str] | None = None,
    cve: str | None = None,
) -> Finding:
    cvss, severity, vector, default_description, default_mitigation = RISK_MAP.get(
        key,
        (0.0, "Info", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
         "Informational observation.", ["Review and validate this observation."]),
    )
    finding = Finding(
        name=name or key,
        category=category or "Recon",
        severity=severity,
        cvss=cvss,
        vector=vector,
        description=description or default_description,
        evidence=evidence[:8000],
        risk=risk or "This observation may increase the attack surface or provide a foothold if left unaddressed.",
        mitigation=mitigation or default_mitigation,
        references=references or [],
        cve=cve,
    )
    ctx.findings.append(finding)
    return finding


def resolve_host(host: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except OSError:
        return []


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def tcp_banner(host: str, port: int, payload: bytes = b"", timeout: int = HTTP_TIMEOUT) -> str:
    """Connect to host:port, optionally send payload, and return the raw banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if payload:
                sock.sendall(payload)
            try:
                return sock.recv(4096).decode("utf-8", "replace").strip()
            except socket.timeout:
                return ""
    except OSError as exc:
        return f"connection failed: {exc}"


def tls_certificate(host: str, port: int = 443) -> dict[str, Any]:
    """Return parsed TLS certificate details for host:port."""
    result: dict[str, Any] = {}
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            cert = tls_sock.getpeercert()
            result["subject"] = dict(x[0] for x in cert.get("subject", []))
            result["issuer"] = dict(x[0] for x in cert.get("issuer", []))
            result["not_before"] = cert.get("notBefore")
            result["not_after"] = cert.get("notAfter")
            result["subject_alt_names"] = [v for _, v in cert.get("subjectAltName", [])]
            result["cipher"] = tls_sock.cipher()
            result["tls_version"] = tls_sock.version()
            # Check expiry
            not_after_str = cert.get("notAfter", "")
            try:
                expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                result["days_until_expiry"] = days_left
            except Exception:
                result["days_until_expiry"] = None
    return result


def request_session():
    """Return a requests.Session with retry logic, timeouts, and a custom User-Agent."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.4,
        status_forcelist={429, 500, 502, 503, 504},
        allowed_methods={"GET", "HEAD", "POST"},
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": f"malak-Scanner/{TOOL_VERSION} (Security Assessment Tool)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    session.verify = False  # scanner targets may use self-signed certs
    return session


def get_url(url: str, **kwargs):
    session = kwargs.pop("session", None) or request_session()
    timeout = kwargs.pop("timeout", HTTP_TIMEOUT)
    allow_redirects = kwargs.pop("allow_redirects", True)
    return session.get(url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)


def head_url(url: str, **kwargs):
    session = kwargs.pop("session", None) or request_session()
    timeout = kwargs.pop("timeout", HTTP_TIMEOUT)
    allow_redirects = kwargs.pop("allow_redirects", False)
    return session.head(url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)


def post_url(url: str, data=None, json=None, **kwargs):
    session = kwargs.pop("session", None) or request_session()
    timeout = kwargs.pop("timeout", HTTP_TIMEOUT)
    return session.post(url, data=data, json=json, timeout=timeout, **kwargs)


def severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    counts = {name: 0 for name in ["Critical", "High", "Medium", "Low", "Info"]}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def overall_risk(findings: list[Finding]) -> str:
    for level in ("Critical", "High", "Medium", "Low"):
        if any(f.severity == level for f in findings):
            return level
    return "Info"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.cvss, SEVERITY_ORDER.get(f.severity, 0)), reverse=True)


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def elapsed(start: float) -> str:
    return f"{time.time() - start:.1f}s"