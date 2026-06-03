# passive_recon.py
from __future__ import annotations

import re
import socket
from typing import Any



from .utils import ScanContext, add_finding, add_warning, get_url, resolve_host, reverse_dns, tls_certificate


# Expanded from 60 → 130 entries covering modern SaaS, cloud infra, and DevOps tooling
COMMON_SUBDOMAINS = [
    # Web / app
    "www", "app", "apps", "web", "portal", "dashboard", "panel", "ui",
    # Auth / identity
    "login", "auth", "sso", "oauth", "id", "identity", "accounts", "account",
    # API / services
    "api", "api2", "api-v1", "api-v2", "rest", "graphql", "rpc", "services",
    # Infrastructure
    "admin", "administrator", "administration", "cpanel", "whm", "plesk",
    "ftp", "ftp2", "sftp", "ssh", "rdp", "vnc",
    # Mail
    "mail", "mail2", "webmail", "smtp", "mx", "mx1", "mx2", "imap", "pop",
    "autodiscover", "exchange",
    # DNS
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    # Network edge
    "vpn", "vpn2", "proxy", "gateway", "firewall", "router", "switch",
    "remote", "access", "extranet",
    # Dev / staging
    "dev", "dev2", "development", "staging", "stage", "uat", "qa", "test",
    "test2", "beta", "alpha", "demo", "sandbox", "preview", "next",
    # Internal
    "internal", "intranet", "corp", "office", "mgmt", "management",
    # Content / assets
    "cdn", "static", "assets", "media", "img", "images", "files",
    "upload", "uploads", "download", "downloads", "video", "stream",
    # Business
    "shop", "store", "checkout", "payment", "pay", "billing", "invoice",
    "blog", "news", "forum", "wiki", "docs", "help", "support", "kb",
    "status", "uptime", "monitor", "health",
    # DevOps / CI
    "git", "gitlab", "github", "gitea", "jenkins", "ci", "cd", "build",
    "jira", "confluence", "bitbucket", "sonar", "nexus", "artifactory",
    "grafana", "kibana", "prometheus", "alertmanager",
    # Cloud / infra
    "s3", "storage", "backup", "backups", "old", "new", "legacy",
    "cloud", "aws", "azure", "gcp",
    # Data
    "db", "database", "mysql", "mssql", "postgres", "mongo", "redis",
    "elastic", "search", "cache",
    # HR / ERP / CRM
    "hr", "erp", "crm", "finance", "accounting", "payroll",
    # Security
    "siem", "soc", "security", "waf", "ids", "ips",
    # Mobile / IoT
    "mobile", "m", "api-mobile", "push", "iot",
]

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "CAA", "SRV"]

# Regex patterns for secrets in JavaScript or HTML source
JS_SECRET_PATTERNS = [
    (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
    (r'(?i)(?:secret|secret[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-/+]{16,})["\']', "Secret Key"),
    (r'(?i)(?:access[_-]?token|auth[_-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Access Token"),
    (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Password"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(?i)ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
    (r'(?i)glpat-[A-Za-z0-9\-_]{20}', "GitLab Personal Access Token"),
    (r'(?i)eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token"),
    (r'(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'(?i)(?:mongodb\+srv|mongodb)://[^\s"\']+', "MongoDB Connection String"),
    (r'(?i)(?:postgresql|mysql|redis)://[^\s"\']+', "Database URI"),
]

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)

# Technology fingerprinting: (pattern, name, applies_to)
TECH_PATTERNS: list[tuple[str, str]] = [
    # CMS
    (r'wp-content|wp-includes|generator["\s]+content["\s]*=[\s"\']+WordPress', "WordPress"),
    (r'content=["\']Joomla|/media/system/js/', "Joomla"),
    (r'Drupal\.settings|/sites/default/', "Drupal"),
    (r'content=["\']TYPO3', "TYPO3"),
    # Frameworks
    (r'__REACT_DEVTOOLS_GLOBAL_HOOK__|data-reactroot|data-reactid', "React"),
    (r'ng-app|angular\.js|_ngcontent|ng-version', "Angular"),
    (r'data-v-[0-9a-f]+|vue\.min\.js|__vue__', "Vue.js"),
    (r'__NEXT_DATA__|/_next/static', "Next.js"),
    (r'__NUXT__|/_nuxt/', "Nuxt.js"),
    (r'data-svelte|__SVELTE', "Svelte"),
    # Servers / platforms
    (r'AmazonS3|s3\.amazonaws\.com', "Amazon S3"),
    (r'x-amz-cf-id|cloudfront\.net', "Amazon CloudFront"),
    (r'cf-ray|__cfduid|cloudflare', "Cloudflare"),
    (r'x-vercel-id|vercel\.app', "Vercel"),
    (r'x-github-request-id|github\.com', "GitHub Pages"),
    (r'x-powered-by.*express', "Express.js"),
    (r'x-powered-by.*django|csrftoken', "Django"),
    (r'x-powered-by.*laravel|laravel_session', "Laravel"),
    (r'x-powered-by.*rails|_rails_session', "Ruby on Rails"),
    (r'x-powered-by.*asp\.net|__viewstate', "ASP.NET"),
    # Security / CDN
    (r'x-sucuri-id|sucuri-cloudproxy', "Sucuri WAF"),
    (r'x-akamai-transformed|akamaighost', "Akamai"),
    (r'x-iinfo|imperva', "Imperva WAF"),
    (r'x-cache.*varnish|via.*varnish', "Varnish Cache"),
    (r'x-cache.*squid|squid/', "Squid Proxy"),
]

WAF_HEADERS = {
    "x-sucuri-id": "Sucuri WAF",
    "cf-ray": "Cloudflare",
    "x-firewall": "Generic Firewall",
    "x-akamai-transformed": "Akamai",
    "x-iinfo": "Imperva",
    "x-distil-cs": "Distil Networks",
    "x-sqreen-responded": "Sqreen",
}


def run(ctx: ScanContext, console) -> None:
    from .wizard import PhaseProgress
    with PhaseProgress(console, "Phase 1 - Passive Reconnaissance") as pp:
        pp.step("WHOIS registration lookup")
        _whois(ctx, console)

        pp.step("DNS enumeration  (A, AAAA, MX, NS, TXT, SOA, CAA, SRV, PTR, DMARC, zone-transfer)")
        _dns(ctx, console)

        pp.step(f"Subdomain brute-force  ({len(COMMON_SUBDOMAINS)} candidates)")
        _subdomains(ctx, console)

        pp.step("IP intelligence  (reverse DNS · ASN · Tor/proxy check)")
        _ip_intel(ctx, console)

        pp.step("Building Google dork checklist")
        _google_dorks(ctx)

        pp.step("Certificate transparency  (crt.sh + live TLS grab + expiry check)")
        _cert_transparency(ctx, console)

        pp.step("Technology fingerprinting  (response headers + HTML pattern matching)")
        _technology_fingerprint(ctx, console)

        pp.step("Email harvesting + JS secret scanning across crawled URLs")
        _harvest_page_content(ctx, console)

        pp.done()


def _whois(ctx: ScanContext, console) -> None:
    if not ctx.domain:
        return
    try:
        import whois

        data = whois.whois(ctx.domain)
        ctx.whois = {
            "registrar": getattr(data, "registrar", None),
            "creation_date": str(getattr(data, "creation_date", "")),
            "expiration_date": str(getattr(data, "expiration_date", "")),
            "updated_date": str(getattr(data, "updated_date", "")),
            "org": getattr(data, "org", None),
            "country": getattr(data, "country", None),
            "name_servers": sorted(set(str(ns).lower() for ns in (getattr(data, "name_servers", []) or []))),
            "status": str(getattr(data, "status", "")),
        }
    except Exception as exc:
        add_warning(ctx, console, f"WHOIS lookup failed: {exc}")


def _dns(ctx: ScanContext, console) -> None:
    if not ctx.domain:
        return
    try:
        import dns.query
        import dns.resolver
        import dns.reversename
        import dns.zone

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 10

        for record_type in DNS_TYPES:
            try:
                query_target = ctx.domain
                if record_type == "PTR" and ctx.ip_addresses:
                    query_target = dns.reversename.from_address(
                        next(iter(ctx.ip_addresses))
                    ).to_text()
                answers = resolver.resolve(query_target, record_type, lifetime=10)
                ctx.dns_records[record_type] = [answer.to_text() for answer in answers]
            except Exception:
                ctx.dns_records.setdefault(record_type, [])

        # Email security checks
        txt_joined = " ".join(ctx.dns_records.get("TXT", [])).lower()
        if "v=spf1" not in txt_joined:
            add_finding(ctx, "Missing SPF",
                        f"No TXT record containing 'v=spf1' found for {ctx.domain}.",
                        category="Config",
                        references=["https://datatracker.ietf.org/doc/html/rfc7208"])
        try:
            dmarc = resolver.resolve(f"_dmarc.{ctx.domain}", "TXT", lifetime=10)
            ctx.dns_records["DMARC"] = [answer.to_text() for answer in dmarc]
            # Check if policy is set to none (weak)
            dmarc_value = " ".join(ctx.dns_records["DMARC"]).lower()
            if "p=none" in dmarc_value:
                add_finding(ctx, "Missing DMARC",
                            f"DMARC record found but policy is 'none' (monitoring only): {dmarc_value}",
                            category="Config",
                            name="DMARC policy set to none",
                            description="A DMARC record exists but with p=none, meaning spoofed emails are not blocked.")
        except Exception:
            add_finding(ctx, "Missing DMARC",
                        f"No DMARC TXT record found at _dmarc.{ctx.domain}.",
                        category="Config",
                        references=["https://datatracker.ietf.org/doc/html/rfc7489"])

        # Zone transfer attempt against all nameservers
        for ns_raw in ctx.dns_records.get("NS", []):
            ns_host = ns_raw.rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, ctx.domain, lifetime=15))
                names = [item.to_text() for item in zone.nodes.keys()]
                add_finding(ctx, "Zone Transfer allowed",
                            f"AXFR succeeded against {ns_host}.\nSample names ({len(names)} total):\n" + "\n".join(names[:30]),
                            category="Network",
                            references=["https://www.cisa.gov/uscert/ncas/alerts/TA15-119A"])
            except Exception:
                continue

    except Exception as exc:
        add_warning(ctx, console, f"DNS enumeration failed: {exc}")


def _subdomains(ctx: ScanContext, console) -> None:
    if not ctx.domain:
        return
    for label in COMMON_SUBDOMAINS:
        subdomain = f"{label}.{ctx.domain}"
        ips = resolve_host(subdomain)
        if not ips:
            continue
        live = _http_probe(subdomain)
        ctx.subdomains[subdomain] = {"ips": ips, "live": live, "source": "bruteforce"}
        for ip in ips:
            ctx.ip_addresses.add(ip)
        if live:
            add_finding(ctx, "Subdomain found",
                        f"{subdomain} → {', '.join(ips)}\nLive response: {live}",
                        category="Recon",
                        name=f"Live subdomain: {subdomain}")


def _http_probe(host: str) -> str | None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            response = get_url(url, timeout=8)
            if response.status_code < 500:
                return f"{url} (HTTP {response.status_code})"
        except Exception:
            continue
    return None


def _ip_intel(ctx: ScanContext, console) -> None:
    for ip in resolve_host(ctx.host):
        ctx.ip_addresses.add(ip)
    for ip in list(ctx.ip_addresses):
        ptr = reverse_dns(ip)
        if ptr:
            ctx.service_notes.append({"service": "Reverse DNS", "target": ip, "result": ptr})
        # Tor exit node check
        try:
            response = get_url("https://check.torproject.org/torbulkexitlist", timeout=10)
            if ip in response.text.splitlines():
                ctx.service_notes.append({"service": "Tor exit node", "target": ip,
                                           "result": "IP appears in the Tor bulk exit node list"})
        except Exception:
            pass
        # Proxy / VPN check
        try:
            response = get_url(f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1", timeout=10)
            data = response.json() if response.ok else {}
            entry = data.get(ip, {})
            if str(entry.get("proxy", "")).lower() == "yes":
                note = f"Type: {entry.get('type', 'unknown')} | ASN: {entry.get('asn', '')} | Provider: {entry.get('provider', '')}"
                ctx.service_notes.append({"service": "ProxyCheck", "target": ip, "result": note})
        except Exception:
            pass
        # ASN / org lookup via ipinfo.io (no auth needed for basic info)
        try:
            response = get_url(f"https://ipinfo.io/{ip}/json", timeout=10)
            if response.ok:
                info = response.json()
                ctx.service_notes.append({
                    "service": "IP Info",
                    "target": ip,
                    "result": f"ASN: {info.get('org','')} | City: {info.get('city','')} | Country: {info.get('country','')}",
                })
        except Exception:
            pass


def _google_dorks(ctx: ScanContext) -> None:
    target = ctx.domain or ctx.host
    ctx.google_dorks = [
        f'site:{target}',
        f'site:{target} filetype:pdf',
        f'site:{target} filetype:sql OR filetype:bak OR filetype:env OR filetype:log',
        f'site:{target} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:portal',
        f'site:{target} intitle:"index of"',
        f'site:{target} "password" OR "secret" OR "api_key" OR "token"',
        f'site:{target} ext:php intitle:"phpinfo()"',
        f'site:{target} inurl:".git" OR inurl:".svn" OR inurl:".DS_Store"',
        f'site:{target} inurl:wp-content OR inurl:wp-admin',
        f'"@{target}" email',
        f'site:{target} "Internal Server Error" OR "stack trace" OR "exception"',
        f'inurl:"{target}" site:pastebin.com OR site:github.com',
    ]


def _cert_transparency(ctx: ScanContext, console) -> None:
    if not ctx.domain:
        return
    try:
        response = get_url(f"https://crt.sh/?q=%.{ctx.domain}&output=json", timeout=20)
        if response.ok:
            seen: set[str] = set()
            for item in response.json()[:500]:
                name_value = item.get("name_value", "")
                names = sorted({
                    name.strip().lower().lstrip("*.")
                    for name in name_value.splitlines()
                    if name.strip()
                })
                for name in names:
                    if name.endswith(ctx.domain) and name not in seen:
                        seen.add(name)
                        if name not in ctx.subdomains:
                            ips = resolve_host(name)
                            ctx.subdomains[name] = {
                                "ips": ips,
                                "live": None,
                                "source": "crt.sh",
                            }
                            for ip in ips:
                                ctx.ip_addresses.add(ip)
                ctx.certificates.append({
                    "issuer": item.get("issuer_name", ""),
                    "not_before": item.get("not_before", ""),
                    "not_after": item.get("not_after", ""),
                    "serial": item.get("serial_number", ""),
                    "names": names,
                })
    except Exception as exc:
        add_warning(ctx, console, f"Certificate transparency lookup failed: {exc}")

    # Live TLS certificate from the target itself
    if ctx.base_url and ctx.base_url.startswith("https"):
        try:
            cert = tls_certificate(ctx.host)
            ctx.certificates.append(cert)
            days = cert.get("days_until_expiry")
            if days is not None and days < 30:
                add_finding(ctx, "SSL expiring soon",
                            f"Certificate for {ctx.host} expires in {days} days.\nNot after: {cert.get('not_after')}",
                            category="Config")
            # Weak TLS version check
            tls_ver = cert.get("tls_version", "")
            if tls_ver in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                add_finding(ctx, "Weak TLS",
                            f"Negotiated protocol: {tls_ver}\nCipher: {cert.get('cipher')}",
                            category="Config",
                            references=["https://www.rfc-editor.org/rfc/rfc8996"])
        except Exception:
            pass


def _technology_fingerprint(ctx: ScanContext, console) -> None:
    if not ctx.base_url:
        return
    try:
        response = get_url(ctx.base_url)
        headers = {key.lower(): value for key, value in response.headers.items()}
        html = response.text[:300_000]
        header_blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        techs: set[str] = set()

        # Server / X-Powered-By header disclosure
        server = headers.get("server")
        powered = headers.get("x-powered-by")
        if server:
            techs.add(f"Server: {server}")
            add_finding(ctx, "Server header disclosure",
                        f"Server: {server}",
                        category="Config",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"])
        if powered:
            techs.add(f"X-Powered-By: {powered}")
            add_finding(ctx, "Server header disclosure",
                        f"X-Powered-By: {powered}",
                        category="Config",
                        name="X-Powered-By disclosure")

        # HTML + header pattern fingerprinting
        for pattern, tech_name in TECH_PATTERNS:
            if re.search(pattern, html, re.I) or re.search(pattern, header_blob, re.I):
                techs.add(tech_name)

        # WAF / CDN detection
        for header_key, waf_name in WAF_HEADERS.items():
            if header_key in headers:
                techs.add(f"WAF/CDN: {waf_name}")

        ctx.technologies.update(techs)
        for tech in techs:
            add_finding(ctx, "Technology fingerprint", tech, category="Recon",
                        name=f"Technology detected: {tech}")

    except Exception as exc:
        add_warning(ctx, console, f"Technology fingerprinting failed: {exc}")


def _harvest_page_content(ctx: ScanContext, console) -> None:
    """Scan crawled URLs and inline JS for email addresses and hardcoded secrets."""
    if not ctx.base_url:
        return
    urls_to_scan = list(dict.fromkeys(
        ([ctx.base_url] if ctx.base_url else []) + ctx.crawl.get("scripts", [])
    ))[:60]

    found_emails: set[str] = set()
    found_secrets: list[dict] = []

    for url in urls_to_scan:
        try:
            response = get_url(url, timeout=10)
            body = response.text
        except Exception:
            continue

        # Email harvest
        for email in EMAIL_PATTERN.findall(body):
            # Filter obvious false positives
            if any(skip in email.lower() for skip in ("example.com", "test.com", "sentry.io", "schema.org")):
                continue
            found_emails.add(email.lower())

        # Secret detection in JS / HTML
        for pattern, label in JS_SECRET_PATTERNS:
            for match in re.finditer(pattern, body):
                value = match.group(0)[:120]
                found_secrets.append({"url": url, "type": label, "snippet": value})

    # Deduplicate and store
    for email in found_emails:
        ctx.crawl["emails"].append(email)
    if found_emails:
        add_finding(ctx, "Email Address Harvested",
                    "Emails found in page content:\n" + "\n".join(sorted(found_emails)[:50]),
                    category="Recon")

    # Report unique secrets (deduplicated by snippet prefix)
    seen_snippets: set[str] = set()
    for secret in found_secrets:
        key = secret["snippet"][:40]
        if key in seen_snippets:
            continue
        seen_snippets.add(key)
        ctx.crawl["js_secrets"].append(secret)
        add_finding(ctx, "JS Secret Detected",
                    f"Type: {secret['type']}\nSource: {secret['url']}\nSnippet: {secret['snippet']}",
                    category="Config",
                    name=f"Potential {secret['type']} in source",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"])