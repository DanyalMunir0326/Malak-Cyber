# active_recon.py
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse



from .utils import ScanContext, add_finding, add_warning, get_url, head_url


HIGH_RISK_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    69: "TFTP", 79: "Finger", 80: "HTTP", 110: "POP3", 111: "RPCBind",
    119: "NNTP", 135: "RPC/DCOM", 137: "NetBIOS-NS", 138: "NetBIOS-DGM",
    139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 512: "rexec",
    513: "rlogin", 514: "rsh/syslog", 515: "LPD", 587: "SMTP Submission",
    631: "IPP (CUPS)", 636: "LDAPS", 873: "rsync",
    1080: "SOCKS Proxy", 1099: "Java RMI", 1433: "MSSQL",
    1521: "Oracle DB", 1723: "PPTP VPN", 2049: "NFS",
    2375: "Docker API (unencrypted)", 2376: "Docker API (TLS)",
    3000: "Dev server / Grafana", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit default listener", 4848: "GlassFish Admin",
    5000: "Flask dev / Docker Registry", 5432: "PostgreSQL",
    5900: "VNC", 5984: "CouchDB", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    6379: "Redis", 7001: "WebLogic", 8009: "Apache AJP",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Jupyter Notebook",
    9000: "PHP-FPM / Portainer", 9090: "Prometheus", 9200: "Elasticsearch",
    9300: "Elasticsearch inter-node", 10250: "Kubernetes Kubelet",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB shard",
    50000: "SAP ICM", 50070: "Hadoop NameNode WebUI",
}

SENSITIVE_PATHS = [
    # VCS exposure
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/index",
    "/.git/logs/HEAD", "/.svn/entries", "/.svn/wc.db", "/.hg/store/00manifest.i",
    # Environment / config
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/config.json", "/config.yml", "/config.yaml",
    "/settings.py", "/settings.php", "/configuration.php",
    "/local_settings.py", "/database.yml", "/database.php",
    "/app.config", "/web.config", "/appsettings.json",
    # CMS
    "/wp-config.php", "/wp-login.php", "/wp-admin/", "/wp-admin/admin-ajax.php",
    "/wp-json/wp/v2/users",
    # Admin panels
    "/admin/", "/admin/login", "/admin/index.php", "/administrator/",
    "/administration/", "/adminpanel/",
    "/panel/", "/cpanel/", "/whm/", "/plesk/",
    "/phpmyadmin/", "/phpmyadmin/index.php", "/adminer/", "/dbadmin/",
    "/h2-console", "/console",
    # Backup / dumps
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/dump.sql", "/site.zip", "/www.zip", "/backup.bak",
    "/database.sql", "/db_backup.sql",
    # Debug / info pages
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info", "/status",
    "/elmah.axd", "/trace.axd", "/glimpse.axd",
    # API discovery
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/api/swagger", "/swagger.json", "/swagger.yaml",
    "/swagger-ui.html", "/swagger-ui/", "/openapi.json", "/openapi.yaml",
    "/graphql", "/graphiql", "/api/graphql",
    "/api-docs", "/api-docs/swagger.json",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/beans", "/actuator/mappings", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/loggers",
    # Metrics / monitoring
    "/metrics", "/health", "/healthz", "/readyz", "/livez",
    "/jolokia", "/jolokia/list",
    # Security / compliance
    "/.well-known/security.txt", "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/.htaccess", "/.htpasswd",
    # Misc sensitive
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/web.config.bak", "/application.wadl",
    "/druid/index.html", "/druid/datasource.json",
]


def run(ctx: ScanContext, console) -> None:
    from .wizard import PhaseProgress
    with PhaseProgress(console, "Phase 2 - Active Reconnaissance") as pp:
        pp.step("Port scan  (nmap SYN scan · top 1000 ports · service/version detection · OS detection · NSE scripts)")
        _port_scan(ctx, console)

        if ctx.base_url:
            pp.step(f"Web crawl  (BFS up to depth 4 · forms · inline JS · API endpoints · HTML comments)")
            _web_crawl(ctx, console)

            pp.step(f"Directory brute-force  ({len(SENSITIVE_PATHS)} sensitive paths · soft-404 baseline filtering)")
            _directory_bruteforce(ctx, console)
        else:
            pp.warn("No HTTP base URL — skipping web crawl and directory brute-force")

        pp.done()


def _port_scan(ctx: ScanContext, console) -> None:
    try:
        import nmap

        scanner = nmap.PortScanner()
        # -sS  SYN scan (requires root/admin)
        # -sV  service/version detection, intensity 5 = thorough without max aggression
        # -O   OS detection
        # --traceroute  path mapping
        # -T3  normal timing (T4 can cause packet loss on rate-limited hosts)
        # --top-ports 1000  broader coverage than 200
        # --script  banner grabs, common safe NSE scripts
        # --open  only show open ports in output
        args = (
            "-sS -sV --version-intensity 5 -O --traceroute "
            "-T3 --top-ports 1000 --open "
            "--script=banner,http-title,ssl-cert,smtp-commands,ftp-anon,ssh-hostkey"
        )
        scanner.scan(ctx.host, arguments=args)
        ctx.raw_outputs["nmap"] = scanner.csv()

        for host in scanner.all_hosts():
            host_data = scanner[host]
            if "trace" in host_data:
                ctx.traceroute = str(host_data["trace"])

            # OS detection
            osmatch = host_data.get("osmatch", [])
            if osmatch:
                best = osmatch[0]
                ctx.service_notes.append({
                    "service": "OS Detection",
                    "target": host,
                    "result": f"{best.get('name', '')} (accuracy {best.get('accuracy', '')}%)",
                })

            for proto in ("tcp", "udp"):
                if proto not in host_data:
                    continue
                for port, data in host_data[proto].items():
                    if data.get("state") != "open":
                        continue
                    port_int = int(port)
                    # Collect NSE script output
                    script_output = ""
                    if "script" in data:
                        script_output = "\n".join(
                            f"  [{name}]: {out}"
                            for name, out in data["script"].items()
                        )
                    record = {
                        "host": host,
                        "port": port,
                        "protocol": proto.upper(),
                        "service": data.get("name", ""),
                        "version": " ".join(filter(None, [
                            data.get("product", ""),
                            data.get("version", ""),
                            data.get("extrainfo", ""),
                        ])),
                        "risk": HIGH_RISK_PORTS.get(port_int, ""),
                        "script_output": script_output,
                    }
                    ctx.open_ports.append(record)

                    # Per-port findings
                    if port_int == 23:
                        add_finding(ctx, "Telnet open",
                                    f"nmap: TCP/23 open on {host}\n{script_output}",
                                    category="Network",
                                    references=["https://cwe.mitre.org/data/definitions/319.html"])
                    if port_int == 21 and "ftp-anon" in data.get("script", {}):
                        if "Login with username" in data["script"].get("ftp-anon", ""):
                            add_finding(ctx, "Anonymous FTP login",
                                        f"nmap ftp-anon script confirmed anonymous FTP on {host}:21\n{data['script']['ftp-anon']}",
                                        category="Network")
                    if port_int in HIGH_RISK_PORTS:
                        ctx.service_notes.append({
                            "service": "High-risk open port",
                            "target": f"{host}:{port}",
                            "result": HIGH_RISK_PORTS[port_int],
                        })
    except Exception as exc:
        add_warning(ctx, console, f"Port scan failed: {exc}")


def _web_crawl(ctx: ScanContext, console) -> None:
    if not ctx.base_url:
        return
    try:
        from bs4 import BeautifulSoup, Comment

        queue: deque[tuple[str, int]] = deque([(ctx.base_url, 0)])
        seen: set[str] = set()
        base_netloc = urlparse(ctx.base_url).netloc

        while queue and len(seen) < 400:
            url, depth = queue.popleft()
            if url in seen or depth > 4:
                continue
            seen.add(url)

            try:
                response = get_url(url, timeout=12)
            except Exception:
                continue

            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            ctx.crawl["urls"].append(url)
            ctx.crawl["sitemap"].append(urlparse(url).path or "/")

            # Form enumeration
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or "")
                ctx.crawl["forms"].append({
                    "page": url,
                    "action": action,
                    "method": (form.get("method") or "GET").upper(),
                    "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
                    "inputs": [
                        {
                            "name": field.get("name") or field.get("id", ""),
                            "type": field.get("type", field.name),
                        }
                        for field in form.find_all(["input", "textarea", "select"])
                    ],
                })

            # JavaScript files
            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    ctx.crawl["scripts"].append(urljoin(url, src))
                # Inline JS secret scanning
                inline = script.string or ""
                if inline and len(inline) > 20:
                    _scan_inline_js(ctx, url, inline)

            # HTML comments
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                comment_text = str(comment).strip()
                if re.search(r"TODO|FIXME|password|secret|key|token|debug|internal|admin", comment_text, re.I):
                    ctx.crawl["comments"].append({
                        "page": url,
                        "comment": comment_text[:600],
                    })

            # API endpoint detection in source
            for match in re.findall(
                r'["\']([^"\']{1,200}(?:/api/|/v\d+/|/graphql|/rest/|/rpc/)[^"\']*)["\']',
                response.text, re.I,
            ):
                endpoint = urljoin(url, match)
                if endpoint not in ctx.crawl["api_endpoints"]:
                    ctx.crawl["api_endpoints"].append(endpoint)

            # Link following
            for anchor in soup.find_all("a", href=True):
                next_url = urljoin(url, anchor["href"]).split("#")[0].split("?")[0]
                parsed = urlparse(next_url)
                if (parsed.netloc == base_netloc
                        and parsed.scheme in {"http", "https"}
                        and next_url not in seen):
                    queue.append((next_url, depth + 1))

    except Exception as exc:
        add_warning(ctx, console, f"Web crawl failed: {exc}")


def _scan_inline_js(ctx: ScanContext, page_url: str, js_code: str) -> None:
    """Check inline JavaScript for hardcoded secrets."""
    from .passive_recon import JS_SECRET_PATTERNS
    for pattern, label in JS_SECRET_PATTERNS:
        for match in re.finditer(pattern, js_code):
            snippet = match.group(0)[:120]
            ctx.crawl["js_secrets"].append({"url": page_url, "type": label, "snippet": snippet})
            add_finding(
                ctx, "JS Secret Detected",
                f"Type: {label}\nFound in inline JS on: {page_url}\nSnippet: {snippet}",
                category="Config",
                name=f"Potential {label} in inline JS",
            )
            break  # one finding per pattern per page is enough


def _directory_bruteforce(ctx: ScanContext, console) -> None:
    if not ctx.base_url:
        return

    # Baseline: fingerprint the 404 response to reduce false positives
    baseline_404_len = None
    try:
        r = get_url(urljoin(ctx.base_url, "/__malak_nonexistent_probe_12345__"))
        baseline_404_len = len(r.text)
    except Exception:
        pass

    for path in SENSITIVE_PATHS:
        url = urljoin(ctx.base_url, path)
        try:
            response = head_url(url)
            # If HEAD not supported, fall back to GET
            if response.status_code in {405, 501}:
                response = get_url(url)

            status = response.status_code
            if status not in {200, 301, 302, 403, 401}:
                continue

            # Skip if response length matches the 404 baseline (soft 404)
            if status == 200 and baseline_404_len is not None:
                try:
                    full = get_url(url)
                    if abs(len(full.text) - baseline_404_len) < 50:
                        continue
                except Exception:
                    continue

            location = response.headers.get("Location", "")
            item = {"path": path, "url": url, "status": status, "location": location}
            ctx.sensitive_paths.append(item)
            evidence = f"Request: HEAD {url}\nStatus: {status}\nLocation: {location}"

            if "/.git" in path:
                add_finding(ctx, "Git repo exposed", evidence, category="Config",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"])
            elif path in {
                "/.env", "/.env.local", "/.env.production", "/.env.backup",
                "/config.php", "/config.json", "/config.yml", "/config.yaml",
                "/settings.py", "/wp-config.php", "/backup.sql", "/db.sql",
                "/database.yml", "/appsettings.json",
            } and status == 200:
                add_finding(ctx, "Exposed config", evidence, category="Config")
            elif status == 403:
                add_finding(ctx, "Sensitive file exposed", evidence, category="Config",
                            name=f"Restricted resource exists: {path}",
                            description="HTTP 403 indicates the resource exists but is access-restricted. Authentication bypass or misconfiguration may expose it.")
            else:
                add_finding(ctx, "Sensitive file exposed", evidence, category="Config",
                            name=f"Sensitive path accessible: {path}")

        except Exception:
            continue