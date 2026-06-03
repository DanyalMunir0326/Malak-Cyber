# enumeration.py
from __future__ import annotations

import ftplib
import re
import socket



from .utils import ScanContext, add_finding, add_warning, get_url, tcp_banner


def run(ctx: ScanContext, console) -> None:
    from .wizard import PhaseProgress

    # Build a human-readable label for each open port
    SERVICE_LABELS: dict[int, str] = {
        21: "FTP  — banner grab · anonymous login · upload test",
        22: "SSH  — banner + version · weak cipher check (paramiko)",
        25: "SMTP — EHLO · VRFY/EXPN enumeration · open relay test",
        53: "DNS  — version.bind · hostname.bind (CHAOS queries)",
        69: "TFTP — unauthenticated read probe",
        111: "RPCBind — portmapper DUMP",
        139: "SMB  — SMBv1 negotiate probe",
        161: "SNMP — public community string GET",
        389: "LDAP — anonymous bind attempt",
        445: "SMB  — SMBv1 negotiate probe",
        465: "SMTPS — EHLO · VRFY · open relay test",
        587: "SMTP Submission — EHLO · VRFY · open relay test",
        636: "LDAPS — anonymous bind attempt",
        873: "rsync — daemon module listing",
        3389: "RDP  — NLA negotiation probe",
        5900: "VNC  — protocol version banner",
        6379: "Redis — INFO · CONFIG GET · KEYS *",
        9200: "Elasticsearch — cluster health · index listing · node info",
        11211: "Memcached — unauthenticated stats",
        27017: "MongoDB — unauthenticated database listing",
        2375: "Docker API — version · containers · images",
        4848: "GlassFish — admin console probe",
        8888: "Jupyter Notebook — unauthenticated access probe",
        9090: "Prometheus — metrics endpoint probe",
        10250: "Kubernetes Kubelet — pod listing probe",
    }

    with PhaseProgress(console, "Phase 3 - Service Enumeration") as pp:
        if not ctx.open_ports:
            pp.warn("No open ports detected — skipping service enumeration")
        else:
            pp.step(f"Preparing to enumerate {len(ctx.open_ports)} open port(s)")
            for port in ctx.open_ports:
                number = int(port["port"])
                host   = port.get("host") or ctx.host
                label  = SERVICE_LABELS.get(number, f"Port {number}/{port.get('protocol','TCP')} — {port.get('service','')} {port.get('version','')}".strip())
                pp.step(f"{host}:{number}  →  {label}")
                try:
                    _enumerate_port(ctx, port)
                except Exception as exc:
                    pp.warn(f"Enumeration error on port {number}: {exc}")
        pp.done()


def _enumerate_port(ctx: ScanContext, port: dict) -> None:
    number = int(port["port"])
    host = port.get("host") or ctx.host

    dispatch = {
        21: _ftp,
        22: _ssh,
        25: lambda c, h: _smtp(c, h, 25),
        53: _dns,
        69: _tftp,
        111: _rpcbind,
        139: _smb,
        161: _snmp,
        389: lambda c, h: _ldap(c, h, 389),
        445: _smb,
        465: lambda c, h: _smtp(c, h, 465),
        587: lambda c, h: _smtp(c, h, 587),
        636: lambda c, h: _ldap(c, h, 636),
        873: _rsync,
        3389: _rdp,
        5900: _vnc,
        6379: _redis,
        11211: _memcached,
        27017: _mongodb,
        9200: lambda c, h: (
            _http_api(c, "Unauthenticated Elasticsearch", f"http://{h}:9200/_cluster/health", "Elasticsearch cluster health"),
            _http_api(c, "Unauthenticated Elasticsearch", f"http://{h}:9200/_cat/indices?v", "Elasticsearch index list"),
            _http_api(c, "Unauthenticated Elasticsearch", f"http://{h}:9200/_nodes", "Elasticsearch node info"),
        ),
        2375: lambda c, h: (
            _http_api(c, "Docker API open", f"http://{h}:2375/version", "Docker version"),
            _http_api(c, "Docker API open", f"http://{h}:2375/containers/json?all=true", "Docker containers"),
            _http_api(c, "Docker API open", f"http://{h}:2375/images/json", "Docker images"),
        ),
        5984: lambda c, h: (
            _http_api(c, "Unauthenticated MongoDB", f"http://{h}:5984/_all_dbs", "CouchDB databases"),
            _http_api(c, "Unauthenticated MongoDB", f"http://{h}:5984/_config", "CouchDB config"),
        ),
        4848: lambda c, h: _http_api(c, "Sensitive file exposed", f"http://{h}:4848", "GlassFish admin console"),
        8888: lambda c, h: _http_api(c, "Sensitive file exposed", f"http://{h}:8888", "Jupyter Notebook"),
        9090: lambda c, h: _http_api(c, "Sensitive file exposed", f"http://{h}:9090/metrics", "Prometheus metrics"),
        10250: lambda c, h: _http_api(c, "Sensitive file exposed", f"https://{h}:10250/pods", "Kubernetes Kubelet"),
    }

    if number in dispatch:
        dispatch[number](ctx, host)
    elif number in {1433, 1521, 3306, 5432, 5984}:
        ctx.service_notes.append({
            "service": "Database port open",
            "target": f"{host}:{number}",
            "result": (
                f"{port.get('service', 'DB')} {port.get('version', '')} open. "
                "Verify authentication posture with approved credentials."
            ),
        })


# ── Service handlers ──────────────────────────────────────────────────────────

def _ftp(ctx: ScanContext, host: str) -> None:
    try:
        ftp = ftplib.FTP(host, timeout=10)
        banner = ftp.getwelcome()
        ctx.service_notes.append({"service": "FTP banner", "target": host, "result": banner})

        # Version disclosure check
        if re.search(r"ProFTPD 1\.[0-2]\.|vsftpd [12]\.", banner, re.I):
            add_finding(ctx, "Outdated SSH version",
                        f"FTP banner discloses potentially outdated version: {banner}",
                        category="Network",
                        name="Outdated FTP version detected")

        # Anonymous login attempt
        try:
            ftp.login("anonymous", "malak-scanner@test.invalid")
            entries: list[str] = []
            ftp.retrlines("LIST", entries.append)
            evidence = f"Anonymous FTP login succeeded on {host}:21\nWelcome: {banner}\nDirectory listing (first 25 entries):\n" + "\n".join(entries[:25])
            add_finding(ctx, "Anonymous FTP login", evidence, category="Network",
                        references=["https://cwe.mitre.org/data/definitions/287.html"])

            # Upload permission test
            try:
                import io
                ftp.storbinary("STOR malak-scanner-permtest.txt", io.BytesIO(b"write permission test"))
                add_finding(ctx, "Anonymous FTP login",
                            "Anonymous FTP upload succeeded on {host}:21 — write permissions confirmed.",
                            category="Network",
                            name="Anonymous FTP upload allowed")
                # Clean up
                try:
                    ftp.delete("malak-scanner-permtest.txt")
                except Exception:
                    pass
            except ftplib.error_perm:
                pass
        except ftplib.error_perm:
            pass
        finally:
            try:
                ftp.quit()
            except Exception:
                pass
    except Exception:
        return


def _ssh(ctx: ScanContext, host: str) -> None:
    banner = tcp_banner(host, 22)
    ctx.service_notes.append({"service": "SSH banner", "target": host, "result": banner})

    # OpenSSH version check — recommend < 8.0 as outdated for conservative threshold
    match = re.search(r"OpenSSH[_ -](\d+)\.(\d+)", banner)
    if match:
        major, minor = int(match.group(1)), int(match.group(2))
        if (major, minor) < (8, 0):
            add_finding(ctx, "Outdated SSH version",
                        f"SSH banner: {banner}\nDetected version: OpenSSH {major}.{minor} (recommend >= 8.0)",
                        category="Network",
                        references=["https://www.openssh.com/releasenotes.html"])

    # Algorithm enumeration via SSH2_MSG_KEXINIT probe
    try:
        import paramiko
        transport = paramiko.Transport((host, 22))
        transport.start_client(timeout=10)
        security_opts = transport.get_security_options()
        kex = list(security_opts.kex)
        ciphers = list(security_opts.ciphers)
        weak_ciphers = [c for c in ciphers if re.search(r"arcfour|3des|blowfish|cast|rc4|cbc", c, re.I)]
        if weak_ciphers:
            add_finding(ctx, "Weak TLS",
                        f"Weak SSH ciphers offered: {', '.join(weak_ciphers)}\nAll ciphers: {', '.join(ciphers)}",
                        category="Network",
                        name="Weak SSH cipher suites",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2008-5161"])
        transport.close()
    except Exception:
        pass


def _smtp(ctx: ScanContext, host: str, port: int) -> None:
    try:
        import smtplib

        smtp = smtplib.SMTP(host, port, timeout=10)
        banner_code, banner_msg = smtp.ehlo()
        ehlo_response = smtp.ehlo_resp.decode("utf-8", "replace") if smtp.ehlo_resp else ""
        results = [f"EHLO banner: {banner_msg}", f"EHLO extensions:\n{ehlo_response}"]

        # VRFY enumeration test (check user existence leakage)
        for test_user in ("root", "admin", "postmaster"):
            try:
                code, msg = smtp.docmd("VRFY", test_user)
                results.append(f"VRFY {test_user}: {code} {msg!r}")
                if code in {250, 252}:
                    add_finding(ctx, "SMTP User Enumeration",
                                f"VRFY {test_user} on {host}:{port} returned {code}: {msg!r}",
                                category="Network",
                                references=["https://datatracker.ietf.org/doc/html/rfc5321"])
                    break
            except Exception:
                pass

        # EXPN test
        try:
            code, msg = smtp.docmd("EXPN", "root")
            results.append(f"EXPN root: {code} {msg!r}")
        except Exception:
            pass

        # Open relay test — attempt to relay from external to external address
        try:
            code, msg = smtp.docmd("MAIL FROM:<test@external-malak-test.invalid>")
            if code == 250:
                code2, msg2 = smtp.docmd("RCPT TO:<relay-test@external-malak-test.invalid>")
                if code2 == 250:
                    add_finding(ctx, "SMTP open relay",
                                f"Open relay test: MAIL FROM external accepted (250), RCPT TO external also accepted (250).\n"
                                f"Host: {host}:{port}",
                                category="Network",
                                references=["https://www.rfc-editor.org/rfc/rfc2505"])
        except Exception:
            pass

        smtp.quit()
        ctx.service_notes.append({
            "service": "SMTP enumeration",
            "target": f"{host}:{port}",
            "result": "\n".join(results),
        })
    except Exception:
        return


def _dns(ctx: ScanContext, host: str) -> None:
    try:
        import dns.message
        import dns.query
        import dns.rdatatype

        # version.bind query (CHAOS class) — reveals BIND version if not suppressed
        query = dns.message.make_query("version.bind", dns.rdatatype.TXT, "CH")
        response = dns.query.udp(query, host, timeout=10)
        response_text = str(response)[:1000]
        ctx.service_notes.append({
            "service": "DNS version.bind",
            "target": host,
            "result": response_text,
        })
        if re.search(r"BIND\s+\d+\.\d+\.\d+", response_text, re.I):
            add_finding(ctx, "Server header disclosure",
                        f"DNS server revealed BIND version via version.bind query:\n{response_text}",
                        category="Config",
                        name="DNS version disclosure (version.bind)")

        # hostname.bind query — reveals server identity
        try:
            hquery = dns.message.make_query("hostname.bind", dns.rdatatype.TXT, "CH")
            hresponse = dns.query.udp(hquery, host, timeout=10)
            ctx.service_notes.append({
                "service": "DNS hostname.bind",
                "target": host,
                "result": str(hresponse)[:500],
            })
        except Exception:
            pass
    except Exception:
        return


def _smb(ctx: ScanContext, host: str) -> None:
    # Attempt to retrieve the raw SMB negotiate response to check for SMBv1
    try:
        # SMBv1 negotiate request (raw bytes)
        smb1_negotiate = (
            b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18"
            b"\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43"
            b"\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52"
            b"\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e"
            b"\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66"
            b"\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20"
            b"\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30"
            b"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02"
            b"\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
        )
        with socket.create_connection((host, 445), timeout=10) as sock:
            sock.sendall(smb1_negotiate)
            response = sock.recv(4096)
            hex_resp = response.hex()
            # If the response contains SMB1 dialect index != 0xFF (no support), SMBv1 is active
            if b"\xff\x53\x4d\x42" in response:
                ctx.service_notes.append({"service": "SMB", "target": host, "result": "SMBv1 negotiate response received"})
                add_finding(ctx, "SMBv1",
                            f"SMBv1 negotiate frame accepted on {host}:445.\nHex sample: {hex_resp[:120]}",
                            category="Network",
                            cve="CVE-2017-0144",
                            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                                        "https://www.cisa.gov/uscert/ncas/alerts/TA17-132A"])
            else:
                ctx.service_notes.append({"service": "SMB", "target": host,
                                           "result": "SMBv1 not negotiated; likely SMBv2/v3 only."})
    except Exception:
        ctx.service_notes.append({
            "service": "SMB",
            "target": host,
            "result": "SMB port open; manual review recommended for share enumeration, signing config, and NTLMv1.",
        })


def _rdp(ctx: ScanContext, host: str) -> None:
    # RDP CONNECT request to check if NLA (Network Level Authentication) is enforced
    try:
        # RDP Connection Request PDU (minimal TPKT + X.224 COTP)
        rdp_cr = (
            b"\x03\x00\x00\x13"     # TPKT header, length 19
            b"\x0e\xd0\x00\x00\x00\x00\x00"  # COTP CR
            b"\x00\x00\x00\x00\x00\x00"       # padding
        )
        with socket.create_connection((host, 3389), timeout=10) as sock:
            sock.sendall(rdp_cr)
            data = sock.recv(1024)
            if data:
                # Byte offset 11 = selectedProtocol; 0x02 = CredSSP/NLA required
                nla_required = len(data) > 11 and (data[11] & 0x02)
                if not nla_required:
                    add_finding(ctx, "RDP NLA disabled",
                                f"RDP on {host}:3389 responded without requiring NLA.\nRaw hex: {data[:32].hex()}",
                                category="Network",
                                references=["https://docs.microsoft.com/en-us/windows/win32/termserv/network-level-authentication"])
                ctx.service_notes.append({
                    "service": "RDP probe",
                    "target": host,
                    "result": f"NLA required: {bool(nla_required)} | Raw: {data[:32].hex()}",
                })
    except Exception as exc:
        banner = tcp_banner(host, 3389)
        ctx.service_notes.append({
            "service": "RDP probe",
            "target": host,
            "result": banner or f"RDP TCP connection accepted ({exc}); NLA status requires protocol negotiation.",
        })


def _redis(ctx: ScanContext, host: str) -> None:
    try:
        with socket.create_connection((host, 6379), timeout=10) as sock:
            # Send INFO first
            sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
            info_data = sock.recv(8192).decode("utf-8", "replace")

            if "redis_version" not in info_data.lower():
                return

            evidence_parts = [f"Redis INFO response (first 2000 chars):\n{info_data[:2000]}"]

            # Attempt CONFIG GET to confirm write-level access
            sock.sendall(b"*3\r\n$6\r\nCONFIG\r\n$3\r\nGET\r\n$3\r\ndir\r\n")
            config_data = sock.recv(4096).decode("utf-8", "replace")
            evidence_parts.append(f"\nCONFIG GET dir response:\n{config_data[:500]}")

            # Attempt KEYS * (dangerous on large instances; sends but doesn't wait for full response)
            sock.sendall(b"*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n")
            keys_data = b""
            sock.settimeout(3)
            try:
                keys_data = sock.recv(4096)
            except socket.timeout:
                pass
            evidence_parts.append(f"\nKEYS * sample:\n{keys_data[:500].decode('utf-8','replace')}")

            add_finding(ctx, "Unauthenticated Redis",
                        "\n".join(evidence_parts),
                        category="Network",
                        cve="CVE-2022-0543",
                        references=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
                            "https://redis.io/docs/management/security/",
                        ])
    except Exception:
        return


def _mongodb(ctx: ScanContext, host: str) -> None:
    try:
        import pymongo

        client = pymongo.MongoClient(
            host, 27017,
            serverSelectionTimeoutMS=10_000,
            connectTimeoutMS=10_000,
        )
        dbs = client.list_database_names()
        # Attempt to count collections in each DB
        db_summary = []
        for db_name in dbs[:10]:
            try:
                colls = client[db_name].list_collection_names()
                db_summary.append(f"  {db_name}: {len(colls)} collections — {colls[:5]}")
            except Exception:
                db_summary.append(f"  {db_name}: (collection list failed)")
        add_finding(ctx, "Unauthenticated MongoDB",
                    f"list_database_names() succeeded — {len(dbs)} databases:\n" + "\n".join(db_summary),
                    category="Network",
                    references=["https://www.mongodb.com/docs/manual/administration/security-checklist/"])
        client.close()
    except ImportError:
        ctx.service_notes.append({
            "service": "MongoDB",
            "target": host,
            "result": "Open MongoDB port; install pymongo to attempt unauthenticated enumeration.",
        })
    except Exception:
        ctx.service_notes.append({
            "service": "MongoDB",
            "target": host,
            "result": "MongoDB port open; authentication appears to be required or connection was refused.",
        })


def _http_api(ctx: ScanContext, finding_key: str, url: str, label: str) -> None:
    try:
        response = get_url(url, timeout=10)
        if response.status_code == 200:
            add_finding(ctx, finding_key,
                        f"GET {url}\nStatus: 200\nContent-Type: {response.headers.get('Content-Type','')}\nBody sample:\n{response.text[:3000]}",
                        category="Network",
                        name=label)
    except Exception:
        return


def _memcached(ctx: ScanContext, host: str) -> None:
    try:
        with socket.create_connection((host, 11211), timeout=10) as sock:
            sock.sendall(b"stats\r\n")
            data = sock.recv(8192).decode("utf-8", "replace")
            if "STAT" not in data:
                return
            # Also try to dump a slab key
            sock.sendall(b"stats items\r\n")
            items_data = sock.recv(4096).decode("utf-8", "replace")
            add_finding(ctx, "Unauthenticated Memcached",
                        f"Memcached stats response from {host}:11211:\n{data[:2000]}\n\nstats items:\n{items_data[:500]}",
                        category="Network",
                        references=["https://www.cvedetails.com/cve/CVE-2011-4972/"])
    except Exception:
        return


def _vnc(ctx: ScanContext, host: str) -> None:
    banner = tcp_banner(host, 5900)
    ctx.service_notes.append({"service": "VNC handshake", "target": host, "result": banner})
    # VNC 3.3 handshake: bytes 0–11 = "RFB 003.003\n", security type byte at offset 12
    if banner.startswith("RFB"):
        # Security type 1 = None (no auth), 2 = VNC auth
        if "003.003" in banner or "003.007" in banner:
            add_finding(ctx, "Sensitive file exposed",
                        f"VNC server on {host}:5900 uses legacy RFB protocol version: {banner[:20]}",
                        category="Network",
                        name="VNC legacy protocol version",
                        description="Older RFB protocol versions have weaker security negotiation and may allow auth bypass.")


def _snmp(ctx: ScanContext, host: str) -> None:
    """SNMPv1 GetRequest with community string 'public'."""
    # Minimal SNMPv1 GetRequest for sysDescr (OID .1.3.6.1.2.1.1.1.0)
    snmp_get_public = bytes.fromhex(
        "302602010004067075626c6963a01902043f8d0b5302010002010030"
        "0b300906052b060102010101000500"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(snmp_get_public, (host, 161))
            data, _ = sock.recvfrom(4096)
            if data:
                add_finding(ctx, "Sensitive file exposed",
                            f"SNMP on {host}:161 responded to public community string GetRequest.\nHex: {data[:80].hex()}",
                            category="Network",
                            name="SNMP public community string accepted",
                            description="SNMPv1/v2c with community string 'public' exposes system information and may allow write access with 'private'.",
                            references=["https://cwe.mitre.org/data/definitions/326.html"])
    except Exception:
        return


def _ldap(ctx: ScanContext, host: str, port: int) -> None:
    """Attempt an anonymous LDAP bind and check for information disclosure."""
    try:
        # Anonymous bind: LDAP BindRequest (version 3, anonymous)
        ldap_anon_bind = bytes.fromhex(
            "300c020101600702013003800000"
        )
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.sendall(ldap_anon_bind)
            response = sock.recv(1024)
            # Successful bind response code = 0x00 in resultCode
            if response and len(response) > 7 and response[7:8] in (b"\x00", b"\x0a"):
                add_finding(ctx, "Sensitive file exposed",
                            f"LDAP anonymous bind accepted on {host}:{port}.\nRaw response hex: {response[:40].hex()}",
                            category="Network",
                            name="LDAP anonymous bind allowed",
                            description="Anonymous LDAP bind permits unauthenticated directory enumeration.")
            else:
                ctx.service_notes.append({"service": f"LDAP:{port}", "target": host,
                                           "result": "Anonymous bind rejected (authentication required)."})
    except Exception:
        ctx.service_notes.append({
            "service": f"LDAP:{port}",
            "target": host,
            "result": "LDAP port open; anonymous bind test inconclusive.",
        })


def _rsync(ctx: ScanContext, host: str) -> None:
    """Check if rsync is accessible without authentication."""
    banner = tcp_banner(host, 873, payload=b"@RSYNCD: 31.0\n")
    if banner and "RSYNCD" in banner.upper():
        ctx.service_notes.append({"service": "rsync", "target": host, "result": banner})
        add_finding(ctx, "Sensitive file exposed",
                    f"rsync daemon on {host}:873 responded:\n{banner[:500]}",
                    category="Network",
                    name="rsync daemon exposed",
                    description="An exposed rsync daemon may allow unauthenticated file listing or download.")


def _tftp(ctx: ScanContext, host: str) -> None:
    """Send a TFTP read request for a known file to test if the service responds."""
    # TFTP RRQ for /etc/passwd in octet mode
    rrq = b"\x00\x01/etc/passwd\x00octet\x00"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(rrq, (host, 69))
            data, _ = sock.recvfrom(1024)
            if data and data[1:2] in (b"\x03", b"\x05"):  # DATA or ERROR
                add_finding(ctx, "Sensitive file exposed",
                            f"TFTP on {host}:69 responded to /etc/passwd RRQ.\nOpcode: {data[1]}\nData: {data[:80].hex()}",
                            category="Network",
                            name="TFTP service accessible",
                            description="TFTP provides no authentication; accessible TFTP servers allow unauthenticated file read/write.")
    except Exception:
        return


def _rpcbind(ctx: ScanContext, host: str) -> None:
    """Retrieve the RPC program list from portmapper."""
    # Sun RPC DUMP call to portmapper
    rpc_dump = bytes.fromhex(
        "000000280000000000000002000186a0000000020000000400000000"
        "000000000000000000000000"
    )
    try:
        with socket.create_connection((host, 111), timeout=10) as sock:
            sock.sendall(rpc_dump)
            data = sock.recv(4096)
            if data:
                ctx.service_notes.append({
                    "service": "RPCBind",
                    "target": host,
                    "result": f"RPC portmapper responded ({len(data)} bytes). Programs may include NFS, NIS, mountd.",
                })
    except Exception:
        return