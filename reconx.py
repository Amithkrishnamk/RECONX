#!/usr/bin/env python3
"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

RECONX — Advanced Automated Reconnaissance Framework
Version: 2.0 | Author: VAPT Edition
Phases: OSINT → SubEnum → DNS → HTTP → Ports → CVE → Secrets → Report
"""

import asyncio
import aiohttp
import subprocess
import socket
import json
import os
import sys
import re
import argparse
import datetime
import random
import time
import hashlib
import base64
import concurrent.futures
import ipaddress
import ssl
from pathlib import Path
from urllib.parse import urljoin, urlparse

# ── Optional imports ──
try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQ_OK = True
except ImportError:
    REQ_OK = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    R=Fore.RED; G=Fore.GREEN; Y=Fore.YELLOW; C=Fore.CYAN
    M=Fore.MAGENTA; B=Fore.BLUE; W=Fore.WHITE; RS=Style.RESET_ALL; BD=Style.BRIGHT
except ImportError:
    R=G=Y=C=M=B=W=RS=BD=""

# ─────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────
BANNER = f"""
{C}{BD}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝{RS}
{Y}  Advanced Automated Reconnaissance Framework v2.0{RS}
{M}  OSINT → SubEnum → DNS → HTTP → Ports → CVE → Secrets → Report{RS}
{R}  ⚠  For authorized penetration testing only. Use responsibly.{RS}
"""

# ─────────────────────────────────────────────────────────────────
# USER-AGENT POOL (rotation for stealth)
# ─────────────────────────────────────────────────────────────────
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "python-httpx/0.24.0",
    "curl/8.1.2",
    "Go-http-client/1.1",
]

def ua(): return random.choice(UA_POOL)

# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────
def log(level, msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    icons = {
        "info":    f"{C}[*]{RS}",
        "success": f"{G}[+]{RS}",
        "warn":    f"{Y}[!]{RS}",
        "error":   f"{R}[-]{RS}",
        "section": f"{M}[»]{RS}",
        "vuln":    f"{R}{BD}[VULN]{RS}",
        "secret":  f"{R}{BD}[SECRET]{RS}",
    }
    print(f"  {icons.get(level,'[?]')} {BD}{ts}{RS}  {msg}")

def section(title):
    print(f"\n{C}{'═'*65}{RS}")
    print(f"  {M}{BD}{title}{RS}")
    print(f"{C}{'═'*65}{RS}")

def run_cmd(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", 1
    except Exception as e:
        return "", str(e), 1

def tool_ok(name):
    o, _, rc = run_cmd(f"which {name}")
    return rc == 0 and bool(o)

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def jitter(base=0.3, variance=0.4):
    """Random delay for stealth."""
    time.sleep(base + random.uniform(0, variance))

# ─────────────────────────────────────────────────────────────────
# MODULE 1: OSINT — PASSIVE INTELLIGENCE
# ─────────────────────────────────────────────────────────────────
def osint_whois(domain):
    """WHOIS lookup."""
    out, _, rc = run_cmd(f"whois {domain} 2>/dev/null", timeout=15)
    if rc != 0 or not out:
        return {}
    data = {}
    for line in out.splitlines():
        for key in ["Registrar:", "Registrant:", "Creation Date:", "Updated Date:",
                    "Expiry Date:", "Name Server:", "Registrant Email:"]:
            if key.lower() in line.lower():
                val = line.split(":", 1)[-1].strip()
                data.setdefault(key.rstrip(":"), []).append(val)
    return data

def osint_shodan(domain, api_key=None):
    """Shodan InternetDB (free, no key required) + optional API."""
    results = {}
    if not REQ_OK:
        return results
    # Free InternetDB — no key needed
    ip = resolve_ip(domain)
    if ip:
        try:
            r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10,
                             headers={"User-Agent": ua()})
            if r.status_code == 200:
                data = r.json()
                results["internetdb"] = {
                    "ip": ip,
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "hostnames": data.get("hostnames", []),
                    "cpes": data.get("cpes", []),
                    "tags": data.get("tags", []),
                }
                if data.get("vulns"):
                    log("vuln", f"Shodan InternetDB: {ip} has known vulns → {', '.join(data['vulns'][:5])}")
                if data.get("ports"):
                    log("success", f"Shodan InternetDB: {ip} open ports → {data['ports']}")
        except Exception as e:
            log("warn", f"Shodan InternetDB failed: {e}")
    # Full API if key provided
    if api_key and ip:
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
                             timeout=15, headers={"User-Agent": ua()})
            if r.status_code == 200:
                results["shodan_api"] = r.json()
        except Exception:
            pass
    return results

def osint_censys_search(domain):
    """Censys search via web scrape (no API key)."""
    # Use certificate transparency as censys proxy
    return crt_sh_enum(domain)

def osint_google_dorks(domain):
    """Generate Google dork queries (display only, not auto-search)."""
    dorks = [
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:xls OR filetype:xlsx',
        f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
        f'site:{domain} inurl:config OR inurl:backup OR inurl:.env',
        f'site:{domain} "password" OR "passwd" OR "secret"',
        f'site:{domain} inurl:api OR inurl:swagger OR inurl:graphql',
        f'"@{domain}" filetype:sql',
        f'site:pastebin.com "{domain}"',
        f'site:github.com "{domain}" password OR secret OR token',
        f'inurl:"{domain}" ext:log OR ext:txt',
    ]
    return dorks

def osint_wayback(domain):
    """Check Wayback Machine for archived URLs."""
    if not REQ_OK:
        return []
    try:
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=50&fl=original&collapse=urlkey"
        r = requests.get(url, timeout=15, headers={"User-Agent": ua()})
        if r.status_code == 200:
            data = r.json()
            urls = list(set([row[0] for row in data[1:] if row]))
            return urls[:30]
    except Exception:
        pass
    return []

def crt_sh_enum(domain):
    """Certificate transparency via crt.sh."""
    if not REQ_OK:
        return []
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         timeout=20, headers={"User-Agent": ua()})
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for e in data:
                for n in e.get("name_value","").splitlines():
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n != domain and " " not in n:
                        subs.add(n.lower())
            return list(subs)
    except Exception as e:
        log("warn", f"crt.sh: {e}")
    return []

# ─────────────────────────────────────────────────────────────────
# MODULE 2: SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────
WORDLIST = [
    "www","mail","ftp","admin","api","dev","staging","test","blog","shop",
    "vpn","remote","portal","dashboard","beta","app","m","mobile","static",
    "cdn","media","assets","secure","login","auth","oauth","sso","git",
    "gitlab","jenkins","jira","confluence","support","help","docs","status",
    "monitor","metrics","grafana","kibana","elastic","smtp","pop","imap",
    "ns1","ns2","mx","webmail","internal","corp","intranet","uat","qa",
    "pre-prod","db","database","redis","mongo","mysql","postgres","backup",
    "old","new","v2","demo","sandbox","s3","storage","files","upload",
    "download","img","images","video","stream","live","chat","forum",
    "community","wiki","kb","search","track","analytics","stats","reports",
    "billing","pay","payment","checkout","store","shop","ecommerce","cart",
    "hr","crm","erp","vpn2","gateway","proxy","relay","smtp2","bounce",
    "autodiscover","autoconfig","exchange","owa","outlook","sharepoint",
    "office","teams","meet","video","zoom","webrtc","api2","api-v2","rest",
    "graphql","grpc","ws","websocket","socket","push","notify","hooks",
    "webhook","callback","events","queue","broker","kafka","rabbit","celery",
    "worker","scheduler","cron","batch","etl","pipeline","airflow","prefect",
    "k8s","kubernetes","docker","registry","harbor","nexus","artifactory",
    "sonar","sonarqube","fortify","checkmarx","vault","consul","nomad",
    "prometheus","alertmanager","loki","jaeger","zipkin","newrelic","datadog",
]

async def dns_bruteforce_async(domain, wordlist):
    """Async DNS brute-force — much faster than threaded."""
    found = {}
    semaphore = asyncio.Semaphore(100)

    async def check(sub):
        fqdn = f"{sub}.{domain}"
        async with semaphore:
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, resolve_ip, fqdn)
                if ip:
                    return fqdn, ip
            except Exception:
                pass
        return None

    tasks = [check(s) for s in wordlist]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if r and not isinstance(r, Exception):
            fqdn, ip = r
            found[fqdn] = ip
    return found

def enumerate_subdomains(domain, wordlist=None):
    """Full async subdomain enumeration."""
    section("PHASE 2 — Subdomain Enumeration")
    if wordlist is None:
        wordlist = WORDLIST

    all_subs = {}

    # subfinder binary
    if tool_ok("subfinder"):
        log("info", "Running subfinder...")
        out, _, rc = run_cmd(f"subfinder -d {domain} -silent -timeout 30", 60)
        if rc == 0 and out:
            for s in out.splitlines():
                s = s.strip()
                if s:
                    ip = resolve_ip(s)
                    all_subs[s] = ip or "unresolved"
            log("success", f"subfinder → {len(all_subs)} subdomains")

    # amass passive
    if tool_ok("amass"):
        log("info", "Running amass (passive)...")
        out, _, rc = run_cmd(f"amass enum -passive -d {domain} -timeout 60", 90)
        if rc == 0 and out:
            for s in out.splitlines():
                s = s.strip()
                if s and s.endswith(domain):
                    ip = resolve_ip(s)
                    all_subs.setdefault(s, ip or "unresolved")

    # crt.sh
    log("info", "Querying crt.sh...")
    for s in crt_sh_enum(domain):
        if s not in all_subs:
            ip = resolve_ip(s)
            all_subs[s] = ip or "unresolved"

    # async DNS brute-force
    log("info", f"Async DNS brute-force ({len(wordlist)} words)...")
    brute = asyncio.run(dns_bruteforce_async(domain, wordlist))
    for fqdn, ip in brute.items():
        all_subs.setdefault(fqdn, ip)

    # root domain
    all_subs[domain] = resolve_ip(domain) or "unresolved"

    log("success", f"Total: {BD}{len(all_subs)}{RS} unique subdomains")
    for sub, ip in sorted(all_subs.items()):
        color = G if ip != "unresolved" else Y
        print(f"    {color}  {sub:<50} → {ip}{RS}")

    return all_subs

# ─────────────────────────────────────────────────────────────────
# MODULE 3: DNS DEEP ENUMERATION
# ─────────────────────────────────────────────────────────────────
def dns_enum(domain):
    """Deep DNS enumeration — records, zone transfer, DNSSEC, SPF."""
    section("PHASE 3 — DNS Deep Enumeration")
    records = {}
    findings = []

    rtypes = ["A","AAAA","MX","NS","TXT","SOA","CNAME","PTR","SRV","CAA","DMARC","DKIM"]

    if DNS_OK:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        for rtype in rtypes:
            qname = domain
            if rtype == "DMARC":
                qname = f"_dmarc.{domain}"
            try:
                ans = resolver.resolve(qname, rtype if rtype not in ("DMARC","DKIM") else "TXT")
                records[rtype] = [str(r) for r in ans]
                log("success", f"{rtype:<8} → {', '.join(records[rtype][:2])}")
            except Exception:
                pass
    else:
        for rtype in ["A","AAAA","MX","NS","TXT","SOA"]:
            out, _, rc = run_cmd(f"dig +short {domain} {rtype}")
            if rc == 0 and out:
                records[rtype] = [l.strip() for l in out.splitlines() if l.strip()]
                log("success", f"{rtype:<8} → {', '.join(records[rtype][:2])}")

    # Zone transfer attempt
    ns_list = records.get("NS", [])
    for ns in ns_list[:3]:
        ns = ns.rstrip(".")
        log("info", f"Attempting zone transfer from {ns}...")
        out, _, rc = run_cmd(f"dig @{ns} {domain} AXFR +noall +answer", timeout=10)
        if rc == 0 and out and "Transfer failed" not in out and len(out) > 100:
            log("vuln", f"ZONE TRANSFER SUCCESS on {ns}!")
            findings.append({"type": "zone_transfer", "ns": ns, "data": out[:500]})
            records["AXFR"] = [out]

    # SPF analysis
    txt_records = records.get("TXT", [])
    spf = [t for t in txt_records if "v=spf1" in t.lower()]
    if not spf:
        log("warn", "No SPF record found — email spoofing may be possible!")
        findings.append({"type": "missing_spf", "severity": "medium"})
    elif "+all" in str(spf):
        log("vuln", "SPF record has +all — allows any sender!")
        findings.append({"type": "weak_spf", "value": str(spf), "severity": "high"})

    # DMARC check
    dmarc = records.get("DMARC", [])
    if not dmarc:
        log("warn", "No DMARC record — phishing risk!")
        findings.append({"type": "missing_dmarc", "severity": "medium"})

    return records, findings

# ─────────────────────────────────────────────────────────────────
# MODULE 4: ASYNC HTTP PROBING
# ─────────────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

INTERESTING_PATHS = [
    "/.env", "/.git/HEAD", "/.git/config", "/config.php", "/wp-config.php",
    "/web.config", "/app.config", "/database.yml", "/config/database.yml",
    "/admin", "/admin/", "/administrator", "/wp-admin", "/phpmyadmin",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/crossdomain.xml",
    "/server-status", "/server-info", "/actuator", "/actuator/env",
    "/actuator/health", "/actuator/mappings", "/api/swagger.json",
    "/swagger-ui.html", "/api-docs", "/openapi.json", "/v1/api-docs",
    "/graphql", "/graphiql", "/.well-known/security.txt",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/_debug", "/debug", "/console", "/rails/info/properties",
    "/telescope", "/horizon", "/clockwork", "/tracy",
]

async def probe_host_async(session, host, semaphore):
    """Async HTTP probe for a single host."""
    result = None
    async with semaphore:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            try:
                headers = {"User-Agent": ua(), "Accept": "*/*"}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8),
                                        allow_redirects=True, ssl=False) as resp:
                    body = await resp.text(errors="replace")
                    title = ""
                    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                    if m:
                        title = m.group(1).strip()[:80]

                    resp_headers = dict(resp.headers)
                    missing_sec = [h for h in SECURITY_HEADERS
                                   if h.lower() not in {k.lower() for k in resp_headers}]
                    server = resp_headers.get("Server", resp_headers.get("server", ""))
                    powered = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by", ""))
                    ctype = resp_headers.get("Content-Type", "")

                    # Tech detection from headers + body
                    tech = detect_tech(resp_headers, body)

                    result = {
                        "url": str(resp.url),
                        "status": resp.status,
                        "title": title,
                        "server": server,
                        "powered_by": powered,
                        "content_type": ctype,
                        "content_length": len(body),
                        "missing_security_headers": missing_sec,
                        "tech_stack": tech,
                        "redirect": str(resp.url) if str(resp.url) != url else None,
                        "scheme": scheme,
                    }
                    break
            except Exception:
                continue
    return host, result

def detect_tech(headers, body):
    """Fingerprint technology from headers and HTML body."""
    tech = []
    h = {k.lower(): v.lower() for k, v in headers.items()}
    b = body.lower()

    signatures = {
        "WordPress":    ["wp-content", "wp-includes", "wordpress"],
        "Drupal":       ["drupal", "/sites/default/"],
        "Joomla":       ["joomla", "/components/com_"],
        "Laravel":      ["laravel_session", "laravel"],
        "Django":       ["csrftoken", "django"],
        "Rails":        ["_rails_", "x-runtime", "x-request-id"],
        "Express":      ["express"],
        "Spring Boot":  ["x-application-context", "spring"],
        "ASP.NET":      ["__viewstate", "aspnet", "x-aspnet-version"],
        "PHP":          ["php", "x-powered-by: php"],
        "Nginx":        ["nginx"],
        "Apache":       ["apache"],
        "IIS":          ["microsoft-iis", "x-powered-by: asp"],
        "Cloudflare":   ["cf-ray", "cf-cache-status"],
        "AWS":          ["x-amz", "amazon"],
        "React":        ["react", "__react"],
        "Vue":          ["vue", "v-app"],
        "Angular":      ["ng-version", "angular"],
        "jQuery":       ["jquery"],
        "Bootstrap":    ["bootstrap"],
        "GraphQL":      ["graphql", "application/graphql"],
    }
    srv = h.get("server","")
    powered = h.get("x-powered-by","")
    combined = f"{srv} {powered} {b[:5000]}"

    for name, sigs in signatures.items():
        for sig in sigs:
            if sig in combined:
                if name not in tech:
                    tech.append(name)
                break
    return tech

async def http_probe_all_async(subdomains):
    """Probe all live subdomains asynchronously."""
    section("PHASE 4 — Async HTTP Probing")

    # httpx binary fallback
    if tool_ok("httpx"):
        log("info", "httpx binary detected — using it for probing...")
        tmp = "/tmp/reconx_targets.txt"
        with open(tmp, "w") as f:
            f.write("\n".join(subdomains.keys()))
        out, _, rc = run_cmd(
            f"httpx -l {tmp} -title -status-code -tech-detect -silent -timeout 5 -random-agent",
            timeout=120
        )
        if rc == 0 and out:
            results = {}
            for line in out.splitlines():
                results[line] = {"raw_httpx": line}
                log("success", line)
            return results

    # Pure async Python
    hosts = [h for h, ip in subdomains.items() if ip != "unresolved"]
    log("info", f"Async probing {len(hosts)} live hosts...")

    conn = aiohttp.TCPConnector(ssl=False, limit=50)
    semaphore = asyncio.Semaphore(30)
    results = {}

    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [probe_host_async(session, h, semaphore) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            host, result = await coro
            if result:
                results[host] = result
                sc = result["status"]
                col = G if sc == 200 else (Y if sc in (301,302,403,401) else R)
                tech = f"{C}[{', '.join(result['tech_stack'][:3])}]{RS}" if result["tech_stack"] else ""
                miss = f"{R}[Missing: {', '.join(result['missing_security_headers'][:3])}]{RS}" if result["missing_security_headers"] else ""
                title = result["title"][:35] or "(no title)"
                print(f"    {col}[{sc}]{RS}  {host:<38}  {BD}{title:<35}{RS}  {tech}  {miss}")

    log("success", f"Live web services: {BD}{len(results)}{RS}")
    return results

def path_discovery(http_results):
    """Discover interesting paths on live hosts."""
    section("PHASE 4b — Interesting Path Discovery")
    findings = []

    if not REQ_OK:
        log("warn", "requests not available — skipping path discovery")
        return findings

    hosts = list(http_results.keys())[:20]  # limit for safety

    def check_path(args):
        host, path = args
        # Use base URL from probe
        result = http_results.get(host, {})
        scheme = result.get("scheme", "https")
        url = f"{scheme}://{host}{path}"
        try:
            r = requests.get(url, timeout=5, verify=False,
                             headers={"User-Agent": ua()}, allow_redirects=False)
            if r.status_code in (200, 301, 302, 403, 500):
                return {
                    "url": url,
                    "status": r.status_code,
                    "size": len(r.content),
                    "path": path,
                    "host": host,
                }
        except Exception:
            pass
        return None

    combos = [(h, p) for h in hosts for p in INTERESTING_PATHS]
    log("info", f"Checking {len(combos)} paths across {len(hosts)} hosts...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        results = list(ex.map(check_path, combos))

    for r in results:
        if r:
            col = R if r["status"] == 200 else Y
            findings.append(r)
            log("warn" if r["status"] != 200 else "vuln",
                f"{col}[{r['status']}]{RS}  {r['url']}  ({r['size']} bytes)")

    return findings

# ─────────────────────────────────────────────────────────────────
# MODULE 5: NMAP — ADVANCED PORT SCANNING
# ─────────────────────────────────────────────────────────────────
RISKY_SERVICES = {
    "ftp":      "Cleartext file transfer — credentials sniffable",
    "telnet":   "Cleartext remote access — extremely dangerous",
    "smb":      "File sharing — common ransomware vector",
    "rdp":      "Remote Desktop — brute-force & BlueKeep risk",
    "vnc":      "Remote desktop — often unauth or weak passwords",
    "redis":    "In-memory DB — often unauthenticated by default",
    "mongodb":  "NoSQL DB — often unauthenticated by default",
    "mysql":    "Database — check for remote root access",
    "postgres": "Database — check for remote access",
    "rsync":    "File sync — often allows unauthenticated reads",
    "elasticsearch": "Search engine — often unauthenticated, data exposure",
    "memcached":"Cache — almost always unauthenticated",
    "docker":   "Container daemon — critical if exposed",
    "kubernetes":"K8s API — critical if exposed",
}

def nmap_advanced(ip, scan_type="default"):
    """Advanced nmap scan with scripts."""
    profiles = {
        "stealth": f"nmap -sS -T2 -f --open --randomize-hosts -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443 {ip}",
        "quick":   f"nmap -T4 -F --open {ip}",
        "default": f"nmap -T4 -sV -sC --open -p 21,22,23,25,53,80,110,143,443,445,1433,3306,3389,5432,5900,6379,8080,8443,8888,9200,9300,27017,28017 {ip}",
        "full":    f"nmap -T4 -sV -sC --open -p- {ip}",
        "vuln":    f"nmap -T4 -sV --script=vuln,auth,default --open -p 21,22,23,25,53,80,443,445,3306,3389,5432 {ip}",
    }
    cmd = profiles.get(scan_type, profiles["default"])
    log("info", f"nmap [{scan_type}] → {ip}")
    out, err, rc = run_cmd(cmd, timeout=300)

    ports = []
    vuln_findings = []
    if rc == 0 and out:
        for line in out.splitlines():
            line = line.strip()
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    state = parts[1]
                    service = parts[2].lower()
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    risk = RISKY_SERVICES.get(service, "")
                    ports.append({
                        "port_proto": port_proto,
                        "state": state,
                        "service": service,
                        "version": version,
                        "risk": risk,
                    })
                    if risk:
                        vuln_findings.append({
                            "type": "risky_service",
                            "ip": ip,
                            "port": port_proto,
                            "service": service,
                            "detail": risk,
                            "severity": "high" if service in ("telnet","redis","mongodb","docker") else "medium",
                        })
            # Capture NSE vuln script output
            if "VULNERABLE" in line or "CVE-" in line:
                vuln_findings.append({
                    "type": "nmap_script",
                    "ip": ip,
                    "detail": line,
                    "severity": "high",
                })
    return ports, vuln_findings, out

def port_scan_all(subdomains, scan_type="default"):
    """Scan all unique IPs."""
    section("PHASE 5 — Advanced Port Scanning")
    if not tool_ok("nmap"):
        log("error", "nmap not found → sudo apt install nmap")
        return {}, []

    ip_map = {}
    for host, ip in subdomains.items():
        if ip and ip != "unresolved":
            try:
                ipaddress.ip_address(ip)
                ip_map.setdefault(ip, []).append(host)
            except ValueError:
                pass

    log("info", f"Scanning {len(ip_map)} unique IPs (scan profile: {scan_type})...")
    all_ports = {}
    all_vulns = []

    for ip, hosts in ip_map.items():
        ports, vulns, raw = nmap_advanced(ip, scan_type)
        all_ports[ip] = {"hosts": hosts, "ports": ports, "raw": raw}
        all_vulns.extend(vulns)

        if ports:
            log("success", f"{ip} — {len(ports)} open ports:")
            for p in ports:
                col = R if p["risk"] else G
                risk_str = f"  {R}⚠ {p['risk']}{RS}" if p["risk"] else ""
                print(f"    {col}  {p['port_proto']:<12} {p['state']:<8} {p['service']:<15} {p['version'][:30]}{RS}{risk_str}")
        else:
            log("warn", f"{ip} — no open ports detected")

    return all_ports, all_vulns

# ─────────────────────────────────────────────────────────────────
# MODULE 6: CVE / VULNERABILITY LOOKUP
# ─────────────────────────────────────────────────────────────────
def lookup_cves(port_results):
    """Cross-reference discovered services with NVD/CVE databases."""
    section("PHASE 6 — CVE Correlation")
    if not REQ_OK:
        log("warn", "requests not available — skipping CVE lookup")
        return []

    cve_findings = []
    # Extract service+version pairs
    service_versions = set()
    for ip, data in port_results.items():
        for p in data.get("ports", []):
            svc = p.get("service","")
            ver = p.get("version","")
            if svc and ver:
                service_versions.add((svc, ver, ip, p.get("port_proto","")))

    for svc, ver, ip, port in list(service_versions)[:15]:
        # Extract version number
        ver_match = re.search(r'(\d+\.\d+[\.\d]*)', ver)
        if not ver_match:
            continue
        ver_num = ver_match.group(1)
        query = f"{svc} {ver_num}"
        log("info", f"CVE lookup: {query}")

        try:
            # NVD free API (no key required)
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={svc}+{ver_num}&resultsPerPage=5"
            r = requests.get(url, timeout=15, headers={"User-Agent": ua()})
            jitter(0.5, 0.5)  # rate limit respect

            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve = v.get("cve", {})
                    cve_id = cve.get("id", "")
                    desc_list = cve.get("descriptions", [])
                    desc = next((d["value"] for d in desc_list if d["lang"]=="en"), "")[:200]
                    metrics = cve.get("metrics", {})
                    score = None
                    severity = "unknown"
                    for key in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                        if key in metrics and metrics[key]:
                            score = metrics[key][0].get("cvssData",{}).get("baseScore")
                            severity = metrics[key][0].get("cvssData",{}).get("baseSeverity","unknown")
                            break

                    if score and float(score) >= 7.0:
                        cve_findings.append({
                            "cve_id": cve_id,
                            "service": svc,
                            "version": ver_num,
                            "ip": ip,
                            "port": port,
                            "score": score,
                            "severity": severity,
                            "description": desc,
                        })
                        col = R if float(score) >= 9.0 else Y
                        log("vuln", f"{col}{cve_id}{RS}  score={score} ({severity})  {svc} {ver_num} on {ip}:{port}")
        except Exception as e:
            log("warn", f"CVE lookup failed for {svc}: {e}")

    if not cve_findings:
        log("info", "No critical CVEs found for detected versions")
    return cve_findings

# ─────────────────────────────────────────────────────────────────
# MODULE 7: SECRET / CREDENTIAL SCANNING
# ─────────────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":       r"[0-9a-zA-Z/+]{40}",
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":         r"gh[ps]_[A-Za-z0-9]{36}",
    "Slack Token":          r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Private Key":          r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "JWT Token":            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]+",
    "Basic Auth (base64)":  r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}",
    "Password in URL":      r"[?&]password=[^&\s]{4,}",
    "API Key param":        r"[?&](api_key|apikey|token|secret|key)=[^&\s]{8,}",
    "SendGrid Key":         r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "Stripe Key":           r"sk_(test|live)_[0-9a-zA-Z]{24}",
    "Heroku Key":           r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "DB Connection String": r"(mysql|postgres|mongodb|redis)://[^\s\"']+",
    ".env password":        r"(PASSWORD|PASSWD|DB_PASS|SECRET_KEY)\s*=\s*[^\s]{4,}",
}

def scan_secrets_in_response(url, body, host):
    """Scan HTTP response body for secrets."""
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, body, re.I)
        if matches:
            findings.append({
                "type": "secret",
                "name": name,
                "url": url,
                "host": host,
                "matches": [m[:80] if isinstance(m, str) else str(m)[:80] for m in matches[:3]],
            })
            log("secret", f"{R}{name}{RS} found at {url}")
    return findings

def js_secret_scan(http_results):
    """Download and scan JS files from live hosts for secrets."""
    section("PHASE 7 — Secret & Credential Scanning")
    if not REQ_OK:
        return []

    findings = []
    hosts = list(http_results.keys())[:15]

    def scan_host(host):
        host_findings = []
        result = http_results.get(host, {})
        scheme = result.get("scheme","https") if isinstance(result, dict) else "https"
        base = f"{scheme}://{host}"

        # Scan main page
        try:
            r = requests.get(base, timeout=8, verify=False, headers={"User-Agent": ua()})
            body = r.text

            # Find secrets in main page
            host_findings.extend(scan_secrets_in_response(base, body, host))

            # Extract JS file URLs
            js_urls = re.findall(r'src=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', body, re.I)
            for js in js_urls[:10]:
                js_url = js if js.startswith("http") else urljoin(base, js)
                try:
                    jr = requests.get(js_url, timeout=8, verify=False,
                                      headers={"User-Agent": ua()})
                    host_findings.extend(scan_secrets_in_response(js_url, jr.text, host))
                except Exception:
                    pass

        except Exception:
            pass
        return host_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(scan_host, hosts))
    for r in results:
        findings.extend(r)

    if not findings:
        log("info", "No secrets/credentials found in scanned responses")
    return findings

# ─────────────────────────────────────────────────────────────────
# MODULE 8: REPORT GENERATION
# ─────────────────────────────────────────────────────────────────
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

def severity_color(s):
    return {
        "critical": R+BD, "high": R, "medium": Y, "low": G, "unknown": W
    }.get(s.lower(), W)

def generate_report(domain, data, output_dir):
    """Generate JSON, Markdown, and HTML reports."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dt_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    subdomains    = data.get("subdomains", {})
    dns_records   = data.get("dns_records", {})
    dns_findings  = data.get("dns_findings", [])
    http_results  = data.get("http_results", {})
    path_findings = data.get("path_findings", [])
    port_results  = data.get("port_results", {})
    port_vulns    = data.get("port_vulns", [])
    cve_findings  = data.get("cve_findings", [])
    secret_findings = data.get("secret_findings", [])
    osint_data    = data.get("osint", {})
    wayback_urls  = data.get("wayback_urls", [])
    google_dorks  = data.get("google_dorks", [])

    all_findings = dns_findings + port_vulns + cve_findings + secret_findings
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity","unknown"), 4))

    # ── JSON ──
    full_report = {
        "meta": {"tool": "RECONX v2.0", "target": domain, "timestamp": ts},
        "osint": osint_data,
        "subdomains": subdomains,
        "dns": {"records": dns_records, "findings": dns_findings},
        "http": http_results if isinstance(http_results, dict) else {},
        "paths": path_findings,
        "ports": {ip: {"hosts": d["hosts"], "ports": d["ports"]} for ip, d in port_results.items()},
        "cves": cve_findings,
        "secrets": secret_findings,
        "findings_summary": all_findings,
    }
    json_path = output_dir / f"reconx_{domain}_{ts}.json"
    with open(json_path, "w") as f:
        json.dump(full_report, f, indent=2)

    # ── Markdown ──
    md_path = output_dir / f"reconx_{domain}_{ts}.md"
    with open(md_path, "w") as f:
        f.write(f"# RECONX Report — {domain}\n\n")
        f.write(f"**Generated:** {dt_str}  \n**Tool:** RECONX v2.0  \n**Target:** `{domain}`\n\n---\n\n")

        # Executive summary
        crit = [x for x in all_findings if x.get("severity") in ("critical","high")]
        f.write("## Executive Summary\n\n")
        f.write(f"| Metric | Count |\n|--------|-------|\n")
        f.write(f"| Subdomains found | {len(subdomains)} |\n")
        f.write(f"| Live web services | {len(http_results) if isinstance(http_results, dict) else 0} |\n")
        f.write(f"| Unique IPs scanned | {len(port_results)} |\n")
        f.write(f"| CVEs identified | {len(cve_findings)} |\n")
        f.write(f"| Secrets found | {len(secret_findings)} |\n")
        f.write(f"| High/Critical findings | {len(crit)} |\n\n")

        # Findings
        if all_findings:
            f.write("## Findings (Sorted by Severity)\n\n")
            f.write("| Severity | Type | Detail |\n|----------|------|--------|\n")
            for fi in all_findings:
                sev = fi.get("severity","unknown").upper()
                ftype = fi.get("type","")
                detail = fi.get("detail", fi.get("description", str(fi)))[:120]
                f.write(f"| {sev} | {ftype} | {detail} |\n")
            f.write("\n")

        # DNS
        f.write("## DNS Records\n\n| Type | Value |\n|------|-------|\n")
        for rtype, vals in dns_records.items():
            for v in vals:
                f.write(f"| {rtype} | `{v[:100]}` |\n")
        f.write("\n")

        # Subdomains
        f.write(f"## Subdomains ({len(subdomains)})\n\n| Subdomain | IP |\n|-----------|----|\n")
        for sub, ip in sorted(subdomains.items()):
            f.write(f"| `{sub}` | `{ip}` |\n")
        f.write("\n")

        # HTTP
        if isinstance(http_results, dict) and http_results:
            f.write(f"## HTTP Services ({len(http_results)})\n\n")
            f.write("| Host | Status | Title | Tech | Missing Headers |\n")
            f.write("|------|--------|-------|------|-----------------|\n")
            for host, r in http_results.items():
                if isinstance(r, dict) and "raw_httpx" not in r:
                    miss = ", ".join(r.get("missing_security_headers",[])[:3])
                    tech = ", ".join(r.get("tech_stack",[])[:3])
                    f.write(f"| `{host}` | {r.get('status','')} | {r.get('title','')[:40]} | {tech} | {miss} |\n")
            f.write("\n")

        # Interesting paths
        if path_findings:
            f.write(f"## Interesting Paths ({len(path_findings)})\n\n")
            f.write("| Status | URL | Size |\n|--------|-----|------|\n")
            for p in path_findings:
                f.write(f"| {p['status']} | `{p['url']}` | {p['size']} |\n")
            f.write("\n")

        # Port results
        if port_results:
            f.write("## Port Scan Results\n\n")
            for ip, data_p in port_results.items():
                f.write(f"### {ip}\n**Hosts:** {', '.join(data_p['hosts'])}\n\n")
                if data_p["ports"]:
                    f.write("| Port | State | Service | Version | Risk |\n|------|-------|---------|---------|------|\n")
                    for p in data_p["ports"]:
                        f.write(f"| {p['port_proto']} | {p['state']} | {p['service']} | {p['version'][:40]} | {p.get('risk','')} |\n")
                f.write("\n")

        # CVEs
        if cve_findings:
            f.write(f"## CVE Findings ({len(cve_findings)})\n\n")
            f.write("| CVE | Service | Score | Severity | IP | Description |\n")
            f.write("|-----|---------|-------|----------|----|-------------|\n")
            for c in cve_findings:
                f.write(f"| {c['cve_id']} | {c['service']} {c['version']} | {c.get('score','')} | {c.get('severity','')} | {c['ip']} | {c['description'][:80]} |\n")
            f.write("\n")

        # Secrets
        if secret_findings:
            f.write(f"## Secret / Credential Findings ({len(secret_findings)})\n\n")
            f.write("| Type | Host | URL |\n|------|------|-----|\n")
            for s in secret_findings:
                f.write(f"| {s['name']} | {s['host']} | `{s['url'][:80]}` |\n")
            f.write("\n")

        # OSINT
        if google_dorks:
            f.write("## Google Dorks (Manual)\n\n")
            for d in google_dorks:
                f.write(f"- `{d}`\n")
            f.write("\n")

        if wayback_urls:
            f.write(f"## Wayback Machine URLs ({len(wayback_urls)})\n\n")
            for u in wayback_urls[:20]:
                f.write(f"- {u}\n")
            f.write("\n")

    return json_path, md_path

# ─────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="RECONX v2.0 — Advanced Automated Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 reconx.py -d example.com
  python3 reconx.py -d example.com --scan-type full
  python3 reconx.py -d example.com --scan-type vuln --shodan-key YOUR_KEY
  python3 reconx.py -d example.com --skip-cve --skip-secrets
  python3 reconx.py -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  python3 reconx.py -d example.com --scan-type stealth --output /tmp/results
        """
    )
    parser.add_argument("-d","--domain",      required=True, help="Target domain")
    parser.add_argument("--scan-type",        default="default",
                        choices=["stealth","quick","default","full","vuln"],
                        help="Nmap scan profile (stealth=slow/evasive, vuln=NSE scripts)")
    parser.add_argument("--output",           default="./reconx_output", help="Output directory")
    parser.add_argument("-w","--wordlist",    help="Custom subdomain wordlist")
    parser.add_argument("--shodan-key",       help="Shodan API key (optional, enhances results)")
    parser.add_argument("--skip-subdomains",  action="store_true")
    parser.add_argument("--skip-http",        action="store_true")
    parser.add_argument("--skip-paths",       action="store_true")
    parser.add_argument("--skip-nmap",        action="store_true")
    parser.add_argument("--skip-cve",         action="store_true")
    parser.add_argument("--skip-secrets",     action="store_true")
    parser.add_argument("--skip-osint",       action="store_true")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    for prefix in ["https://","http://","www."]:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")

    log("info", f"Target: {BD}{domain}{RS}")
    log("info", f"Scan: {args.scan_type} | Output: {args.output}")
    log("warn", f"Ensure you have written authorization to test {domain}")
    print()

    data = {}

    # ── OSINT ──
    section("PHASE 1 — OSINT & Passive Intelligence")
    if not args.skip_osint:
        log("info", "WHOIS lookup...")
        whois = osint_whois(domain)
        if whois:
            for k, vals in list(whois.items())[:6]:
                log("success", f"{k}: {', '.join(vals[:2])}")

        log("info", "Shodan InternetDB lookup...")
        shodan = osint_shodan(domain, args.shodan_key)

        log("info", "Wayback Machine archive check...")
        wayback = osint_wayback(domain)
        if wayback:
            log("success", f"Wayback Machine: {len(wayback)} archived URLs found")

        dorks = osint_google_dorks(domain)
        log("success", f"Generated {len(dorks)} Google dork queries")

        data["osint"] = {"whois": whois, "shodan": shodan}
        data["wayback_urls"] = wayback
        data["google_dorks"] = dorks

    # ── SUBDOMAINS ──
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist) as f:
                wordlist = [l.strip() for l in f if l.strip()]
            log("info", f"Custom wordlist: {len(wordlist)} words")
        except Exception as e:
            log("warn", f"Wordlist load failed: {e}")

    if not args.skip_subdomains:
        subdomains = enumerate_subdomains(domain, wordlist)
    else:
        log("warn", "Subdomain enumeration skipped")
        subdomains = {domain: resolve_ip(domain) or "unresolved"}
    data["subdomains"] = subdomains

    # ── DNS ──
    dns_rec, dns_findings = dns_enum(domain)
    data["dns_records"] = dns_rec
    data["dns_findings"] = dns_findings

    # ── HTTP PROBING ──
    http_results = {}
    if not args.skip_http:
        http_results = asyncio.run(http_probe_all_async(subdomains))
    data["http_results"] = http_results

    # ── PATH DISCOVERY ──
    path_findings = []
    if not args.skip_paths and http_results:
        path_findings = path_discovery(http_results)
    data["path_findings"] = path_findings

    # ── PORT SCANNING ──
    port_results, port_vulns = {}, []
    if not args.skip_nmap:
        port_results, port_vulns = port_scan_all(subdomains, args.scan_type)
    data["port_results"] = port_results
    data["port_vulns"] = port_vulns

    # ── CVE LOOKUP ──
    cve_findings = []
    if not args.skip_cve and port_results:
        cve_findings = lookup_cves(port_results)
    data["cve_findings"] = cve_findings

    # ── SECRET SCANNING ──
    secret_findings = []
    if not args.skip_secrets and http_results:
        secret_findings = js_secret_scan(http_results)
    data["secret_findings"] = secret_findings

    # ── REPORT ──
    section("PHASE 8 — Report Generation")
    json_path, md_path = generate_report(domain, data, args.output)
    log("success", f"JSON  → {BD}{json_path}{RS}")
    log("success", f"Markdown → {BD}{md_path}{RS}")

    # ── SUMMARY ──
    all_findings = dns_findings + port_vulns + cve_findings + secret_findings
    crit = [f for f in all_findings if f.get("severity") in ("critical","high")]
    print(f"\n{C}{'═'*65}{RS}")
    print(f"  {G}{BD}✓ RECONX Complete{RS}  |  Target: {BD}{domain}{RS}")
    print(f"  Subdomains: {BD}{len(subdomains)}{RS}  |  Live HTTP: {BD}{len(http_results) if isinstance(http_results,dict) else 0}{RS}  |  IPs scanned: {BD}{len(port_results)}{RS}")
    print(f"  CVEs: {BD}{len(cve_findings)}{RS}  |  Secrets: {BD}{len(secret_findings)}{RS}  |  {R}{BD}High/Crit findings: {len(crit)}{RS}")
    print(f"{C}{'═'*65}{RS}\n")


if __name__ == "__main__":
    main()
