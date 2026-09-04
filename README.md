<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**Advanced Automated Reconnaissance Framework**

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-red?style=flat-square)

*OSINT → SubEnum → DNS → HTTP → Ports → CVE → Secrets → Report*

> ⚠️ **For authorized penetration testing only. Always obtain written permission before scanning any target.**

</div>

---

## What is RECONX?

RECONX is a full-chain automated recon framework built for VAPT engagements. It chains 8 phases of intelligence gathering — from passive OSINT to active scanning to CVE correlation — into a single command, then produces structured JSON and Markdown reports.

---

## Features

| Module | Capability |
|--------|-----------|
| **OSINT** | WHOIS, Shodan InternetDB (free, no key), Wayback Machine, Google Dorks |
| **Subdomain Enum** | subfinder binary, crt.sh (cert transparency), async DNS brute-force |
| **DNS Analysis** | A/AAAA/MX/NS/TXT/SOA/CAA/DMARC, zone transfer attempts, SPF/DMARC audit |
| **HTTP Probing** | Async probing, tech stack fingerprinting, security header audit, redirect chains |
| **Path Discovery** | 40+ sensitive paths (.env, /.git, /actuator, /admin, swagger, etc.) |
| **Port Scanning** | nmap with 5 scan profiles including stealth mode and NSE vuln scripts |
| **CVE Lookup** | NVD API cross-reference of discovered service versions (no API key needed) |
| **Secret Scanning** | AWS keys, GitHub tokens, JWTs, DB strings, API keys in HTML/JS responses |
| **Reporting** | JSON + Markdown reports with executive summary and severity-sorted findings |

---

## Requirements

### System
```bash
sudo apt install -y nmap python3-pip whois dnsutils
```

### Python
```bash
pip3 install dnspython requests colorama aiohttp
```

### Optional (recommended — enhances results)
```bash
# Install Go first
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Then install Go-based tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/owasp-amass/amass/v4/...@master

export PATH=$PATH:~/go/bin
```

> RECONX auto-detects subfinder/httpx/amass — falls back to pure Python if not installed.

---

## Installation

```bash
git clone https://github.com/yourusername/reconx.git
cd reconx
pip3 install -r requirements.txt
chmod +x reconx.py
```

---

## Usage

### Basic Scan
```bash
python3 reconx.py -d example.com
```

### Full Scan (all ports, NSE vuln scripts)
```bash
python3 reconx.py -d example.com --scan-type full
```

### Vuln Scan (nmap NSE + CVE lookup)
```bash
python3 reconx.py -d example.com --scan-type vuln
```

### Stealth Mode (slow, evasive, fragmented packets)
```bash
python3 reconx.py -d example.com --scan-type stealth
```

### With Shodan API Key (richer results)
```bash
python3 reconx.py -d example.com --shodan-key YOUR_API_KEY
```

### Custom Wordlist (SecLists recommended)
```bash
python3 reconx.py -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Skip Specific Phases
```bash
python3 reconx.py -d example.com --skip-nmap --skip-cve
python3 reconx.py -d example.com --skip-subdomains --skip-osint
```

### Custom Output Directory
```bash
python3 reconx.py -d example.com --output ./pentest/client-name/recon
```

---

## All Flags

```
-d, --domain           Target domain (required)
--scan-type            stealth | quick | default | full | vuln
--output               Output directory (default: ./reconx_output)
-w, --wordlist         Path to custom subdomain wordlist
--shodan-key           Shodan API key for full host data
--skip-osint           Skip OSINT phase
--skip-subdomains      Skip subdomain enumeration
--skip-http            Skip HTTP probing
--skip-paths           Skip interesting path discovery
--skip-nmap            Skip port scanning
--skip-cve             Skip CVE correlation
--skip-secrets         Skip secret/credential scanning
```

---

## Scan Profiles

| Profile | Speed | Ports | Description |
|---------|-------|-------|-------------|
| `stealth` | Very slow | Common | Fragmented packets, low timing (T2) — evades basic IDS |
| `quick` | Fast | Top 100 | Fast overview scan |
| `default` | Medium | 24 key ports | Service detection + default NSE scripts |
| `full` | Slow | All 65535 | Complete port sweep with service/version detection |
| `vuln` | Medium | Key ports | Runs `vuln`, `auth`, `default` NSE scripts |

---

## Output Files

After each scan, RECONX creates two files in your output directory:

```
reconx_output/
├── reconx_example.com_20240904_143022.json    ← Machine-readable full data
└── reconx_example.com_20240904_143022.md      ← Human-readable report
```

### JSON Report Structure
```json
{
  "meta": { "tool": "RECONX v2.0", "target": "...", "timestamp": "..." },
  "osint": { "whois": {}, "shodan": {} },
  "subdomains": { "sub.example.com": "1.2.3.4" },
  "dns": { "records": {}, "findings": [] },
  "http": { "sub.example.com": { "status": 200, "title": "...", "tech_stack": [] } },
  "paths": [ { "url": "...", "status": 200, "size": 1234 } ],
  "ports": { "1.2.3.4": { "hosts": [], "ports": [] } },
  "cves": [ { "cve_id": "CVE-...", "score": 9.8, "severity": "CRITICAL" } ],
  "secrets": [ { "name": "AWS Access Key", "url": "..." } ],
  "findings_summary": []
}
```

---

## What RECONX Detects

**DNS Issues**
- Zone transfer vulnerabilities (AXFR)
- Missing/weak SPF records (email spoofing risk)
- Missing DMARC records (phishing risk)

**Web Issues**
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Exposed sensitive paths (.env, .git, /actuator, /admin, swagger)
- Technology stack fingerprinting

**Infrastructure Issues**
- Risky services (Telnet, FTP, Redis, MongoDB, Docker API)
- Known CVEs in discovered service versions (via NVD API)
- Shodan-flagged vulnerabilities (via InternetDB)

**Secrets & Credentials**
- AWS Access/Secret Keys
- GitHub/GitLab tokens
- Stripe/SendGrid API keys
- JWT tokens
- Database connection strings
- Hardcoded passwords in JS files

---

## Recommended Wordlists (SecLists)

```bash
# Install SecLists
sudo apt install seclists

# Or clone manually
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists

# Good wordlists for RECONX:
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt    # Fast
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt   # Thorough
/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt                   # Comprehensive
```

---

## Legal Disclaimer

RECONX is designed for **authorized security testing only**.

- Only use against systems you own or have **explicit written permission** to test
- Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent laws in your jurisdiction
- The authors take no responsibility for misuse of this tool

---

## Contributing

Pull requests welcome. Planned features:
- [ ] Screenshot capture (gowitness integration)
- [ ] Directory brute-force (ffuf/gobuster integration)
- [ ] CORS misconfiguration detection
- [ ] S3 bucket enumeration
- [ ] Nuclei template scanning
- [ ] HTML report with charts
- [ ] Slack/Discord webhook notifications

---

## License

MIT License — see [LICENSE](LICENSE) for details.
