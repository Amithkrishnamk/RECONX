<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**Professional Penetration Testing Framework**

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Version](https://img.shields.io/badge/Version-4.0-red?style=flat-square)
![Modules](https://img.shields.io/badge/Modules-30+-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Author](https://img.shields.io/badge/Author-Amith%20Krishna%20MK-orange?style=flat-square)

**Created by Amith Krishna MK**

*OSINT · SubEnum · DNS · HTTP · CMS · Paths · Ports · CVE/RCE · SQLi · XSS · LFI*
*CORS · SSRF · SSTI · XXE · GraphQL · S3 · WAF · CISA KEV · Nuclei · LinkPiece*

> ⚠️ **For authorized penetration testing only. Always obtain written permission.**

</div>

---

## Overview

RECONX v4.0 is a professional-grade automated penetration testing framework with **30+ modules** across **Tier 1–4** of active offensive security. It supports both **full engagement scans** and **single-module targeted testing** — run exactly what you need.

---

## Installation

```bash
git clone https://github.com/yourusername/reconx.git
cd reconx
pip3 install dnspython requests colorama aiohttp beautifulsoup4
chmod +x reconx.py
```

### Optional (enhances results significantly)
```bash
# Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
export PATH=$PATH:~/go/bin

# System tools
sudo apt install -y nmap whois dnsutils wpscan
```

---

## Usage

### Full Scan (all 30 modules)
```bash
python3 reconx.py -d target.com --full
python3 reconx.py -d target.com --full --scan-type vuln
python3 reconx.py -d target.com --full --shodan-key YOUR_KEY
python3 reconx.py -d target.com --full -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Single Module Scans
```bash
# Reconnaissance
python3 reconx.py -d target.com --module osint
python3 reconx.py -d target.com --module subdomains
python3 reconx.py -d target.com --module dns
python3 reconx.py -d target.com --module http
python3 reconx.py -d target.com --module ports

# CMS & Web
python3 reconx.py -d target.com --module cms
python3 reconx.py -d target.com --module paths

# Active Vulnerability Testing
python3 reconx.py -d target.com --module sqli
python3 reconx.py -d target.com --module xss
python3 reconx.py -d target.com --module lfi
python3 reconx.py -d target.com --module ssrf
python3 reconx.py -d target.com --module ssti
python3 reconx.py -d target.com --module xxe
python3 reconx.py -d target.com --module cors
python3 reconx.py -d target.com --module proto
python3 reconx.py -d target.com --module smuggle
python3 reconx.py -d target.com --module redirect

# Smart Recon
python3 reconx.py -d target.com --module jsanalysis
python3 reconx.py -d target.com --module graphql
python3 reconx.py -d target.com --module s3
python3 reconx.py -d target.com --module asn
python3 reconx.py -d target.com --module certs
python3 reconx.py -d target.com --module waf
python3 reconx.py -d target.com --module favicon

# CVE & Intelligence
python3 reconx.py -d target.com --module cve
python3 reconx.py -d target.com --module nuclei

# Cloud & Infrastructure
python3 reconx.py -d target.com --module cloudmeta
python3 reconx.py -d target.com --module ipv6

# Audit & Harvest
python3 reconx.py -d target.com --module headers
python3 reconx.py -d target.com --module linkpiece
```

---

## All Flags

```
-d,  --domain           Target domain (required)
     --full             Run all 30 modules
     --module           Run single module (see list below)
     --scan-type        stealth | quick | default | full | vuln
     --output           Output directory (default: ./reconx_output)
-w,  --wordlist         Custom subdomain wordlist
     --shodan-key       Shodan API key
     --nuclei-severity  Nuclei severity filter (default: medium,high,critical)
```

---

## Module Reference

| Module | Tier | Description |
|--------|------|-------------|
| `osint` | Passive | WHOIS, Shodan InternetDB, Wayback Machine, Email harvest, Google Dorks |
| `subdomains` | Active | subfinder + amass + crt.sh + async DNS brute (150 concurrent) |
| `dns` | Active | All record types, zone transfer, SPF/DMARC audit |
| `http` | Active | Async HTTP probing, tech fingerprinting (30+ frameworks) |
| `cms` | Active | WordPress deep scan, Joomla, Drupal, wpscan integration |
| `paths` | Active | 120+ sensitive paths discovery |
| `ports` | Active | nmap with 5 profiles incl. stealth mode & NSE vuln scripts |
| `cve` | Intel | CVE/RCE fingerprinting + CISA KEV + NVD API |
| `sqli` | Exploit | SQL injection — error-based & time-based |
| `xss` | Exploit | Reflected XSS testing |
| `lfi` | Exploit | Local File Inclusion with /etc/passwd confirmation |
| `cors` | Exploit | CORS misconfiguration with credential flag |
| `ssrf` | Exploit | SSRF → cloud metadata (AWS/GCP/Azure) |
| `ssti` | Exploit | SSTI → RCE (Jinja2, Twig, Spring SpEL, ERB, Freemarker) |
| `xxe` | Exploit | XXE injection — file read & SSRF via XML |
| `proto` | Exploit | Prototype pollution in Node.js/Express apps |
| `smuggle` | Exploit | HTTP Request Smuggling CL.TE/TE.CL probe |
| `redirect` | Exploit | Open redirect parameter detection |
| `jsanalysis` | Smart | JS deep analysis — hidden APIs, secrets, S3 refs, internal hosts |
| `graphql` | Smart | GraphQL introspection, batch DoS, sensitive type detection |
| `s3` | Smart | AWS S3 + Azure Blob public access enumeration |
| `asn` | Smart | ASN & IP range / BGP prefix discovery |
| `certs` | Smart | TLS cert SANs, expiry, weak cipher detection |
| `waf` | Smart | 9 WAF vendor detection + bypass techniques |
| `favicon` | Smart | Favicon hash for Shodan pivoting |
| `cloudmeta` | Cloud | AWS/GCP/Azure/DO metadata endpoint testing |
| `ipv6` | Cloud | IPv6 scanning (often bypasses firewalls) |
| `headers` | Audit | Security header audit + cookie flags + version disclosure |
| `nuclei` | Intel | Nuclei template scanning (9000+ templates) |
| `linkpiece` | Harvest | Endpoints, params, emails, APIs, internal IPs, subdomains from links |

---

## Built-in CVE/RCE Fingerprints

| CVE | Name | Severity |
|-----|------|----------|
| CVE-2021-44228 | Log4Shell JNDI injection | CRITICAL |
| CVE-2022-22965 | Spring4Shell RCE | CRITICAL |
| CVE-2017-5638 | Apache Struts S2-045 RCE | CRITICAL |
| CVE-2024-6387 | regreSSHion OpenSSH RCE | CRITICAL |
| CVE-2024-4577 | PHP CGI Argument Injection | CRITICAL |
| CVE-2024-23897 | Jenkins CLI RCE | CRITICAL |
| CVE-2023-34362 | MOVEit SQLi RCE | CRITICAL |
| CVE-2023-3519 | Citrix Bleed RCE | CRITICAL |
| CVE-2022-26134 | Confluence OGNL RCE | CRITICAL |
| CVE-2021-26855 | ProxyLogon Exchange RCE | CRITICAL |
| CVE-2020-1472 | Zerologon priv esc | CRITICAL |
| CVE-2020-14882 | WebLogic Auth Bypass | CRITICAL |
| CVE-2019-0708 | BlueKeep RDP RCE | CRITICAL |
| CVE-2018-7600 | Drupalgeddon2 RCE | CRITICAL |
| CVE-2017-0144 | EternalBlue SMB RCE | CRITICAL |
| CVE-2014-6271 | Shellshock RCE | CRITICAL |

---

## Output

```
reconx_output/
├── reconx_target.com_TIMESTAMP.json    ← Machine-readable full data
├── reconx_target.com_TIMESTAMP.html    ← Dark HTML dashboard
└── reconx_target.com_TIMESTAMP.md      ← Markdown report
```

---

## Legal Disclaimer

RECONX is for **authorized security testing only**.
Unauthorized use may violate CFAA, Computer Misuse Act, and local laws.

---

## Author

**Amith Krishna MK**

---

## License

MIT — see LICENSE
