# HAKA AI — Ethiopian Financial Sector Security Assessment Platform

AI-powered cybersecurity assessment platform for auditing Ethiopian financial institutions and telecoms. Combines automated scanners, AI-driven report generation, threat intelligence, compliance mapping, and business operations tools.

**7 targets analyzed · 137 findings (57 CRITICAL, 87 HIGH) · 10+ tools**

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Pull a model (pick one)
ollama pull qwen3:32b          # 20 GB — best quality
ollama pull deepseek-r1:7b      # 4.7 GB — fast

# 3. Run a scan
python3 scanners/haka_email_scanner.py --domain cbe.com.et

# 4. Generate a report
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json --mode executive

# 5. Chat with findings
python3 haka_chat.py -q "show me critical findings at CBE"

# 6. Build attack paths
python3 haka_attack_paths.py --target cbe

# 7. Run compliance mapping
python3 haka_compliance.py --target cbe --framework nbe

# 8. Manage client pipeline
python3 haka_crm.py --pipeline
```

---

## Tool Inventory

### Scanners (`scanners/`)

Automated security assessment tools that probe targets and produce structured JSON output.

| Tool | Description | Key Capabilities |
|------|-------------|-----------------|
| `haka_exchange_scanner.py` | Exchange server security | OWA exposure, EWS enumeration, version detection, auth assessment |
| `haka_email_scanner.py` | Email security posture | SPF/DKIM/DMARC validation, MX enumeration, STARTTLS checking |
| `haka_dns_scanner.py` | DNS infrastructure | Zone transfer attempt, DNSSEC validation, subdomain enumeration |
| `haka_tls_scanner.py` | TLS/SSL assessment | Cipher suite analysis, certificate validation, protocol version checks |
| `haka_web_scanner.py` | Web application scan | Header analysis, cookie security, clickjacking, CSP validation |
| `haka_s3_scanner.py` | S3 bucket audit | Public exposure, ACL analysis, encryption status |
| `haka_vpn_scanner.py` | VPN endpoint audit | IKE/ISAKMP enumeration, vendor fingerprinting |
| `haka_collab_scanner.py` | Collaboration tool scan | Teams/SharePoint/Webex exposure assessment |
| `haka_ct_scanner.py` | Certificate Transparency | Real-time CT log monitoring, subdomain discovery via certs |
| `haka_ai.py` | AI orchestration | Master orchestrator that runs all scanners and consolidates results |

**Usage examples:**

```bash
python3 scanners/haka_exchange_scanner.py --target mail.cbe.com.et
python3 scanners/haka_email_scanner.py --domain cbe.com.et
python3 scanners/haka_dns_scanner.py --domain cbe.com.et
python3 scanners/haka_tls_scanner.py --host cbe.com.et --port 443
python3 scanners/haka_web_scanner.py --url https://cbe.com.et
python3 scanners/haka_s3_scanner.py --bucket cbe-bucket
python3 scanners/haka_ct_scanner.py --domain cbe.com.et --monitor
python3 scanners/haka_ai.py --target cbe --all    # Run all scanners
```

### AI Tools

LLM-powered analysis and reporting tools that consume scanner output.

#### `haka_ai_reporter.py` — AI Report Engine

Generates professional, client-ready security assessment reports from HAKA scan findings.

```bash
# Technical report (full detail)
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json

# Executive summary for board/regulators
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json --mode executive

# One-page leave-behind (top 3 findings)
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json --mode onepager

# Remediation roadmap only
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json --mode remediation

# Process a directory of scanner JSONs
python3 haka_ai_reporter.py --input reports/ --mode executive

# Dry-run (preview prompt without LLM call)
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json --dry-run

# Interactive mode (refine each section)
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json --interactive

# Use specific model
python3 haka_ai_reporter.py --input reports/haka_consolidated_cbe.json \
    --model deepseek-r1:7b --output /tmp/cbe_report.md
```

**Report Modes:**

| Mode | Description | Best For |
|------|-------------|----------|
| `executive` | 2-3 paragraph business summary, top risks, priorities | Board, regulators |
| `technical` | Full findings, MITRE mapping, methodology | Security teams, auditors |
| `onepager` | Top 3 critical issues, fits on one page | Leave-behind, quick briefs |
| `remediation` | Phased action plan, effort estimates, verification | Project planning, compliance |

**Input formats:** Consolidated JSONs (preferred), individual scanner JSONs, or directory of JSONs (auto-merges).

#### `haka_chat.py` — Natural Language Query Interface

Interactive chat for querying HAKA scan findings in plain English.

```bash
# One-shot queries
python3 haka_chat.py -q "show me critical findings at CBE"
python3 haka_chat.py -q "compare CBE and Awash Bank"
python3 haka_chat.py -q "which bank has the worst email security"
python3 haka_chat.py -q "how many banks have exposed Exchange servers"

# Filter by target
python3 haka_chat.py -q "list all findings" --target cbe

# Interactive REPL
python3 haka_chat.py --interactive
python3 haka_chat.py -i --target awash

# Preview context
python3 haka_chat.py -q "find anything related to SWIFT" --dry-run
```

**Interactive REPL commands:** `targets`, `stats`, `model <name>`, `filter <target>`, `help`, `quit`

**Smart context selection** filters findings by target name, severity, technology keywords, and intent detection (comparison, pattern analysis, lookup).

#### `haka_attack_paths.py` — Attack Path Constructor

Chains HAKA findings into realistic multi-step attack scenarios following MITRE ATT&CK kill chain.

```bash
# Generate 3 attack paths for CBE
python3 haka_attack_paths.py --target cbe

# 5 paths for Awash, save to file
python3 haka_attack_paths.py --target awash --count 5 --output attack_paths_awash.md

# Use local model
python3 haka_attack_paths.py --target cbe --model r1 --count 2
```

**Output:** Named attack paths, risk levels, kill chain stage coverage, step-by-step narrative tied to finding IDs, adversary profiles, impact assessments.

#### `haka_compliance.py` — Regulatory Compliance Mapper

Maps HAKA findings to regulatory frameworks: NBE cybersecurity directives, ISO 27001, PCI-DSS.

```bash
# Single framework
python3 haka_compliance.py --target cbe --framework nbe

# All targets, all frameworks
python3 haka_compliance.py --framework all --output compliance_full.md

# Specific target + framework
python3 haka_compliance.py --target awash --framework pcidss
```

**Output:** Compliance scores per framework, finding-to-control mapping tables, critical compliance gaps (3+ control violations), regulatory risk statements, prioritized remediation roadmap.

**Embedded controls:** 30 NBE controls across 10 directives (SBB/77/2020, FIS/01/2021, FIS/02/2019, CIS/01/2022, Risk Management Guidelines, Data Protection Proclamation, Email Security, DNS Security, Network Security, Access Control).

#### `haka_threat_intel.py` — CVE & Exploit Intelligence

Extracts software versions from findings and enriches with CVE data, CVSS scores, exploit availability.

```bash
# Full CVE analysis
python3 haka_threat_intel.py --target cbe

# Only exploitable findings
python3 haka_threat_intel.py --target cbe --exploit-only

# Save to file
python3 haka_threat_intel.py --target awash --output threat_intel_awash.md
```

**Output:** Software inventory table, per-product CVE lists with CVSS scores, exploit availability matrix (public PoC, Metasploit, CISA KEV), prioritized patching roadmap.

### Detectors (`detectors/`)

Active monitoring and detection tools for ongoing security operations.

| Tool | Description |
|------|-------------|
| `haka_spray_detector.py` | Password spray attack detection via EVTX log analysis |
| `haka_kerberos_detector.py` | Kerberos attack detection (Golden/Silver Ticket, AS-REP roasting) |
| `haka_wazuh_ai.py` | AI-enhanced Wazuh SIEM integration for anomaly detection |

```bash
python3 detectors/haka_spray_detector.py --evtx security.evtx
python3 detectors/haka_kerberos_detector.py --dc 10.0.0.1
python3 detectors/haka_wazuh_ai.py --alert-file alerts.json
```

### Business Tools

Client management and invoicing for security consulting engagements.

#### `haka_crm.py` — Client & Pipeline Tracker

Lightweight CRM for tracking security consulting engagements. Uses SQLite (no external DB).

```bash
# Add a client
python3 haka_crm.py --add-client --name "Abebe Kebede" --org "CBE" \
    --email "ak@cbe.com.et" --status prospect

# List all clients
python3 haka_crm.py --list-clients

# Add an engagement
python3 haka_crm.py --add-engagement --client 1 --type external_assessment \
    --value 8000 --status proposed

# List engagements
python3 haka_crm.py --list-engagements

# Show pipeline
python3 haka_crm.py --pipeline

# Export pipeline to markdown
python3 haka_crm.py --pipeline --export

# Update client/engagement status
python3 haka_crm.py --update --client 1 --status active
python3 haka_crm.py --update --engagement 1 --status signed
```

**Database:** `~/.haka/haka_crm.db` (auto-created)

#### `haka_invoice.py` — Invoice Generator

Generates professional invoices for security consulting work. Outputs Markdown.

```bash
# Generate from client name + line items
python3 haka_invoice.py --client "CBE" \
    --items "External Security Assessment:8000" \
    --items "Remediation Roadmap:2000"

# Generate from CRM engagement (auto-fills type + value)
python3 haka_invoice.py --engagement 1

# Custom invoice number, dates
python3 haka_invoice.py --client "Awash Bank" \
    --items "Full Penetration Test:15000" \
    --number HAKA-2026-005 \
    --date 2026-05-01 --due 2026-06-15 \
    --output /tmp/awash_invoice.md

# List all invoices
python3 haka_invoice.py --list

# Mark as paid
python3 haka_invoice.py --paid HAKA-2026-001
```

**Invoice includes:** HAKA Security header, invoice/dates, client info, line items, subtotal, 15% VAT (Ethiopia), total, payment instructions, professional footer. Numbering: `HAKA-YYYY-NNN`.

---

## Provider & Model Setup

HAKA uses a unified provider layer (`haka_providers.py`) supporting local Ollama and cloud APIs.

### Model Shortcuts

| Shortcut | Full Model | Provider |
|----------|-----------|----------|
| `openclaw` | openclaw/default | OpenClaw Gateway (local, same model) |
| `deepseek` | deepseek-chat | DeepSeek API |
| `claude` | claude-sonnet-4-20250514 | Anthropic |
| `claude-opus` | claude-opus-4-20250514 | Anthropic |
| `claude-haiku` | claude-haiku-4-5-20250514 | Anthropic |
| `gpt5` | gpt-4o | OpenAI |
| `qwen` | qwen3:32b | Ollama (local) |
| `r1` | deepseek-r1:7b | Ollama (local) |
| `gemma` | gemma3:27b | Ollama (local) |
| `coder` | qwen2.5-coder:7b | Ollama (local) |

### API Key Setup

#### OpenClaw Gateway (zero config)
The `openclaw` shortcut auto-discovers the gateway token from `~/.openclaw/openclaw.json`.
No setup needed — just make sure the gateway chat completions endpoint is enabled.

#### Cloud APIs
Place keys in any of these (auto-discovered):
- `~/.deepseek.env`
- `~/HAKA-AI/.env`
- `~/kewani-bot/.env`
- Environment variables: `DEEPSEEK_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`

```bash
# Example ~/.deepseek.env
export DEEPSEEK_API_KEY="sk-your-key-here"
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

### Local Models (Ollama)

```bash
# Pull recommended models
ollama pull qwen3:32b          # 20 GB — best quality reports
ollama pull deepseek-r1:7b      # 4.7 GB — fast chat queries
ollama pull gemma3:27b          # 17 GB — alternative for reports
ollama pull qwen2.5-coder:7b    # 4.7 GB — code analysis

# Usage
python3 haka_ai_reporter.py --model qwen --input reports/haka_consolidated_cbe.json
python3 haka_chat.py --model r1 -q "show me critical findings"
```

---

## Directory Structure

```
HAKA-AI/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── haka_providers.py            # Unified LLM backend
│
├── scanners/                    # Security assessment scanners
│   ├── haka_ai.py               # Master orchestrator
│   ├── haka_exchange_scanner.py
│   ├── haka_email_scanner.py
│   ├── haka_dns_scanner.py
│   ├── haka_tls_scanner.py
│   ├── haka_web_scanner.py
│   ├── haka_s3_scanner.py
│   ├── haka_vpn_scanner.py
│   ├── haka_collab_scanner.py
│   └── haka_ct_scanner.py
│
├── detectors/                   # Active monitoring & detection
│   ├── haka_spray_detector.py
│   ├── haka_kerberos_detector.py
│   └── haka_wazuh_ai.py
│
├── haka_ai_reporter.py          # AI report engine
├── haka_chat.py                 # NL query interface
├── haka_attack_paths.py         # Attack path constructor
├── haka_compliance.py           # Regulatory compliance mapper
├── haka_threat_intel.py         # CVE & exploit intelligence
│
├── haka_crm.py                  # Client & pipeline tracker
├── haka_invoice.py              # Invoice generator
│
├── dashboard.html               # Web dashboard
├── dashboard_server.py          # Dashboard HTTP server
│
├── reports/                     # Scan output (JSON)
│   ├── haka_consolidated_cbe.json
│   ├── haka_consolidated_awash.json
│   ├── haka_consolidated_dashen.json
│   ├── haka_consolidated_boa.json
│   ├── haka_consolidated_ethiotelecom.json
│   ├── haka_consolidated_telebirr.json
│   └── haka_consolidated_etaf.json
│
└── resources/                   # Static resources
```

---

## Data Summary

**7 targets across Ethiopian financial sector — 137 findings**

| Target | File | Findings |
|--------|------|----------|
| CBE | `haka_consolidated_cbe.json` | 31 (12 CRIT, 19 HIGH) |
| Awash Bank | `haka_consolidated_awash.json` | 25 (9 CRIT, 16 HIGH) |
| Ethio Telecom | `haka_consolidated_ethiotelecom.json` | 23 (9 CRIT, 14 HIGH) |
| Dashen Bank | `haka_consolidated_dashen.json` | 20 (7 CRIT, 13 HIGH) |
| Bank of Abyssinia | `haka_consolidated_boa.json` | 18 (6 CRIT, 12 HIGH) |
| Telebirr | `haka_consolidated_telebirr.json` | 17 (7 CRIT, 10 HIGH) |
| ETAF | `haka_consolidated_etaf.json` | 3 (3 HIGH) |

---

## Output Files Explained

| Output Type | Format | Generated By | Content |
|-------------|--------|-------------|---------|
| Scanner reports | JSON | All scanners | Raw findings with severity, evidence, remediation |
| Consolidated reports | JSON | `haka_ai.py` | Merged findings across all scanners per target |
| AI reports | Markdown | `haka_ai_reporter.py` | Professional reports (executive, technical, onepager, remediation) |
| Attack paths | Markdown | `haka_attack_paths.py` | Multi-step attack scenarios with kill chain mapping |
| Compliance reports | Markdown | `haka_compliance.py` | Framework compliance scores, gap analysis, roadmaps |
| Threat intel | Markdown | `haka_threat_intel.py` | CVE lists, CVSS scores, exploit availability |
| Pipeline reports | Markdown | `haka_crm.py --export` | Sales pipeline summary with values by stage |
| Invoices | Markdown | `haka_invoice.py` | Professional invoices for client delivery |
