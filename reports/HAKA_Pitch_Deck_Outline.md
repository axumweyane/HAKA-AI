# HAKA Security — Pitch Deck Outline
## "Ethiopian Banking Security: An Urgent Assessment"
### April 2026 | 10-Slide Investor/Client Presentation

---

## Slide 1: Title — "Ethiopian Banking Security: An Urgent Assessment"

**Visual:** HAKA logo + stylized Ethiopian banking sector skyline (CBE tower, Ethio Telecom HQ)

**Key Message:**
> Ethiopia's financial sector is in the midst of unprecedented digital growth — and unprecedented cyber risk. As the NBE enforces new cybersecurity directives, we assessed 7 of the country's most critical financial institutions. What we found demands immediate attention.

**Bullet Points:**
- 7 Ethiopian financial/government targets assessed
- 50 critical vulnerabilities discovered
- Every bank can be impersonated via email
- The first Ethiopian-owned firm to produce this data

---

## Slide 2: The Landscape — Why Ethiopia, Why Now

**Visual:** Timeline graphic showing: CBE 2024 Breach → NBE Cybersecurity Directives → HAKA Assessment → Now

**Key Message:**
> The 2024 CBE breach demonstrated that Ethiopian banks are targets. The NBE is now enforcing cybersecurity standards. And Ethiopia has no domestic cybersecurity industry to meet the demand.

**Supporting Points:**
- CBE 2024 breach: one of the largest financial incidents in Ethiopian history
- NBE cybersecurity directives now mandate minimum security standards
- International assessment firms charge $50K-150K+ per engagement
- No Ethiopian-owned firm has conducted sector-wide assessments — until now
- All .et domains share single DNS infrastructure (Ethio Telecom) — systemic risk

**Speaker Notes:** Frame this as an opportunity gap. Ethiopian banks need assessments. Currently, the only options are expensive international firms with no local context. HAKA fills this gap.

---

## Slide 3: What We Found — 7-Target Sweep Summary

**Visual:** Bar chart showing risk scores descending: CBE 95, Awash 90, Ethio Telecom 88, Dashen 85, telebirr 82, BoA 80, ETAF 25

**Key Message:**
> We conducted passive external assessments on 7 of Ethiopia's most critical institutions. Six scored above 80/100 on our risk scale. Only ETAF demonstrated adequate external security posture.

**Summary Table:**

| Target | Risk | Critical | High | Signature Finding |
|--------|------|----------|------|--------------------|
| CBE | 95 | 12 | 19 | No DMARC, exposed Exchange, public S3 |
| Awash Bank | 90 | 9 | 16 | Exchange exposed, 129 internal hosts in certs |
| Ethio Telecom | 88 | 9 | 14 | phpinfo.php public, 365 hosts exposed |
| Dashen Bank | 85 | 7 | 13 | cPanel/WHM exposed, .git on production |
| telebirr | 82 | 7 | 10 | 798 MB debug.log public, domain squatted |
| BoA | 80 | 6 | 12 | Mattermost public/no MFA, CORS wildcard |
| ETAF | 25 | 0 | 3 | Minimal external footprint — good posture |

**Collective: 50 Critical | 87 High | All externally discoverable, no intrusive testing needed**

**Speaker Notes:** Emphasize that we found all of this through passive reconnaissance and basic external scanning. We never touched production systems. This is what any motivated adversary can see with zero special access.

---

## Slide 4: CBE Deep Dive — Ethiopia's Largest Bank at 95/100 Risk

**Visual:** CBE logo + redacted infrastructure diagram showing exposed services

**Key Message:**
> The Commercial Bank of Ethiopia — serving 30+ million customers — scored 95/100 on our risk assessment. The primary brand domain can be perfectly impersonated via email with zero technical barriers.

**Top Findings:**
1. **Email completely spoofable:** No DMARC, no DKIM on combanketh.et — attackers can send email as @combanketh.et to any customer, partner, or correspondent bank worldwide
2. **Exchange 2019 CU14 fully exposed:** OWA, ECP, EWS, MAPI, RPC, OAB — all accessible from the internet with NTLM authentication. 9+ backend servers mapped including DR site
3. **SWIFT infrastructure in public certificates:** mfaswift, mfashiftdev, mfashifttest hostnames visible to anyone searching certificate transparency logs
4. **S3 bucket 'cbe' publicly listable:** 26 files, including 3.4 MB JavaScript bundle — exposed without authentication
5. **SonicWall VPN with known critical exploits:** CVE-2021-20016 (CVSS 9.8) and CVE-2024-40766 (CVSS 9.3, exploited by Akira ransomware)

**Business Impact Statement:**
> "CBE's external attack surface is the largest of any assessed target. An adversary could phish every CBE customer, map the bank's payment infrastructure, and extract application source code — all from passive reconnaissance alone."

---

## Slide 5: Awash Bank Deep Dive — 129 Internal Systems on Public Display

**Visual:** Awash Bank logo + 129-hostnames word cloud (vcenter, sap, pam, wso2, etc.)

**Key Message:**
> Awash Bank's certificate transparency logs expose 129 internal hostnames — effectively publishing the bank's entire enterprise architecture diagram to the public internet.

**Top Findings:**
1. **Complete enterprise architecture exposed:** 129 hostnames from 1,217 certificates including vcenter (virtualization), cbs (core banking system), sap (ERP), pam (privileged access management), xg (firewall), f5bigip (load balancer), adselfservice
2. **F5 BIG-IP cookie decodes to internal IP:** Internal IP 10.10.13.98 revealed in unencrypted load balancer cookie — anyone can map internal network topology
3. **Every Exchange service exposed, including PowerShell:** Single server, no HA/DR, PowerShell accessible from internet
4. **TLS 1.0 and 1.1 still enabled:** 3 generations of TLS — including the completely broken TLS 1.0
5. **Bank website on shared US hosting:** Same provider (HostDime) as Dashen Bank — shared with unrelated commercial websites

**Business Impact Statement:**
> "The 129 internal hostnames in certificate transparency logs provide anyone with a complete map of Awash's infrastructure — knowing the bank runs vcenter, SAP, and a privileged access management system tells attackers exactly where to focus."

---

## Slide 6: Cross-Cutting Patterns — Every Bank Has the Same Problems

**Visual:** Six-column comparison with red/yellow/green indicators across DMARC/DKIM/DNSSEC/HSTS/CSP

**Key Message:**
> The same vulnerabilities appear across every Ethiopian financial institution. These aren't isolated incidents — they're systemic failures that require sector-wide intervention.

**The Six Systemic Patterns:**

| Pattern | CBE | Awash | Ethio Tel | Dashen | telebirr | BoA |
|---------|-----|-------|-----------|--------|----------|-----|
| Domain Spoofable via Email | ✅ | ✅ | 🟡 | ✅ | ✅ | ✅ |
| No DNSSEC | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Internal Hosts in CT Logs | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| No DKIM | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Security Headers Missing | ✅ | ✅ | ✅ | ✅ | ✅ | 🟡 |
| Server Versions Disclosed | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ |

**The Single Point of Failure:**
- All .et domains use ns1/ns2.telecom.net.et
- Ethio Telecom controls DNS for every bank
- Compromise Ethio Telecom DNS = redirect ALL Ethiopian banking traffic

**Speaker Notes:** This is the slide that shows why HAKA's sector-wide view is uniquely valuable. Individual banks see their own issues. We see the pattern.

---

## Slide 7: Our Approach — The HAKA Methodology

**Visual:** Four-phase methodology diagram

**Key Message:**
> We use a phased, risk-based approach that starts with what anyone can see — and builds to comprehensive internal assessment. Every engagement is adapted to the client's specific infrastructure.

**Phase 1 — External Security Posture Assessment (1-2 weeks)**
- Certificate transparency log analysis
- DNS enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, DNSSEC, CAA)
- Email security configuration (SPF, DKIM, DMARC, MTA-STS, BIMI)
- HTTP security header analysis
- TLS/SSL configuration assessment
- Cloud storage bucket discovery
- VPN and remote access endpoint identification
- Web server fingerprinting and version disclosure
- Subdomain enumeration
- **Deliverable:** Executive report with risk score, prioritized findings, remediation roadmap

**Phase 2 — Full External Penetration Testing (2-4 weeks)**
- Authenticated and unauthenticated web application testing
- API security testing
- Network service vulnerability assessment
- Social engineering simulation (phishing, pretexting)
- Wireless security assessment (if applicable)
- **Deliverable:** Technical report with proof-of-concept, CVSS scoring, MITRE ATT&CK mapping

**Phase 3 — Internal Security Assessment (1-3 weeks on-site)**
- Internal network segmentation testing
- Active Directory security review
- Endpoint security configuration audit
- Privilege escalation path analysis
- Data exfiltration path testing
- **Deliverable:** Full technical report with exploitation paths and detection recommendations

**Phase 4 — Continuous Monitoring (Ongoing)**
- Quarterly external reassessment
- Certificate transparency monitoring
- DNS and email security change detection
- Dark web credential monitoring
- Monthly executive summary reports

**All assessments include:**
- Risk scoring aligned with CVSS
- MITRE ATT&CK framework mapping
- Executive summary for board/NBE reporting
- Technical appendix for IT teams
- 90-day remediation support

---

## Slide 8: Service Packages

**Visual:** Three-column service tier comparison

**Key Message:**
> We offer flexible engagement models from basic external assessment to comprehensive ongoing security programs — all priced for Ethiopian institutions.

### Package 1: External Security Assessment
**$5,000 — $8,000 | 2-week engagement**

Includes:
- Full passive reconnaissance (CT logs, DNS, email security, cloud discovery)
- External infrastructure vulnerability scanning
- Web application security header analysis
- TLS/SSL configuration assessment
- Executive report with risk score and prioritized findings
- Remediation roadmap with technical recommendations
- 30-day email support for remediation questions

**Deliverable: 20-30 page report with executive summary and technical appendix**

---

### Package 2: Full External + Internal Penetration Test
**$15,000 — $25,000 | 3-6 week engagement**

Includes everything in Package 1 plus:
- Authenticated and unauthenticated penetration testing
- API security testing
- Internal network assessment (on-site)
- Active Directory security review
- Social engineering simulation
- MITRE ATT&CK kill-chain mapping
- Wazuh SIEM detection rule recommendations
- Executive presentation to board/management
- 90-day remediation support

**Deliverable: 50-80 page technical report with proof-of-concept, CVSS scoring, and detection engineering recommendations**

---

### Package 3: Quarterly Security Retainer
**$20,000 — $40,000/year | 4 assessments/year**

Includes:
- Quarterly external security posture reassessment
- Continuous certificate transparency monitoring
- DNS and email security change detection
- Dark web credential monitoring for your domain
- Monthly executive summary reports
- Priority incident response access
- Annual full penetration test included

**Best for: Banks and financial institutions requiring NBE compliance documentation**

---

### Add-On: Incident Response Retainer
**$2,000/month | 24/7 availability**

Includes:
- Priority incident response team access
- 4-hour response SLA during business hours
- 12-hour response SLA outside business hours
- Incident containment and forensic analysis
- Post-incident report and remediation roadmap
- Annual tabletop exercise

---

## Slide 9: Pricing & ROI

**Visual:** Cost comparison: HAKA vs International Firms vs Cost of Breach

**Key Message:**
> The cost of assessment is a fraction of the cost of a breach. And HAKA's pricing is designed for Ethiopian institutions — not international consulting rates.

**Price Comparison:**

| Engagement Type | International Firm | HAKA Security |
|----------------|-------------------|---------------|
| External Assessment | $25K-50K | $5K-8K |
| Full Pentest | $75K-150K | $15K-25K |
| Quarterly Retainer | $80K-200K/yr | $20K-40K/yr |
| IR Retainer | $5K-10K/mo | $2K/mo |

**HAKA Advantage:**
- 60-80% cost savings vs. international firms
- Local context — we understand Ethiopian infrastructure, telecom dependencies, and regulatory requirements
- Faster turnaround — no international travel/logistics
- Reports tailored for NBE regulatory submission
- Founded and staffed by Ethiopian security professionals

**The ROI of Prevention:**
- Average cost of a data breach in financial services: $5.9M (IBM 2025)
- CBE 2024 breach: estimated cost in the tens of millions
- A single DMARC deployment prevents 90%+ of domain spoofing — cost: included in our $5K assessment
- The SIM swap attack chain we identified affects every bank — cost to fix: coordinated telecom/banking policy, not technology

---

## Slide 10: Call to Action — "Schedule Your Assessment"

**Visual:** HAKA logo + contact information + "Secure Ethiopia's Financial Future"

**Key Message:**
> Your institution's external security posture is visible to anyone with an internet connection right now. The question is: who will see it first — your security team, or an adversary?

**Three Immediate Actions:**

1. **Schedule an External Assessment**
   - 2-week engagement, comprehensive report
   - Cost: $5,000-$8,000
   - Deliverable: Risk score, prioritized findings, remediation roadmap
   - First step toward NBE compliance

2. **Request a Capability Briefing**
   - 1-hour presentation to your security team or board
   - Tailored to your institution's infrastructure
   - Includes preliminary findings (if available)

3. **Join the HAKA Financial Security Working Group**
   - Cross-institutional threat intelligence sharing
   - Coordinated remediation of systemic issues (DNS, SIM swap, email security)
   - Quarterly sector-wide security briefings

**Contact:**
- 📧 [Email Placeholder]
- 📞 [Phone Placeholder]
- 🌐 [Website Placeholder]
- 📍 Addis Ababa, Ethiopia

**Closing Statement:**
> Ethiopia's financial sector is growing faster than its cybersecurity capabilities. HAKA exists to close that gap — with Ethiopian expertise, Ethiopian pricing, and Ethiopian commitment to securing our country's financial future.

---

*This document is a pitch deck outline. Final presentation slides require graphic design, data visualization, and formatting for the target audience.*
