# HAKA Security Consulting

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗  ██╗ █████╗ ██╗  ██╗ █████╗                             ║
║   ██║  ██║██╔══██╗██║ ██╔╝██╔══██╗                            ║
║   ███████║███████║█████╔╝ ███████║                            ║
║   ██╔══██║██╔══██║██╔═██╗ ██╔══██║                            ║
║   ██║  ██║██║  ██║██║  ██╗██║  ██║                            ║
║   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝                            ║
║                                                              ║
║          Ethiopian Financial Sector Security                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

# Cybersecurity Assessment Proposal

**Proposal Number:** `HAKA-PROP-2026-008`

**Prepared For:** `Commercial Bank of Ethiopia`

**Prepared By:** HAKA Security Consulting  
Owner & Principal Consultant: Tigray  

**Date:** `28 April 2026`

---

## Confidentiality Notice

This document contains proprietary information intended solely for the recipient. Do not distribute or reproduce without prior written consent of HAKA Security Consulting.

---

## 1. Executive Summary

HAKA Security Consulting is an Ethiopian cybersecurity firm specializing in security assessments for the financial services and telecommunications sectors. We combine automated scanning, manual testing, and AI-driven analysis to deliver actionable security intelligence to our clients.

This proposal outlines a `External Vulnerability Assessment` for **`Commercial Bank of Ethiopia`** . The engagement is designed to identify vulnerabilities in Internet-facing systems, assess their risk to the organization, and provide a prioritized remediation plan.

Our approach is informed by experience assessing `seven (7)` major Ethiopian financial and telecom institutions, adherence to industry frameworks (NIST, OWASP, MITRE ATT&CK), and alignment with National Bank of Ethiopia cybersecurity directives.

---

## 2. Scope of Work

### 2.1 Engagement Type

****External Vulnerability Assessment****

### 2.2 Methodology

The assessment will follow a structured, phased methodology:

| Phase | Activity |
|-------|----------|
| **1. Reconnaissance** | Passive information gathering, domain enumeration, subdomain discovery, technology fingerprinting |
| **2. Vulnerability Scanning** | Automated scanning of all in-scope assets using industry-standard tools, supplemented by manual verification |
| **3. Manual Testing** | Hands-on validation of findings, elimination of false positives, chaining of low-severity issues into attack paths |
| **4. Analysis** | AI-assisted correlation of findings with threat intelligence, MITRE ATT&CK mapping, and regulatory compliance review |
| **5. Reporting** | Production of executive summary, technical report, and prioritized remediation roadmap |

### 2.3 Tools & Techniques

The following may be employed during the engagement:

- **Reconnaissance:** DNS enumeration, certificate transparency log analysis, WHOIS queries, passive OSINT
- **Vulnerability Scanning:** Industry-standard vulnerability scanners, custom HAKA assessment tools
- **Web Application Testing:** OWASP Top 10 assessment, API testing, authentication testing
- **TLS/SSL Analysis:** Cipher suite evaluation, certificate chain validation, protocol version assessment
- **Email Security:** SPF/DKIM/DMARC validation, mail server configuration review
- **Network Perimeter:** Port scanning, service enumeration, banner grabbing

### 2.4 In-Scope Assets

```
[Client to provide list of in-scope assets]


**External Vulnerability Assessment**

The engagement will evaluate the security posture of Internet-facing systems, including web applications, email infrastructure, VPN endpoints, DNS configuration, and TLS/SSL implementation. Assessment includes automated vulnerability scanning, manual validation of findings, and MITRE ATT&CK mapping.

**Typical duration:** 2–3 weeks
**In-scope by default:** External IP ranges, public-facing domains, email security (SPF/DKIM/DMARC), TLS configuration, web application perimeter.
e.g.:
- *.clientbank.com.et
- 196.188.x.x/24 (external perimeter)
- mail.clientbank.com.et
- vpn.clientbank.com.et
```

### 2.5 Explicitly Out of Scope

Unless otherwise agreed in writing, the following are **not** included in this engagement:

- **Denial of Service (DoS)** testing of any kind
- **Social engineering** (phishing, pretexting, vishing, physical impersonation)
- **Physical security** testing or site access
- **Internal network** testing (unless explicitly listed in scope above)
- **Third-party** systems, suppliers, or cloud services not owned or operated by the client
- **Production data** access, modification, or exfiltration
- **Code review** or static analysis of source code

Any findings discovered incidentally in out-of-scope areas will be reported to the client as a courtesy but will not be formally assessed.

---

## 3. Deliverables

Upon completion of the engagement, HAKA Security Consulting will deliver:

| Deliverable | Description |
|-------------|-------------|
| **Executive Report** | 2–3 page summary for management and board-level stakeholders. Risk overview, top findings, and strategic recommendations. |
| **Technical Report** | Detailed findings catalog with severity ratings, CVSS scores, evidence, steps to reproduce, and technical remediation guidance. |
| **Remediation Roadmap** | Prioritized action plan organized by phase (immediate, short-term, long-term), with effort estimates and verification steps. |
| **Findings Database** | Structured export (CSV/JSON) of all findings for integration with the client's internal tracking systems. |

All deliverables are provided in both **PDF** and **original format** (Markdown/CSV) within [FILL] business days of assessment completion.

---

## 4. Timeline

| Milestone | Estimated Date | Duration |
|-----------|---------------|----------|
| **Project Kickoff** | `[Client to confirm]` | ½ day |
| **Reconnaissance & Scanning** | `[Client to confirm]` | [FILL] |
| **Manual Validation** | [FILL] | [FILL] |
| **Analysis & Report Drafting** | [FILL] | [FILL] |
| **Report Delivery** | `[TBD upon kickoff]` | ½ day (walkthrough) |
| **Total Duration** | **[FILL]** | |

The schedule assumes timely provision of required information and access by the client.

---

## 6. Pricing

### Service Fee

| Item | Amount (USD) |
|------|-------------|
| **External Vulnerability Assessment** | **$8,000** |
| VAT (15%) — applicable only if VAT-registered | $1,200 |
| **Total** | **$9,200** |

*Fees are quoted in United States Dollars (USD). Equivalent in Ethiopian Birr (ETB) will be calculated at the NBE reference rate on the invoice date.*

### Payment Terms

- **50%** upon signing of this proposal and issuance of the kickoff notice
- **50%** upon delivery of the final report
- Invoices are payable within [FILL] calendar days
- Payments by bank transfer to the HAKA Security Consulting account at Dashen Bank

### Expenses

Any pre-approved out-of-pocket expenses (e.g., travel outside Addis Ababa, specialized tool licenses) will be billed at cost with receipts.

---

## 7. Terms & Conditions

### 7.1 Confidentiality

All information shared during the engagement shall be treated as confidential. HAKA Security Consulting will execute a Mutual Non-Disclosure Agreement before work begins. Findings, reports, and data belong exclusively to the client upon full payment.

### 7.2 Authorization

The client warrants that it owns or has authorization to test all assets listed in the scope of work. The client is responsible for obtaining any third-party approvals (e.g., from hosting providers, cloud providers, or parent entities).

### 7.3 Limitation of Liability

To the fullest extent permitted by Ethiopian law, HAKA Security Consulting's total liability for any claim arising from this engagement shall not exceed the total fees paid under this proposal. HAKA Security Consulting shall not be liable for indirect, consequential, or incidental damages.

Vulnerability assessments are point-in-time evaluations. A clean assessment does not guarantee the absence of vulnerabilities or that systems are immune to future attacks.

### 7.4 Independent Contractor

HAKA Security Consulting is an independent contractor. Nothing in this proposal creates a partnership, joint venture, employment, or agency relationship between the parties.

### 7.5 Non-Solicitation

During the engagement and for [FILL] months thereafter, neither party shall solicit or hire the other party's personnel directly involved in the engagement without mutual written consent.

### 7.6 Governing Law

This proposal and any resulting agreement shall be governed by the laws of the Federal Democratic Republic of Ethiopia. Any disputes shall be resolved through arbitration in Addis Ababa.

### 7.7 Validity

This proposal is valid for [FILL] calendar days from the date above.

---

## 8. Acceptance

By signing below, the parties agree to the scope, pricing, and terms outlined in this proposal.

---

### For HAKA Security Consulting

```
Signature: ___________________________________
Name:      Tigray
Title:     Owner & Principal Consultant
Date:      ___________________________________
```

---

### For Commercial Bank of Ethiopia

```
Signature: ___________________________________
Name:      [Authorized Signatory Name]
Title:     [Title — CISO, CTO, CEO]
Date:      ___________________________________
```

---

> **Proposal Checklist**
> Before sending, confirm:
> - [ ] Proposal number (HAKA-PROP-YYYY-NNN)
> - [ ] Client name throughout
> - [ ] Engagement type (Executive Summary + Scope)
> - [ ] In-scope assets listed
> - [ ] Deliverable timeline filled
> - [ ] Pricing table complete
> - [ ] Payment terms specified
> - [ ] Validity period set
> - [ ] Signature blocks have client name

---

*HAKA Security Consulting — Ethiopian Financial Sector Security Assessments*
*github.com/axumweyane/HAKA-AI*

---

*Document: Proposal_Template.md — Generated by HAKA Security Consulting*
