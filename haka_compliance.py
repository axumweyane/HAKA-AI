#!/usr/bin/env python3
"""
HAKA Regulatory Compliance Mapper — Phase 3
Maps HAKA findings to regulatory frameworks and generates compliance gap analysis.
Focus: NBE (National Bank of Ethiopia) cybersecurity directives,
       ISO 27001, and PCI-DSS.

Usage:
  python3 haka_compliance.py
  python3 haka_compliance.py --target cbe --framework nbe
  python3 haka_compliance.py --target awash --framework all --output compliance_awash.md
  python3 haka_compliance.py --framework iso27001
"""

import argparse
import json
import os
import sys
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from haka_providers import HakaLLM


# ── Regulatory Framework Definitions ────────────────────────────────────────

NBE_CONTROLS = {
    "NBE-SBB-77-2020-01": {
        "directive": "SBB/77/2020",
        "name": "Annual Vulnerability Assessment",
        "description": "Banks must conduct annual vulnerability assessments and penetration tests on all critical systems.",
        "category": "Security Assessment",
    },
    "NBE-SBB-77-2020-02": {
        "directive": "SBB/77/2020",
        "name": "Vulnerability Remediation Timelines",
        "description": "Critical vulnerabilities must be remediated within 72 hours, high within 7 days.",
        "category": "Vulnerability Management",
    },
    "NBE-SBB-77-2020-03": {
        "directive": "SBB/77/2020",
        "name": "Independent Penetration Testing",
        "description": "Third-party penetration testing required annually; results reported to NBE.",
        "category": "Security Assessment",
    },
    "NBE-FIS-01-2021-01": {
        "directive": "FIS/01/2021",
        "name": "MFA for Internet Banking",
        "description": "Multi-factor authentication required for all internet banking access and sensitive transactions.",
        "category": "Access Control",
    },
    "NBE-FIS-01-2021-02": {
        "directive": "FIS/01/2021",
        "name": "Encryption Standards",
        "description": "TLS 1.2 minimum for all internet banking; TLS 1.0/1.1 prohibited. Strong cipher suites required.",
        "category": "Encryption",
    },
    "NBE-FIS-01-2021-03": {
        "directive": "FIS/01/2021",
        "name": "Session Management",
        "description": "Secure session management: timeouts, secure cookies, anti-CSRF tokens, proper logout.",
        "category": "Application Security",
    },
    "NBE-FIS-01-2021-04": {
        "directive": "FIS/01/2021",
        "name": "Security Headers",
        "description": "All internet banking portals must implement HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
        "category": "Application Security",
    },
    "NBE-FIS-02-2019-01": {
        "directive": "FIS/02/2019",
        "name": "Business Continuity Plan",
        "description": "Documented BCP tested annually; recovery time objectives defined for critical systems.",
        "category": "Business Continuity",
    },
    "NBE-FIS-02-2019-02": {
        "directive": "FIS/02/2019",
        "name": "Disaster Recovery Site",
        "description": "Secondary DR site required; geographically separated from primary. Regular DR testing.",
        "category": "Business Continuity",
    },
    "NBE-FIS-02-2019-03": {
        "directive": "FIS/02/2019",
        "name": "High Availability Architecture",
        "description": "Single points of failure must be eliminated. Load balancing, clustering, failover required.",
        "category": "Business Continuity",
    },
    "NBE-CIS-01-2022-01": {
        "directive": "CIS/01/2022",
        "name": "SWIFT Network Segmentation",
        "description": "SWIFT infrastructure must be isolated from internet and general corporate network with firewalls.",
        "category": "Network Security",
    },
    "NBE-CIS-01-2022-02": {
        "directive": "CIS/01/2022",
        "name": "Core Banking Isolation",
        "description": "Core banking systems must be logically or physically separated from corporate IT network.",
        "category": "Network Security",
    },
    "NBE-CIS-01-2022-03": {
        "directive": "CIS/01/2022",
        "name": "Critical Infrastructure Monitoring",
        "description": "24/7 security monitoring with SIEM; anomaly detection and incident response for critical systems.",
        "category": "Security Operations",
    },
    "NBE-RM-GUIDE-01": {
        "directive": "Risk Management Guidelines",
        "name": "Security Risk Assessment",
        "description": "Regular security risk assessments; risk register maintained and reviewed quarterly.",
        "category": "Risk Management",
    },
    "NBE-RM-GUIDE-02": {
        "directive": "Risk Management Guidelines",
        "name": "Vulnerability Management Program",
        "description": "Formal vulnerability management program: scanning, triage, remediation tracking, metrics.",
        "category": "Vulnerability Management",
    },
    "NBE-RM-GUIDE-03": {
        "directive": "Risk Management Guidelines",
        "name": "Incident Response Capability",
        "description": "Documented incident response plan; IR team designated; annual tabletop exercises.",
        "category": "Incident Response",
    },
    "NBE-DP-PROC-01": {
        "directive": "Data Protection Proclamation",
        "name": "Customer Data Protection",
        "description": "Customer financial and personal data must be protected from unauthorized access or disclosure.",
        "category": "Data Protection",
    },
    "NBE-DP-PROC-02": {
        "directive": "Data Protection Proclamation",
        "name": "Data Encryption at Rest",
        "description": "Sensitive customer data must be encrypted at rest; key management controls required.",
        "category": "Data Protection",
    },
    "NBE-EMAIL-01": {
        "directive": "Email Security Standards",
        "name": "DMARC Implementation",
        "description": "DMARC policy required for all banking domains. Minimum p=quarantine; p=reject recommended.",
        "category": "Email Security",
    },
    "NBE-EMAIL-02": {
        "directive": "Email Security Standards",
        "name": "DKIM Signing",
        "description": "All outbound email must be DKIM-signed. DKIM selectors properly configured.",
        "category": "Email Security",
    },
    "NBE-EMAIL-03": {
        "directive": "Email Security Standards",
        "name": "SPF Configuration",
        "description": "Valid SPF record with hard fail (-all) for all sending domains. No open relays.",
        "category": "Email Security",
    },
    "NBE-EMAIL-04": {
        "directive": "Email Security Standards",
        "name": "MTA-STS & TLS-RPT",
        "description": "MTA-STS policy required for all email servers; TLS encryption enforced for SMTP transport.",
        "category": "Email Security",
    },
    "NBE-DNS-01": {
        "directive": "DNS Security Guidelines",
        "name": "DNSSEC Deployment",
        "description": "DNSSEC signing recommended for all banking domains to prevent DNS spoofing.",
        "category": "DNS Security",
    },
    "NBE-DNS-02": {
        "directive": "DNS Security Guidelines",
        "name": "CAA Records",
        "description": "CAA records required to restrict which CAs can issue certificates for banking domains.",
        "category": "DNS Security",
    },
    "NBE-DNS-03": {
        "directive": "DNS Security Guidelines",
        "name": "Reverse DNS Configuration",
        "description": "PTR records required for all mail server and critical infrastructure IPs.",
        "category": "DNS Security",
    },
    "NBE-NET-01": {
        "directive": "Network Security Standards",
        "name": "Network Segmentation",
        "description": "Core banking, corporate, DMZ, and development networks must be properly segmented.",
        "category": "Network Security",
    },
    "NBE-NET-02": {
        "directive": "Network Security Standards",
        "name": "Internal Services Isolation",
        "description": "Internal services (admin panels, dashboards, intranet) must not be exposed to internet.",
        "category": "Network Security",
    },
    "NBE-NET-03": {
        "directive": "Network Security Standards",
        "name": "VPN-Only Administrative Access",
        "description": "All administrative access must require VPN with MFA. Direct internet exposure prohibited.",
        "category": "Access Control",
    },
    "NBE-ACC-01": {
        "directive": "Access Control Standards",
        "name": "MFA for All Remote Access",
        "description": "MFA required for all remote access to banking systems, including email and administration.",
        "category": "Access Control",
    },
    "NBE-ACC-02": {
        "directive": "Access Control Standards",
        "name": "Least Privilege Enforcement",
        "description": "Access permissions must follow least privilege principle. Regular access reviews.",
        "category": "Access Control",
    },
}

ISO27001_CONTROLS = {
    "ISO-A.5.1": "Information security policies — documented and approved policies",
    "ISO-A.6.1": "Organization of information security — roles and responsibilities",
    "ISO-A.8.1": "Asset management — inventory and classification",
    "ISO-A.8.2": "Information classification — labeling and handling",
    "ISO-A.9.1": "Access control — business requirements for access control",
    "ISO-A.9.2": "User access management — provisioning, review, revocation",
    "ISO-A.9.4": "System and application access control — secure logon, password management",
    "ISO-A.10.1": "Cryptographic controls — encryption policy and key management",
    "ISO-A.11.1": "Physical security perimeter — secure areas",
    "ISO-A.12.1": "Operational procedures — documented operating procedures",
    "ISO-A.12.2": "Protection from malware — anti-malware controls",
    "ISO-A.12.3": "Backup — regular backups and testing",
    "ISO-A.12.4": "Logging and monitoring — event logging, protection, analysis",
    "ISO-A.12.5": "Control of operational software — installation control",
    "ISO-A.12.6": "Technical vulnerability management — scanning, patching",
    "ISO-A.13.1": "Network security management — segmentation, controls",
    "ISO-A.14.2": "Security in development — secure SDLC, testing",
    "ISO-A.16.1": "Incident management — responsibilities, procedures",
    "ISO-A.17.1": "Business continuity — information security continuity",
    "ISO-A.17.2": "Redundancies — availability of information processing facilities",
    "ISO-A.18.1": "Compliance — legal and contractual requirements",
    "ISO-A.18.2": "Information security reviews — independent review",
}

PCIDSS_CONTROLS = {
    "PCI-1": "Install and maintain firewall configuration to protect cardholder data",
    "PCI-2": "Do not use vendor-supplied defaults for system passwords",
    "PCI-3": "Protect stored cardholder data (encryption at rest)",
    "PCI-4": "Encrypt transmission of cardholder data across open networks",
    "PCI-5": "Protect systems against malware; regularly update anti-virus",
    "PCI-6": "Develop and maintain secure systems and applications (patching)",
    "PCI-7": "Restrict access to cardholder data by business need-to-know",
    "PCI-8": "Identify and authenticate access to system components (unique IDs, MFA)",
    "PCI-9": "Restrict physical access to cardholder data",
    "PCI-10": "Track and monitor all access to network resources and cardholder data",
    "PCI-11": "Regularly test security systems and processes (VAPT, ASV scans)",
    "PCI-12": "Maintain a policy that addresses information security",
}


ALL_FRAMEWORKS = {
    "nbe": ("National Bank of Ethiopia Cybersecurity Directives", NBE_CONTROLS,
            "NBE cybersecurity directives for Ethiopian financial institutions"),
    "iso27001": ("ISO 27001:2022", ISO27001_CONTROLS,
                 "International standard for information security management"),
    "pcidss": ("PCI-DSS v4.0", PCIDSS_CONTROLS,
               "Payment Card Industry Data Security Standard"),
}


# Maps user-friendly abbreviations to patterns found in target strings and filenames
TARGET_ALIASES = {
    "cbe": ["cbe", "combanketh"],
    "awash": ["awash"],
    "boa": ["boa", "bankofabyssinia", "abyssinia"],
    "dashen": ["dashen"],
    "etaf": ["etaf"],
    "ethiotelecom": ["ethiotelecom"],
    "telebirr": ["telebirr"],
}


def _target_matches(tgt: str, filename: str, filter_str: str) -> bool:
    """Check if a target/filename matches a user filter (handles abbreviations)."""
    patterns = TARGET_ALIASES.get(filter_str.lower(), [filter_str.lower()])
    tgt_lower = tgt.lower()
    fname_lower = filename.lower()
    for pat in patterns:
        if pat in tgt_lower or pat in fname_lower:
            return True
    return False


def load_findings(input_path: str, target_filter: str = None) -> tuple:
    """Load findings from consolidated JSON. Returns (findings_list, target_name)."""
    findings = []
    target_names = []
    path = Path(input_path)

    if path.is_dir():
        for f in sorted(path.glob("haka_consolidated_*.json")):
            with open(f) as fh:
                data = json.load(fh)
            tgt = data.get("target", "")
            if target_filter and not _target_matches(tgt, f.name, target_filter):
                continue
            target_names.append(tgt)
            findings.extend(data.get("findings", []))
    elif path.is_file():
        with open(path) as fh:
            data = json.load(fh)
        tgt = data.get("target", "")
        if target_filter and not _target_matches(tgt, path.name, target_filter):
            print(f"[!] Target '{target_filter}' doesn't match file target '{tgt}'")
        target_names.append(tgt)
        findings = data.get("findings", [])

    return findings, ", ".join(target_names)


def build_prompt(findings: list, target_label: str, frameworks: dict) -> str:
    """Build the LLM prompt for compliance mapping."""
    finding_list = ""
    for f in findings:
        mitre = f.get("mitre", "N/A")
        finding_list += f"- **{f['id']}** [{f['severity']}]: {f['title']}\n"
        finding_list += f"  Target: {f['target']} | MITRE: {mitre} | Evidence: {f.get('evidence', 'N/A')[:120]}\n"

    framework_sections = ""
    for fw_key, (fw_name, controls, fw_desc) in frameworks.items():
        framework_sections += f"\n### {fw_name}\n{fw_desc}\n\n"
        for ctrl_id, ctrl_info in controls.items():
            if isinstance(ctrl_info, dict):
                framework_sections += (
                    f"- **{ctrl_id}**: {ctrl_info['name']} — {ctrl_info['description']}\n"
                )
            else:
                framework_sections += f"- **{ctrl_id}**: {ctrl_info}\n"

    prompt = f"""You are a regulatory compliance auditor specializing in East African financial services security.

## Assessment Target
{target_label}

## Security Findings ({len(findings)} total)
{finding_list}

## Regulatory Frameworks & Controls
{framework_sections}

## Task
Map each security finding to the specific regulatory controls it violates or impacts. Then:

1. **Compliance Score**: For each framework, determine the percentage of controls that are SATISFIED vs. VIOLATED based on the findings.
   - A control is VIOLATED if any finding directly indicates non-compliance
   - A control is SATISFIED if no finding indicates violation
   - If there's insufficient data to determine, mark as UNKNOWN

2. **Finding-to-Control Mapping**: Create a table mapping each finding ID to the controls it violates, with a brief reason.

3. **Critical Compliance Gaps**: Identify findings that violate 3+ controls (cross-cutting violations).

4. **Regulatory Risk Statement**: A concise executive assessment of the compliance posture and regulatory exposure.

5. **Remediation Priority**: Top-5 findings ranked by regulatory impact.

## Output Format
Use the following Markdown structure exactly:

## Compliance Scores

| Framework | Controls Total | Satisfied | Violated | Unknown | Compliance % |
|-----------|---------------|-----------|----------|---------|-------------|

## Finding → Control Mapping

| Finding ID | Severity | Violated Controls | Impact Summary |
|-----------|----------|------------------|----------------|

(One row per finding that maps to at least one violated control)

## Critical Compliance Gaps
[Findings that violate 3+ controls across frameworks]

## Regulatory Risk Statement
[Concise executive summary of compliance posture]

## Priority Remediation Roadmap
1-5 ranked findings by regulatory impact

Generate the complete analysis now."""

    return prompt


def format_controls(controls_dict: dict) -> str:
    """Format controls for display when LLM doesn't provide mapping."""
    lines = []
    for cid, info in controls_dict.items():
        if isinstance(info, dict):
            lines.append(f"| {cid} | {info['name']} | {info['category']} | UNKNOWN |")
        else:
            lines.append(f"| {cid} | {info} | — | UNKNOWN |")
    return "\n".join(lines)


def generate_compliance_analysis(findings: list, target: str, frameworks: dict,
                                 model: str, output: str = None) -> str:
    """Generate compliance analysis using HakaLLM."""
    llm = HakaLLM()
    prompt = build_prompt(findings, target, frameworks)

    fw_names = ", ".join(name for name, _, _ in frameworks.values())
    print(f"[*] Generating compliance analysis for {target}...")
    print(f"[*] Frameworks: {fw_names}")
    print(f"[*] Model: {model}")
    print(f"[*] Findings loaded: {len(findings)}")

    system_prompt = (
        "You are a senior regulatory compliance auditor specializing in African financial services. "
        "You map security assessment findings to regulatory frameworks with precision. "
        "You understand NBE directives, ISO 27001, and PCI-DSS deeply. "
        "Always provide specific control IDs and reasoned mappings. "
        "Respond in clean Markdown tables and structured sections."
    )

    response = llm.generate(
        prompt=prompt,
        model=model,
        system=system_prompt,
        max_tokens=8192,
        temperature=0.3,
    )

    header = f"""# HAKA Compliance Gap Analysis — {target}

**Generated:** {__import__('datetime').datetime.now().isoformat(timespec='minutes')}
**Tool:** haka_compliance.py
**Model:** {model}
**Frameworks Analyzed:** {fw_names}
**Findings Analyzed:** {len(findings)}

---

"""
    full_output = header + response

    if output:
        with open(output, "w") as f:
            f.write(full_output)
        print(f"[✓] Compliance analysis written to: {output}")
    else:
        print(full_output)

    return full_output


def main():
    parser = argparse.ArgumentParser(
        description="HAKA Regulatory Compliance Mapper — Maps findings to NBE, ISO 27001, and PCI-DSS controls.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                          # All targets, all frameworks
  %(prog)s --target cbe --framework nbe             # CBE vs. NBE directives only
  %(prog)s --target awash --framework all           # Awash vs. all frameworks
  %(prog)s --framework iso27001 --output iso.md     # ISO 27001 only, save to file
        """,
    )
    parser.add_argument(
        "--input", default="reports/",
        help="Consolidated JSON file or directory (default: reports/)",
    )
    parser.add_argument(
        "--target",
        help="Filter to specific target (cbe, awash, boa, dashen, etaf, ethiotelecom, telebirr)",
    )
    parser.add_argument(
        "--framework", default="all",
        choices=["nbe", "iso27001", "pcidss", "all"],
        help="Framework to map against (default: all)",
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: print to stdout)",
    )
    parser.add_argument(
        "--model", default="deepseek",
        help="LLM model to use (default: deepseek)",
    )
    args = parser.parse_args()

    # Resolve default input directory
    if args.input == "reports/":
        script_dir = os.path.dirname(os.path.abspath(__file__))
        args.input = os.path.join(script_dir, "reports")

    # Select frameworks
    if args.framework == "all":
        frameworks = ALL_FRAMEWORKS
    else:
        frameworks = {args.framework: ALL_FRAMEWORKS[args.framework]}

    # Load findings
    findings, target_label = load_findings(args.input, args.target)

    if not findings:
        print("[!] No findings loaded. Check --input and --target.")
        sys.exit(1)

    if args.target:
        target_display = args.target.upper()
    else:
        target_display = target_label or "All HAKA Targets"

    generate_compliance_analysis(
        findings=findings,
        target=target_display,
        frameworks=frameworks,
        model=args.model,
        output=args.output,
    )


if __name__ == "__main__":
    main()
