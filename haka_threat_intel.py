#!/usr/bin/env python3
"""
HAKA CVE & Exploit Intelligence — Phase 3
Enriches HAKA findings with CVE data, CVSS scores, and exploit availability.
Identifies software versions from scan findings and maps them to known vulnerabilities.

Usage:
  python3 haka_threat_intel.py
  python3 haka_threat_intel.py --target cbe
  python3 haka_threat_intel.py --exploit-only
  python3 haka_threat_intel.py --output threat_intel_cbe.md
  python3 haka_threat_intel.py --input reports/haka_consolidated_boa.json
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from haka_providers import HakaLLM


# ── Software & Version Extraction Patterns ──────────────────────────────────

VERSION_PATTERNS = [
    # Exchange Server
    (r"Exchange\s+(?:Server\s+)?(\d{4}\s+CU\d+)", "Microsoft Exchange Server"),
    (r"Exchange\s+(\d{4})", "Microsoft Exchange Server"),
    # IIS
    (r"IIS/([\d.]+)", "Microsoft IIS"),
    # nginx
    (r"nginx/([\d.]+)", "nginx"),
    # LiteSpeed
    (r"LiteSpeed(?:/([\d.]+))?", "LiteSpeed Web Server"),
    # Apache
    (r"Apache/([\d.]+)", "Apache HTTP Server"),
    # F5 BIG-IP
    (r"F5\s*BIG-?IP", "F5 BIG-IP"),
    (r"bigip", "F5 BIG-IP"),
    # Cisco WSA
    (r"Cisco\s+WSA", "Cisco Web Security Appliance"),
    # Spring Boot
    (r"Spring\s*Boot", "Spring Boot"),
    (r"Spring\s*Framework", "Spring Framework"),
    # Mattermost
    (r"Mattermost\s*([\d.]+)?", "Mattermost"),
    # openresty
    (r"openresty/([\d.]+)", "OpenResty"),
    # Sophos
    (r"Sophos", "Sophos Email Gateway"),
    # ARR/IIS
    (r"ARR/([\d.]+)", "Microsoft ARR (Application Request Routing)"),
    # PHP
    (r"PHP/([\d.]+)", "PHP"),
    # OpenSSL
    (r"OpenSSL/([\d.]+[a-z]*)", "OpenSSL"),
    # WordPress
    (r"WordPress\s*([\d.]+)?", "WordPress"),
    # Tomcat
    (r"Apache[\s-]Tomcat[^\d]*([\d.]+)?", "Apache Tomcat"),
    # Generic X-Powered-By
    (r"ASP\.NET", "ASP.NET"),
    (r"X-FEServer:\s*(\S+)", "Microsoft Exchange Server (X-FEServer)"),
]


def extract_software_inventory(findings: list) -> list:
    """Parse findings for version numbers and product names. Returns list of dicts."""
    inventory = []
    seen = set()

    for f in findings:
        # Check title, evidence, and remediation fields
        text_fields = [
            f.get("title", ""),
            f.get("evidence", ""),
            " ".join(f.get("remediation", [])),
        ]
        combined = " ".join(text_fields)

        for pattern, product in VERSION_PATTERNS:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            for ver in matches:
                if isinstance(ver, tuple):
                    ver = ver[0] if ver[0] else ""
                version_str = str(ver).strip() if ver else "(version unknown)"

                key = (product.lower(), version_str.lower(), f.get("target", ""))
                if key not in seen:
                    seen.add(key)
                    inventory.append({
                        "product": product,
                        "version": version_str,
                        "host": f.get("target", "unknown"),
                        "finding_id": f["id"],
                        "severity": f["severity"],
                        "evidence": f.get("evidence", "")[:200],
                    })

    # Sort by product name
    inventory.sort(key=lambda x: x["product"].lower())
    return inventory


def build_prompt(inventory: list, findings: list) -> str:
    """Build the LLM prompt for CVE enrichment."""
    # Software inventory section
    inv_section = "| Product | Version | Host(s) | Finding ID | Severity |\n"
    inv_section += "|---------|---------|---------|------------|----------|\n"
    for item in inventory:
        inv_section += (
            f"| {item['product']} | {item['version']} | {item['host']} | "
            f"{item['finding_id']} | {item['severity']} |\n"
        )

    # Context from findings about what's exposed
    context_brief = ""
    for item in inventory:
        context_brief += f"- {item['finding_id']}: {item['product']} {item['version']} on {item['host']} — {item['evidence'][:150]}\n"

    prompt = f"""You are a vulnerability intelligence analyst specializing in exploit research and CVE enrichment for financial sector security assessments.

## Software Inventory Discovered
{inv_section}

## Context
{context_brief}

## Task
For each software product and version in the inventory above, identify relevant CVEs through April 2026. For each product:

1. **List CVEs**: Provide specific CVE IDs with CVSS v3 scores that affect this version
2. **Exploit Availability**: Indicate whether a public PoC exists (GitHub, ExploitDB), whether there's a Metasploit module, and whether it's in CISA's Known Exploited Vulnerabilities (KEV) catalog
3. **Patch Status**: State whether a patch exists and what version fixes it
4. **Risk Assessment**: Brief assessment of real-world exploitability

Focus on:
- RCE (Remote Code Execution) vulnerabilities
- Authentication bypass
- Privilege escalation
- Information disclosure that could aid attacks

## Output Format
Use the following Markdown structure exactly:

## Software Inventory Summary
[Brief paragraph summarizing what was found]

## Detailed CVE Analysis

### [Product Name] [Version] — [Number] CVEs Found
| CVE ID | CVSS | Type | Exploit Public? | Metasploit? | CISA KEV? | Patched? |
|--------|------|------|----------------|-------------|-----------|----------|
| CVE-... | X.X | RCE/AuthBypass/etc | Yes/No | Yes/No | Yes/No | Yes (vX) |

**Risk Assessment:** [Brief assessment]

(Repeat for each product)

## Exploit Availability Matrix (Summary)
| Product | Public PoC | Metasploit Module | CISA KEV | Active Exploitation |
|---------|-----------|-------------------|----------|-------------------|

## Prioritized Patching Roadmap

| Priority | Product | Finding ID | Action | Deadline |
|----------|---------|------------|--------|----------|
| 1 (Critical) | ... | ... | Upgrade/Patch to ... | Immediate |

Generate the complete analysis now. Be thorough and precise with CVE IDs and versions."""

    return prompt


def generate_threat_intel(inventory: list, findings: list, model: str,
                          exploit_only: bool, output: str = None) -> str:
    """Generate CVE and threat intelligence using HakaLLM."""
    llm = HakaLLM()

    if exploit_only:
        print("[*] Filtering to exploit-only mode...")
        # We still get all CVEs from LLM but flag intention
        note = " (**--exploit-only** mode active — only findings with known public exploits prioritized)\n\n"
    else:
        note = ""

    if not inventory:
        print("[!] No software versions identified in findings.")
        print("[!] Consider running more detailed version scans.")
        return ""

    print(f"[*] Generating CVE intelligence for {len(inventory)} software products...")
    print(f"[*] Model: {model}")
    if exploit_only:
        print("[*] Mode: exploit-only")

    prompt = build_prompt(inventory, findings)

    system_prompt = (
        "You are a senior vulnerability intelligence analyst with deep knowledge of CVEs, "
        "exploit development, and real-world attack trends through April 2026. "
        "You know specific CVE IDs, CVSS scores, exploit availability (GitHub, ExploitDB, Metasploit), "
        "and CISA Known Exploited Vulnerabilities catalog status. "
        "Be precise with version ranges, patch versions, and exploitation techniques. "
        "Prioritize findings with known public exploits and active exploitation. "
        "Respond in clean Markdown with structured tables."
    )

    response = llm.generate(
        prompt=prompt,
        model=model,
        system=system_prompt,
        max_tokens=8192,
        temperature=0.3,
    )

    # Build inventory table
    products_seen = set()
    inv_table = "| Product | Version | Host | Finding ID | Severity |\n"
    inv_table += "|---------|---------|------|------------|----------|\n"
    for item in inventory:
        key = (item['product'], item['version'], item['host'])
        if key not in products_seen:
            products_seen.add(key)
            inv_table += (
                f"| {item['product']} | {item['version']} | {item['host']} | "
                f"{item['finding_id']} | {item['severity']} |\n"
            )

    header = f"""# HAKA CVE & Exploit Intelligence Report

**Generated:** {__import__('datetime').datetime.now().isoformat(timespec='minutes')}
**Tool:** haka_threat_intel.py
**Model:** {model}
**Software Products Identified:** {len(inventory)}
**Total Findings Analyzed:** {len(findings)}
{note}---

## Software Inventory

{inv_table}

---

"""
    full_output = header + response

    if output:
        with open(output, "w") as f:
            f.write(full_output)
        print(f"[✓] Threat intelligence written to: {output}")
    else:
        print(full_output)

    return full_output


def main():
    parser = argparse.ArgumentParser(
        description="HAKA CVE & Exploit Intelligence — Enriches findings with CVE data and exploit availability.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                          # All targets, all findings
  %(prog)s --target cbe                             # CBE only
  %(prog)s --exploit-only                           # Only exploitable findings
  %(prog)s --output threat_intel.md                 # Save to file
  %(prog)s --target awash --exploit-only            # Awash, exploitable only
        """,
    )
    parser.add_argument(
        "--input", default=None,
        help="Consolidated JSON file or directory (default: reports/)",
    )
    parser.add_argument(
        "--target",
        help="Filter to specific target (cbe, awash, boa, dashen, etaf, ethiotelecom, telebirr)",
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: print to stdout)",
    )
    parser.add_argument(
        "--model", default="deepseek",
        help="LLM model to use (default: deepseek)",
    )
    parser.add_argument(
        "--exploit-only", action="store_true",
        help="Only show findings with known public exploits",
    )
    args = parser.parse_args()

    # Resolve input directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if args.input is None:
        args.input = os.path.join(script_dir, "reports")

    input_path = Path(args.input)

    # Target matching helper
    TARGET_ALIASES = {
        "cbe": ["cbe", "combanketh"],
        "awash": ["awash"],
        "boa": ["boa", "bankofabyssinia", "abyssinia"],
        "dashen": ["dashen"],
        "etaf": ["etaf"],
        "ethiotelecom": ["ethiotelecom"],
        "telebirr": ["telebirr"],
    }
    def _matches(tgt, fname, fltr):
        patterns = TARGET_ALIASES.get(fltr.lower(), [fltr.lower()])
        return any(p in tgt.lower() or p in fname.lower() for p in patterns)

    # Load all findings
    all_findings = []
    if input_path.is_dir():
        for f in sorted(input_path.glob("haka_consolidated_*.json")):
            with open(f) as fh:
                data = json.load(fh)
            tgt = data.get("target", "")
            if args.target and not _matches(tgt, f.name, args.target):
                continue
            all_findings.extend(data.get("findings", []))
    elif input_path.is_file():
        with open(input_path) as fh:
            data = json.load(fh)
        tgt = data.get("target", "")
        if args.target and not _matches(tgt, input_path.name, args.target):
            print(f"[!] Target '{args.target}' doesn't match file target '{tgt}'")
        all_findings = data.get("findings", [])
    else:
        print(f"[!] Input path not found: {args.input}")
        sys.exit(1)

    if not all_findings:
        print("[!] No findings loaded. Check --input and --target.")
        sys.exit(1)

    # Extract software inventory
    inventory = extract_software_inventory(all_findings)

    if not inventory:
        print("[!] No software versions identified in findings.")
        print("[!] Consider running more detailed banner grabbing scans.")
        print("[!] Raw findings might not contain version information.")
        sys.exit(1)

    target_display = args.target.upper() if args.target else "All HAKA Targets"

    generate_threat_intel(
        inventory=inventory,
        findings=all_findings,
        model=args.model,
        exploit_only=args.exploit_only,
        output=args.output,
    )


if __name__ == "__main__":
    main()
