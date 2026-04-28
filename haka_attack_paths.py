#!/usr/bin/env python3
"""
HAKA Attack Path Constructor — Phase 3
Constructs realistic multi-step attack scenarios showing how vulnerabilities chain together.
Uses MITRE ATT&CK kill chain stages and the HakaLLM provider.

Usage:
  python3 haka_attack_paths.py
  python3 haka_attack_paths.py --target cbe
  python3 haka_attack_paths.py --target awash --count 5 --output attack_paths_awash.md
  python3 haka_attack_paths.py --input reports/ --model r1 --count 2
"""

import argparse
import json
import os
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from haka_providers import HakaLLM


# ── MITRE ATT&CK Kill Chain ─────────────────────────────────────────────────

KILL_CHAIN_STAGES = [
    ("Reconnaissance", "TA0043", "Gathering information to plan future operations"),
    ("Resource Development", "TA0042", "Establishing resources to support operations"),
    ("Initial Access", "TA0001", "Gaining an initial foothold"),
    ("Execution", "TA0002", "Running malicious code"),
    ("Persistence", "TA0003", "Maintaining access across restarts"),
    ("Privilege Escalation", "TA0004", "Gaining higher-level permissions"),
    ("Defense Evasion", "TA0005", "Avoiding detection"),
    ("Credential Access", "TA0006", "Stealing account credentials"),
    ("Discovery", "TA0007", "Learning about the environment"),
    ("Lateral Movement", "TA0008", "Moving through the environment"),
    ("Collection", "TA0009", "Gathering data of interest"),
    ("Exfiltration", "TA0010", "Stealing data"),
    ("Impact", "TA0040", "Manipulating, interrupting, or destroying systems"),
]

ADVERSARY_PROFILES = [
    "Script Kiddie — Low sophistication, opportunistic, uses known exploits",
    "Cybercriminal Group (FIN7/Carbanak-style) — Medium-high sophistication, financially motivated, targets banks",
    "Nation-State APT (APT38/Lazarus-style) — High sophistication, state-sponsored, targets SWIFT/banking infrastructure",
    "Insider Threat — Internal access, knows the environment, motivated by financial gain or grievance",
    "Hacktivist Group — Medium sophistication, politically/ideologically motivated, targets visible infrastructure",
]


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


def load_findings(input_path: str, target_filter: str = None) -> list:
    """Load findings from a consolidated JSON file or a directory of them."""
    findings = []
    path = Path(input_path)

    if path.is_dir():
        for f in sorted(path.glob("haka_consolidated_*.json")):
            with open(f) as fh:
                data = json.load(fh)
            tgt = data.get("target", "")
            if target_filter and not _target_matches(tgt, f.name, target_filter):
                continue
            findings.extend(data.get("findings", []))
    elif path.is_file():
        with open(path) as fh:
            data = json.load(fh)
        tgt = data.get("target", "")
        if target_filter and not _target_matches(tgt, path.name, target_filter):
            print(f"[!] Target '{target_filter}' doesn't match file target '{tgt}'")
        findings = data.get("findings", [])
    else:
        print(f"[!] Input path not found: {input_path}")
        sys.exit(1)

    return findings


def build_prompt(findings: list, target_label: str, count: int) -> str:
    """Build the LLM prompt for constructing attack paths."""
    # Group findings by severity and build a compact listing
    by_severity = defaultdict(list)
    for f in findings:
        by_severity[f["severity"]].append(f)

    finding_list = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = by_severity.get(sev, [])
        if not items:
            continue
        finding_list += f"\n### {sev} Findings ({len(items)})\n\n"
        for f in items:
            mitre = f.get("mitre", "N/A")
            finding_list += f"- **{f['id']}**: {f['title']} (MITRE: {mitre})\n"
            finding_list += f"  Target: {f['target']}\n"
            if f.get("evidence"):
                evidence = f["evidence"][:150]
                finding_list += f"  Evidence: {evidence}\n"

    prompt = f"""You are a senior penetration tester and red team operator analyzing a security assessment of {target_label}.

## MITRE ATT&CK Kill Chain
The adversary lifecycle moves through these stages:
1. Reconnaissance (TA0043) — Target identification, OSINT gathering
2. Resource Development (TA0042) — Infrastructure, tools, capabilities
3. Initial Access (TA0001) — First entry point
4. Execution (TA0002) — Running malicious code
5. Persistence (TA0003) — Maintaining access
6. Privilege Escalation (TA0004) — Higher privileges
7. Defense Evasion (TA0005) — Avoiding detection
8. Credential Access (TA0006) — Stealing credentials
9. Discovery (TA0007) — Mapping the environment
10. Lateral Movement (TA0008) — Moving between systems
11. Collection (TA0009) — Gathering target data
12. Exfiltration (TA0010) — Removing data
13. Impact (TA0040) — Disruption or destruction

## Discovered Vulnerabilities
{finding_list}

## Task
Construct EXACTLY {count} realistic attack paths showing how an adversary would chain these findings together. 
Follow these rules:
- Each attack path must be a realistic multi-step scenario
- Each step must reference specific finding IDs from the data above
- Use the MITRE ATT&CK kill chain stages — show which stage each step maps to
- Include an adversary profile explaining WHO would execute this attack
- Give each path a descriptive name and a risk level (Critical, High, Medium)
- Each path should use at least 3 different findings chained together
- Be specific about the technology, protocols, and techniques used
- Show the narrative: what the attacker does, how they chain steps, what they achieve

## Output Format
Use the following Markdown format for each attack path:

## Attack Path N: [Descriptive Name]
**Risk:** [Level] | **Stages:** X/13 | **Actor:** [Adversary Profile]

### Step 1 — [Kill Chain Stage Name] (MITRE TXXXX)
[Narrative explaining what the attacker does, linking to finding IDs in brackets like [CRIT-TGT-XX]. Be specific about techniques.]

### Step 2 — [Next Stage] (MITRE TXXXX)
[Continue the chain...]

[Include all steps in the chain. Each step should flow logically from the previous one.]

### Adversary Profile
[Detailed profile of likely attacker: sophistication, motivation, capabilities, TTPs, real-world references]

### Impact Assessment
[What the attacker achieves in this scenario: financial theft, data exfiltration, service disruption, etc.]

Generate each attack path now. Be thorough, specific, and realistic."""

    return prompt


def generate_attack_paths(findings: list, target: str, count: int, model: str,
                          output: str = None) -> str:
    """Generate attack paths using HakaLLM."""
    llm = HakaLLM()
    prompt = build_prompt(findings, target.upper(), count)

    print(f"[*] Generating {count} attack paths for {target}...")
    print(f"[*] Using model: {model}")
    print(f"[*] Findings loaded: {len(findings)}")

    system_prompt = (
        "You are a senior penetration tester and red team expert specializing in financial sector security. "
        "You produce realistic, technically detailed attack path analyses. "
        "Always reference specific finding IDs from the provided vulnerability data. "
        "Respond in clean Markdown format. Be precise about techniques, protocols, and MITRE mappings."
    )

    response = llm.generate(
        prompt=prompt,
        model=model,
        system=system_prompt,
        max_tokens=8192,
        temperature=0.4,
    )

    # Build full document
    header = f"""# HAKA Attack Path Analysis — {target}

**Generated:** {__import__('datetime').datetime.now().isoformat(timespec='minutes')}
**Tool:** haka_attack_paths.py
**Model:** {model}
**Findings Analyzed:** {len(findings)}
**Attack Paths Requested:** {count}

---

"""
    full_output = header + response

    if output:
        with open(output, "w") as f:
            f.write(full_output)
        print(f"[✓] Attack paths written to: {output}")
    else:
        print(full_output)

    return full_output


def main():
    parser = argparse.ArgumentParser(
        description="HAKA Attack Path Constructor — Chains vulnerabilities into realistic multi-step attack scenarios.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                          # All targets, default settings
  %(prog)s --target cbe                             # CBE Commercial Bank only
  %(prog)s --target awash --count 5                 # Awash Bank, 5 paths
  %(prog)s --target cbe --output attack_paths.md    # Save to file
  %(prog)s --model r1 --count 2                     # Use local DeepSeek-R1
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
        "--output",
        help="Output file path (default: print to stdout)",
    )
    parser.add_argument(
        "--model", default="deepseek",
        help="LLM model to use (default: deepseek)",
    )
    parser.add_argument(
        "--count", type=int, default=3,
        help="Number of attack paths to generate (default: 3)",
    )
    args = parser.parse_args()

    # Resolve default input directory relative to script location
    if args.input == "reports/":
        script_dir = os.path.dirname(os.path.abspath(__file__))
        args.input = os.path.join(script_dir, "reports")

    # Load findings
    findings = load_findings(args.input, args.target)

    if not findings:
        print("[!] No findings loaded. Check --input and --target.")
        sys.exit(1)

    # Determine target label
    if args.target:
        target_label = args.target.upper()
    else:
        target_label = "All HAKA Targets"

    generate_attack_paths(
        findings=findings,
        target=target_label,
        count=args.count,
        model=args.model,
        output=args.output,
    )


if __name__ == "__main__":
    main()
