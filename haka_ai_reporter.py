#!/usr/bin/env python3
"""
HAKA AI Reporter — AI-powered security report generator.
Takes HAKA scan results and uses local LLM (ollama) to produce
professional, client-ready security assessment reports.

Usage:
  haka_ai_reporter.py --input consolidated.json
  haka_ai_reporter.py --input /path/to/jsons/ --mode executive
  haka_ai_reporter.py --input consolidated.json --dry-run
  haka_ai_reporter.py --input consolidated.json --interactive
"""

import argparse
import json
import os
import subprocess
import sys
import textwrap
from datetime import datetime
from pathlib import Path

# HAKA provider module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from haka_providers import HakaLLM, MODEL_SHORTCUTS

# ── Constants ────────────────────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
DEFAULT_MODEL = "qwen"  # Uses ollama:qwen3:32b locally

# Model help text
MODEL_HELP = (
    "Model to use. Shortcuts: qwen (local), deepseek (cloud), claude (cloud), "
    "gemma (local), r1 (local). Or full path: anthropic:claude-sonnet-4-20250514"
)
FAST_MODEL = "deepseek-r1:7b"
CHUNK_THRESHOLD = 30  # Findings threshold before chunking

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

TARGET_NAME_MAP = {
    "combanketh.et": "Commercial Bank of Ethiopia (CBE)",
    "awashbank.com": "Awash Bank",
    "bankofabyssinia.com": "Bank of Abyssinia (BOA)",
    "dashenbanksc.com": "Dashen Bank",
    "etaf.mil.et": "Ethiopian Air Force (ETAF)",
    "ethiotelecom.et": "Ethio Telecom",
    "telebirr.ethiotelecom.et": "Telebirr",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def format_finding(f, idx=None):
    """Format a single finding for the LLM prompt."""
    lines = []
    label = f"Finding {idx}" if idx else f"Finding {f.get('id', 'N/A')}"
    lines.append(f"### {label}")
    lines.append(f"- **ID:** {f.get('id', 'N/A')}")
    lines.append(f"- **Severity:** {f.get('severity', 'N/A')}")
    lines.append(f"- **Title:** {f.get('title', 'N/A')}")
    lines.append(f"- **Target:** {f.get('target', 'N/A')}")
    evidence = f.get('evidence', 'N/A')
    if len(evidence) > 500:
        evidence = evidence[:500] + "..."
    lines.append(f"- **Evidence:** {evidence}")
    lines.append(f"- **MITRE ATT&CK:** {f.get('mitre', 'N/A')}")
    rem = f.get('remediation', [])
    if isinstance(rem, list):
        rem = "; ".join(rem)
    lines.append(f"- **Remediation:** {rem}")
    return "\n".join(lines)


def format_findings_summary(findings, max_per_severity=None):
    """Create a compact summary of findings for chunked reports."""
    grouped = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        grouped.setdefault(sev, []).append(f)

    lines = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        items = grouped.get(sev, [])
        if not items:
            continue
        lines.append(f"\n## {sev} ({len(items)} findings)")
        limit = max_per_severity or len(items)
        for i, f in enumerate(items[:limit]):
            lines.append(f"- **{f.get('id')}**: {f.get('title')} — {f.get('target')}")
            lines.append(f"  Evidence: {f.get('evidence', 'N/A')[:200]}")
            lines.append(f"  MITRE: {f.get('mitre', 'N/A')}")
            rem = f.get("remediation", [])
            if isinstance(rem, list):
                rem = "; ".join(rem)
            lines.append(f"  Remediation: {rem}")
    return "\n".join(lines)


def load_findings(input_path):
    """Load findings from a consolidated JSON file or a directory of JSONs."""
    findings = []
    meta = {}

    path = Path(input_path)
    if path.is_file():
        with open(path) as fh:
            data = json.load(fh)
        findings, meta = _extract_from_json(data, path.name)
    elif path.is_dir():
        json_files = sorted(path.glob("*.json"))
        if not json_files:
            print(f"ERROR: No JSON files found in {input_path}", file=sys.stderr)
            sys.exit(1)
        all_findings = []
        all_meta = {}
        for jf in json_files:
            with open(jf) as fh:
                data = json.load(fh)
            f, m = _extract_from_json(data, jf.name)
            all_findings.extend(f)
            if not all_meta:
                all_meta = m
            elif m.get("target") and m["target"] != all_meta.get("target"):
                all_meta["target"] = f"{all_meta.get('target', '')} + {m['target']}"
        # Deduplicate by ID
        seen = set()
        for f in all_findings:
            fid = f.get("id", "")
            if fid not in seen:
                seen.add(fid)
                findings.append(f)
            else:
                # Merge evidence
                for existing in findings:
                    if existing.get("id") == fid and f.get("evidence") not in existing.get("evidence", ""):
                        existing["evidence"] += " | " + f.get("evidence", "")
        meta = all_meta
    else:
        print(f"ERROR: {input_path} is not a file or directory", file=sys.stderr)
        sys.exit(1)

    if not findings:
        print("ERROR: No findings found in input", file=sys.stderr)
        sys.exit(1)

    return findings, meta


def _extract_from_json(data, filename):
    """Extract findings and metadata from a JSON blob."""
    findings = []
    meta = {}

    # Consolidated format
    if "findings" in data and isinstance(data["findings"], list):
        findings = data["findings"]
        meta = {
            "target": data.get("target", "unknown"),
            "risk_score": data.get("risk_score", 0),
            "severity_counts": data.get("severity_counts", {}),
            "scan_time": data.get("scan_time", ""),
        }
    # Exchange scanner format
    elif "risk_findings" in data:
        findings = data.get("risk_findings", [])
        meta = {
            "target": data.get("scan_metadata", {}).get("target", "unknown"),
            "risk_score": data.get("risk_score", 0),
            "severity_counts": data.get("severity_counts", {}),
            "scan_time": data.get("scan_metadata", {}).get("scan_start", ""),
        }
    # DNS recon scanner format
    elif "risk_assessment" in data and "findings" in data.get("risk_assessment", {}):
        findings = data["risk_assessment"]["findings"]
        meta = {
            "target": data.get("scan_metadata", {}).get("target_domain", "unknown"),
            "risk_score": data.get("risk_assessment", {}).get("score", 0),
            "severity_counts": data.get("severity_counts", {}),
            "scan_time": data.get("scan_metadata", {}).get("scan_start", ""),
        }
    # TLS scanner format
    elif "all_findings" in data:
        findings = data["all_findings"]
        meta = {
            "target": data.get("target", "unknown"),
            "risk_score": data.get("risk_score", 0),
            "severity_counts": data.get("finding_counts", {}),
            "scan_time": data.get("scan_time", ""),
        }
    # Generic scanner — try to extract from results
    elif "results" in data:
        raw_findings = []
        for r in data.get("results", []):
            if isinstance(r, dict):
                # Check for nested findings
                if "findings" in r:
                    raw_findings.extend([_normalize_finding(f) for f in r["findings"]])
                elif "checks" in r:
                    raw_findings.extend(_flatten_checks(r))
        findings = raw_findings
        meta = {
            "target": data.get("target", data.get("scan_metadata", {}).get("target", "unknown")),
            "risk_score": 0,
            "severity_counts": {},
            "scan_time": data.get("scan_time", data.get("generated_at", "")),
        }
    else:
        # Unknown format — try to find anything useful
        print(f"WARNING: Unknown JSON format in {filename}", file=sys.stderr)
        meta = {"target": "unknown", "risk_score": 0, "severity_counts": {}}

    # Normalize findings that might be missing standard fields
    normalized = [_normalize_finding(f) for f in findings]
    return normalized, meta


def _normalize_finding(f):
    """Ensure finding has standard keys."""
    if not isinstance(f, dict):
        return {"id": "UNKNOWN", "severity": "INFO", "title": str(f),
                "target": "", "evidence": str(f), "mitre": "", "remediation": []}
    return {
        "id": f.get("id", f.get("finding_id", "UNKNOWN")),
        "severity": f.get("severity", "UNKNOWN").upper(),
        "title": f.get("title", f.get("name", f.get("description", "Untitled"))),
        "target": f.get("target", f.get("domain", f.get("host", ""))),
        "evidence": f.get("evidence", f.get("detail", f.get("description", ""))),
        "mitre": f.get("mitre", f.get("mitre_technique", "")),
        "remediation": f.get("remediation", f.get("recommendation", f.get("fix", []))),
    }


def _flatten_checks(result):
    """Flatten email/DNS scanner checks into findings."""
    findings = []
    domain = result.get("domain", result.get("target", "unknown"))
    checks = result.get("checks", {})

    severity_map = {
        "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
        "low": "LOW", "secure": "INFO",
    }

    for check_name, check_data in checks.items():
        if not isinstance(check_data, dict):
            continue
        # Determine severity from check result
        exists = check_data.get("exists", check_data.get("configured", None))
        status = check_data.get("status", "")
        severity = "INFO"

        if isinstance(exists, bool) and not exists:
            severity = "CRITICAL" if check_name in ("spf", "dmarc") else "HIGH"
        elif status == "vulnerable":
            severity = "HIGH"
        elif status == "missing":
            severity = "CRITICAL" if check_name in ("dmarc", "dkim") else "HIGH"

        findings.append({
            "id": f"SCAN-{check_name.upper()}",
            "severity": severity,
            "title": f"{check_name.upper()} check for {domain}",
            "target": domain,
            "evidence": json.dumps(check_data)[:500],
            "mitre": result.get("mitre", result.get("mitre_technique", "")),
            "remediation": [f"Configure {check_name.upper()} properly for {domain}"],
        })

    return findings


def count_severities(findings):
    """Count findings by severity."""
    counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ── LLM interface (multi-provider) ──────────────────────────────────────────

_llm_instance = None

def get_llm():
    """Get or create the HakaLLM instance."""
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = HakaLLM()
    return _llm_instance


# ── Prompt builders ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are a senior cybersecurity consultant writing professional assessment "
    "reports for bank executives and regulators. Be precise, factual, and direct. "
    "Use business-impact language, not technical jargon. Never sensationalize. "
    "Never fabricate findings."
)


def build_executive_prompt(target_name, risk_score, severity_counts, findings_text):
    """Build prompt for executive summary report."""
    return f"""Write a cybersecurity assessment EXECUTIVE SUMMARY for {target_name}.

CONTEXT:
- Overall Risk Score: {risk_score}/100
- Finding Counts: {json.dumps(severity_counts)}

FINDINGS:
{findings_text}

STRUCTURE — Write these sections with markdown headings (##):

### Executive Summary
A 2-3 paragraph business-language overview. Explain what was tested, the overall security posture, 
and the top business risks. No technical details. Use terms like "business disruption risk", 
"regulatory exposure", "customer trust impact", "financial fraud risk".

### Key Risk Areas (Top 5)
A bullet list of the 5 most impactful risk themes. Each bullet: the business consequence, 
not the technical finding. Example: "Customer account takeover risk due to email spoofing vulnerability" 
not "No DMARC record."

### Risk Score Interpretation
Explain what the {risk_score}/100 risk score means in business terms. 
What level of urgency does this warrant? What would regulators expect?

### Immediate Priorities
3-5 concrete next steps for executives. Business-focused, not technical. 
Example: "Engage email security vendor within 2 weeks" not "Implement DMARC."

WRITE THE REPORT NOW. Use markdown. Do not include a preamble or postamble."""


def build_technical_prompt(target_name, risk_score, severity_counts, findings_text):
    """Build prompt for full technical report."""
    return f"""Write a COMPREHENSIVE TECHNICAL SECURITY ASSESSMENT REPORT for {target_name}.

CONTEXT:
- Overall Risk Score: {risk_score}/100
- Severity Distribution: {json.dumps(severity_counts)}

FINDINGS:
{findings_text}

STRUCTURE — Write these sections with markdown headings (##):

### Executive Summary
Brief technical overview (1 paragraph).

### Methodology
Explain the assessment approach: external reconnaissance, DNS analysis, email security testing, 
web application scanning, Exchange server assessment, TLS/certificate analysis, cloud storage scanning. 
List tools used from HAKA platform.

### Risk Score Calculation
Explain the {risk_score}/100 score methodology. Factor in severity distribution, exploitability, 
and business impact.

### Detailed Findings
For EACH finding provided above, write a detailed analysis section:
- **Finding ID & Title**
- **Technical Description** — explain the vulnerability in technical terms
- **Evidence** — quote the provided evidence
- **MITRE ATT&CK Mapping** — explain the MITRE technique and how it applies
- **Impact Assessment** — what an attacker could achieve
- **Remediation** — specific technical steps to fix

Organize findings by severity (CRITICAL first, then HIGH, then MEDIUM, etc.).

### MITRE ATT&CK Coverage
Summarize the MITRE techniques observed across all findings. Group by tactic.

### Remediation Roadmap
Prioritized remediation phases:
- **Phase 1 (Immediate — 0-30 days):** Critical fixes
- **Phase 2 (Short-term — 30-90 days):** High-severity items
- **Phase 3 (Medium-term — 90-180 days):** Remaining items

### Appendix: Finding Index
A table with columns: ID | Severity | Title | MITRE Technique

WRITE THE REPORT NOW. Use markdown. Do not include a preamble or postamble outside the report."""


def build_onepager_prompt(target_name, risk_score, severity_counts, findings_text):
    """Build prompt for one-page leave-behind."""
    return f"""Write a ONE-PAGE SECURITY ASSESSMENT BRIEF for {target_name}.

CONTEXT:
- Overall Risk Score: {risk_score}/100
- Finding Counts: {json.dumps(severity_counts)}

FINDINGS:
{findings_text}

RULES:
- Must fit on ONE printed page. Be extremely concise.
- Focus on the TOP 3 MOST CRITICAL findings only.
- Every word must earn its place.

STRUCTURE:

### {target_name} — Security Quick-Check
**Risk Score: {risk_score}/100** | **Date: [today]** | **Classification: CONFIDENTIAL**

**Top 3 Critical Issues:**
(For each: 1 line title, 1 line impact, 1 line fix — 3 lines total per issue)

**Risk Heatmap:**
(Create a simple text summary of the severity distribution)

**Bottom Line:**
(1-2 sentence assessment — is this bank secure? what's the biggest concern?)

WRITE THE BRIEF NOW. Use markdown. Be ruthlessly concise. No preamble."""


def build_remediation_prompt(target_name, risk_score, severity_counts, findings_text):
    """Build prompt for remediation-only report."""
    return f"""Write a REMEDIATION ROADMAP for {target_name}.

CONTEXT:
- Overall Risk Score: {risk_score}/100
- Finding Counts: {json.dumps(severity_counts)}

FINDINGS:
{findings_text}

STRUCTURE:

### Remediation Roadmap for {target_name}

**Overall Status:** Risk Score {risk_score}/100 — {severity_counts}

#### Phase 1: Critical — Address Within 30 Days
For each CRITICAL finding, provide:
- Finding reference
- Specific action items (what to do, not why)
- Estimated effort (hours/days)
- Responsible team/role
- Verification method

#### Phase 2: High Priority — Address Within 90 Days
For each HIGH finding, same format as above.

#### Phase 3: Medium Priority — Address Within 180 Days
For MEDIUM and lower findings, same format.

#### Effort Summary
Total estimated effort across all phases. Resource requirements.

#### Verification & Retesting
How to validate each fix is effective before closing.

WRITE THE ROADMAP NOW. Use markdown. Be actionable and specific. No preamble."""


PROMPT_BUILDERS = {
    "executive": build_executive_prompt,
    "technical": build_technical_prompt,
    "onepager": build_onepager_prompt,
    "remediation": build_remediation_prompt,
}


# ── Main report generator ────────────────────────────────────────────────────

def generate_report(findings, meta, args):
    """Generate a report from findings."""
    target_name = args.target_name or TARGET_NAME_MAP.get(
        meta.get("target", ""), meta.get("target", "Unknown Target")
    )
    risk_score = meta.get("risk_score", 0)
    severity_counts = count_severities(findings)

    # Build findings text
    if len(findings) > CHUNK_THRESHOLD:
        print(f"INFO: {len(findings)} findings — using chunked generation")
        findings_text = format_findings_summary(findings)
    else:
        findings_text = "\n\n".join(
            format_finding(f, i + 1) for i, f in enumerate(sorted(
                findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99)
            ))
        )

    # Build prompt
    builder = PROMPT_BUILDERS.get(args.mode, build_technical_prompt)
    prompt = builder(target_name, risk_score, severity_counts, findings_text)

    # Add system prompt
    full_prompt = f"{SYSTEM_PROMPT}\n\n{prompt}"

    if args.dry_run:
        print("=" * 72)
        print("DRY RUN — Prompt that would be sent to LLM:")
        print("=" * 72)
        print(f"Model: {args.model}")
        print(f"Target: {target_name}")
        print(f"Mode: {args.mode}")
        print(f"Findings: {len(findings)}")
        print(f"Prompt length: {len(full_prompt)} chars (~{len(full_prompt)//4} tokens)")
        print("=" * 72)
        print(full_prompt[:10000])
        if len(full_prompt) > 10000:
            print(f"\n... ({len(full_prompt) - 10000} more characters truncated)")
        return

    # Call LLM
    llm = get_llm()
    provider, actual_model = llm.resolve_model(args.model)
    print(f"Generating {args.mode} report for {target_name} via {provider} ({actual_model})...")
    print(f"  {len(findings)} findings, risk score {risk_score}/100")
    response = llm.generate(full_prompt, model=args.model, system=SYSTEM_PROMPT, temperature=0.3)

    # Clean up response — remove any <｜end▁of▁thinking｜> tags or preamble
    # Strip any leading/trailing non-markdown fluff
    lines = response.split("\n")
    # Find first markdown heading
    start_idx = 0
    for i, line in enumerate(lines):
        if line.startswith("#") or line.startswith("##"):
            start_idx = i
            break
    cleaned = "\n".join(lines[start_idx:]).strip()

    # Write output
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        output_path = args.output
    else:
        ext = args.format
        output_path = os.path.join(REPORTS_DIR, f"report_{timestamp}.{ext}")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w") as fh:
        # Add report header
        fh.write(f"# HAKA Security Assessment Report\n\n")
        fh.write(f"**Target:** {target_name}  \n")
        fh.write(f"**Risk Score:** {risk_score}/100  \n")
        fh.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  \n")
        fh.write(f"**Classification:** CONFIDENTIAL  \n")
        fh.write(f"**Generated by:** HAKA AI Reporter ({args.model})\n\n")
        fh.write("---\n\n")
        fh.write(cleaned)
        fh.write("\n")

    print(f"Report written to: {output_path} ({len(cleaned)} chars)")
    return output_path


def interactive_report(findings, meta, args):
    """Interactive mode — generate section by section with user refinement."""
    target_name = args.target_name or TARGET_NAME_MAP.get(
        meta.get("target", ""), meta.get("target", "Unknown Target")
    )
    risk_score = meta.get("risk_score", 0)
    severity_counts = count_severities(findings)

    if len(findings) > CHUNK_THRESHOLD:
        findings_text = format_findings_summary(findings)
    else:
        findings_text = "\n\n".join(
            format_finding(f, i + 1) for i, f in enumerate(sorted(
                findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99)
            ))
        )

    sections = [
        ("executive_summary", f"Write ONLY an Executive Summary section for {target_name} (risk score {risk_score}/100). 2-3 paragraphs. Business language. Keep it under 300 words."),
        ("key_risks", f"Write ONLY a Key Risk Areas section. List the top 5 risk themes based on these findings. Business impact language. No technical jargon."),
        ("risk_interpretation", f"Write ONLY a Risk Score Interpretation section explaining the {risk_score}/100 score."),
        ("immediate_priorities", "Write ONLY an Immediate Priorities section with 3-5 concrete action items."),
        ("detailed_findings", "Write ONLY a Detailed Findings section covering the most critical findings in technical detail. 3-5 findings max."),
    ]

    output_sections = []
    print(f"\nInteractive report for {target_name} — {len(findings)} findings")
    print("Generate sections one at a time. Press Enter to accept, or type feedback to refine.\n")

    for section_name, section_prompt in sections:
        while True:
            prompt = f"""{SYSTEM_PROMPT}

Based on these findings:

{findings_text[:3000]}

{section_prompt}

Respond ONLY with the requested section. Use markdown."""
            print(f"\n--- Generating: {section_name} ---")
            llm = get_llm()
            response = llm.generate(prompt, model=args.model, system=SYSTEM_PROMPT, temperature=0.3)
            print(response[:2000])
            if len(response) > 2000:
                print(f"\n... (truncated, full: {len(response)} chars)")

            choice = input("\n[Enter=accept, r=regenerate, f=feedback, s=skip]: ").strip().lower()
            if choice == "":
                output_sections.append(response)
                break
            elif choice == "r":
                continue
            elif choice == "s":
                break
            elif choice.startswith("f"):
                feedback = choice[1:].strip() or input("Feedback: ")
                section_prompt += f"\n\nRevision requested: {feedback}"
                continue
            else:
                # Treat as feedback
                section_prompt += f"\n\nRevision requested: {choice}"
                continue

    # Assemble final report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or os.path.join(REPORTS_DIR, f"report_{timestamp}.md")
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w") as fh:
        fh.write(f"# HAKA Security Assessment Report\n\n")
        fh.write(f"**Target:** {target_name}  \n")
        fh.write(f"**Risk Score:** {risk_score}/100  \n")
        fh.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  \n")
        fh.write(f"**Classification:** CONFIDENTIAL  \n\n")
        fh.write("---\n\n")
        fh.write("\n\n".join(output_sections))
        fh.write("\n")

    print(f"\nReport written to: {output_path}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HAKA AI Reporter — Generate professional security reports from scan findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
Examples:
  %(prog)s --input reports/haka_consolidated_cbe.json
  %(prog)s --input reports/ --mode executive --target-name "CBE"
  %(prog)s --input findings.json --mode onepager --dry-run
  %(prog)s --input findings.json --mode technical --format html
  %(prog)s --input findings.json --interactive
        """),
    )
    parser.add_argument("--input", "-i", required=True, help="Path to consolidated JSON or directory of JSONs")
    parser.add_argument("--output", "-o", help="Output file path (default: auto-generated in reports/)")
    parser.add_argument("--format", "-f", default="md", choices=["md", "txt", "html"], help="Output format (default: md)")
    parser.add_argument("--mode", "-m", default="technical", choices=["executive", "technical", "onepager", "remediation"], help="Report type (default: technical)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=MODEL_HELP)
    parser.add_argument("--target-name", help="Override target name for report header")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode: refine sections one at a time")
    parser.add_argument("--dry-run", action="store_true", help="Print the prompt without calling LLM")

    args = parser.parse_args()

    # Show provider status
    llm = get_llm()
    provider_name, actual_model = llm.resolve_model(args.model)
    status = llm.status()
    provider_info = status.get(provider_name, {})
    if not provider_info.get("available", False) and provider_name not in ("ollama", "openclaw"):
        print(f"WARNING: Provider '{provider_name}' has no valid API key.", file=sys.stderr)
        print(f"  Falling back to local ollama. Set {provider_name.upper()}_API_KEY for cloud models.", file=sys.stderr)
        args.model = "qwen"  # fallback

    # Load findings
    findings, meta = load_findings(args.input)
    print(f"Loaded {len(findings)} findings from {args.input}")

    # Generate report
    if args.interactive:
        interactive_report(findings, meta, args)
    else:
        generate_report(findings, meta, args)


if __name__ == "__main__":
    main()
