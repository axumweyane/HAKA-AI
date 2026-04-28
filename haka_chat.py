#!/usr/bin/env python3
"""
HAKA Chat — Natural language query interface for HAKA scan findings.
Ask questions about vulnerability assessments across Ethiopian financial institutions.

Usage:
  haka_chat.py --query "show me critical findings at CBE"
  haka_chat.py -q "which bank has the worst email security"
  haka_chat.py --interactive
  haka_chat.py -q "compare CBE and Awash" --target cbe
"""

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import textwrap

# HAKA provider module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from haka_providers import HakaLLM
import urllib.request
import urllib.error
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
DEFAULT_MODEL = "r1"  # Uses ollama:deepseek-r1:7b locally

MODEL_HELP = (
    "Model to use. Shortcuts: r1 (local, fast), qwen (local, quality), "
    "deepseek (cloud), claude (cloud), gemma (local)"
)
MAX_CONTEXT_TOKENS = 4000
CHARS_PER_TOKEN_ESTIMATE = 4

TARGET_ALIASES = {
    "cbe": "combanketh.et",
    "awash": "awashbank.com",
    "boa": "bankofabyssinia.com",
    "bank of abyssinia": "bankofabyssinia.com",
    "abyssinia": "bankofabyssinia.com",
    "dashen": "dashenbanksc.com",
    "etaf": "etaf.mil.et",
    "air force": "etaf.mil.et",
    "ethio telecom": "ethiotelecom.et",
    "ethiotelecom": "ethiotelecom.et",
    "telecom": "ethiotelecom.et",
    "telebirr": "telebirr.ethiotelecom.et",
    "commercial bank": "combanketh.et",
    "commercial bank of ethiopia": "combanketh.et",
}

TARGET_DISPLAY_NAMES = {
    "combanketh.et": "CBE (Commercial Bank of Ethiopia)",
    "awashbank.com": "Awash Bank",
    "bankofabyssinia.com": "Bank of Abyssinia (BOA)",
    "dashenbanksc.com": "Dashen Bank",
    "etaf.mil.et": "Ethiopian Air Force (ETAF)",
    "ethiotelecom.et": "Ethio Telecom",
    "telebirr.ethiotelecom.et": "Telebirr",
}

SYSTEM_PROMPT = (
    "You are a HAKA cybersecurity analyst assistant. You have access to vulnerability "
    "assessment findings from Ethiopian financial institutions. Answer questions precisely "
    "using the provided finding data. If asked to compare, use concrete numbers. "
    "If asked about patterns, synthesize across multiple targets. Keep responses concise."
)

# Technology keywords for smart matching
TECH_KEYWORDS = [
    "exchange", "owa", "ecp", "ews", "outlook",
    "swift", "finra", "banking",
    "s3", "aws", "cloud", "bucket",
    "dns", "spf", "dkim", "dmarc", "email", "phishing", "spoof",
    "tls", "ssl", "certificate", "https",
    "vpn", "ssl vpn", "fortinet", "pulse", "anyconnect",
    "kerberos", "ntlm", "active directory", "ldap",
    "rdp", "rdp", "remote desktop",
    "apache", "nginx", "iis", "tomcat", "web server",
    "mysql", "postgresql", "mssql", "database",
    "cve", "cwe", "vulnerability",
    "proxy", "proxyshell", "proxylogon",
    "sharepoint", "skype", "lync",
    "waf", "firewall", "ids", "ips",
    "open port", "port", "exposed",
    "password", "credential", "authentication", "mfa",
    "subdomain", "domain",
    "xss", "csrf", "sqli", "injection",
]


# ── Data loading ─────────────────────────────────────────────────────────────

def load_all_reports():
    """Load all consolidated JSONs and build in-memory index."""
    index = {}
    pattern = os.path.join(REPORTS_DIR, "haka_consolidated_*.json")
    import glob
    json_files = sorted(glob.glob(pattern))

    if not json_files:
        print(f"ERROR: No consolidated JSONs found in {REPORTS_DIR}", file=sys.stderr)
        sys.exit(1)

    for jf in json_files:
        try:
            with open(jf) as fh:
                data = json.load(fh)
            target = data.get("target", "unknown")
            index[target] = {
                "risk_score": data.get("risk_score", 0),
                "severity_counts": data.get("severity_counts", {}),
                "findings": data.get("findings", []),
                "scan_time": data.get("scan_time", ""),
                "file": os.path.basename(jf),
            }
        except (json.JSONDecodeError, KeyError) as e:
            print(f"WARNING: Skipping {jf}: {e}", file=sys.stderr)

    return index


def resolve_targets(query, index, cli_target=None):
    """Resolve which targets are relevant for a query."""
    query_lower = query.lower() if query else ""
    matched = set()

    # Check CLI --target flag first
    if cli_target:
        for alias, canonical in TARGET_ALIASES.items():
            if cli_target.lower() in alias or cli_target.lower() in canonical:
                if canonical in index:
                    matched.add(canonical)
        if not matched:
            print(f"WARNING: Target '{cli_target}' not found in index", file=sys.stderr)

    # Check query for target mentions
    for alias, canonical in TARGET_ALIASES.items():
        if alias in query_lower:
            if canonical in index:
                matched.add(canonical)

    # If no targets matched, include all
    if not matched:
        matched = set(index.keys())

    return list(matched)


def extract_keywords(query):
    """Extract relevant technology/search keywords from query."""
    query_lower = query.lower() if query else ""
    keywords = set()
    for kw in TECH_KEYWORDS:
        if kw in query_lower:
            keywords.add(kw)
    return keywords


def select_relevant_findings(index, targets, query, max_context=None):
    """Select findings relevant to the query from specified targets."""
    max_chars = max_context or (MAX_CONTEXT_TOKENS * CHARS_PER_TOKEN_ESTIMATE)
    keywords = extract_keywords(query)

    # Collect all findings from matching targets
    all_candidates = []
    for target in targets:
        if target not in index:
            continue
        for f in index[target]["findings"]:
            f = dict(f)
            f["_source_target"] = target
            all_candidates.append(f)

    # Score each finding by relevance
    scored = []
    for f in all_candidates:
        score = 0
        finding_text = json.dumps(f).lower()

        # Severity-based scoring
        sev = f.get("severity", "").upper()
        if sev == "CRITICAL":
            score += 10
        elif sev == "HIGH":
            score += 5

        # Keyword matching
        for kw in keywords:
            if kw in finding_text:
                score += 3

        # If query mentions severity directly
        query_lower = query.lower() if query else ""
        if "critical" in query_lower and sev == "CRITICAL":
            score += 20
        if "high" in query_lower and sev == "HIGH":
            score += 20

        # Target name matching
        if any(t.lower() in query_lower for t in targets):
            score += 2

        scored.append((score, f))

    # Sort by relevance score descending
    scored.sort(key=lambda x: x[0], reverse=True)

    # Select findings up to char limit
    selected = []
    total_chars = 0
    for score, f in scored:
        finding_text = format_finding_compact(f)
        if total_chars + len(finding_text) <= max_chars:
            selected.append(f)
            total_chars += len(finding_text)
        else:
            # If we have room but not much, still try to include criticals
            if f.get("severity") == "CRITICAL" and total_chars < max_chars * 0.9:
                selected.append(f)
                total_chars += len(finding_text)

    return selected


def format_finding_compact(f):
    """Format a finding compactly for context inclusion."""
    target = f.pop("_source_target", "unknown")
    lines = [
        f"  [{f.get('id')}] {f.get('severity')} | {f.get('title')}",
        f"    Target: {f.get('target', target)}",
        f"    Evidence: {f.get('evidence', 'N/A')[:200]}",
        f"    MITRE: {f.get('mitre', 'N/A')} | Fix: {'; '.join(f.get('remediation', []))[:150]}",
    ]
    return "\n".join(lines)


def build_context_summary(index, targets):
    """Build a summary of all targets for comparison/pattern queries."""
    lines = ["# Multi-Target Summary\n"]
    for target in sorted(targets):
        if target not in index:
            continue
        info = index[target]
        display = TARGET_DISPLAY_NAMES.get(target, target)
        lines.append(f"## {display}")
        lines.append(f"  Risk Score: {info['risk_score']}/100")
        lines.append(f"  Severity: {json.dumps(info['severity_counts'])}")
        lines.append(f"  Total Findings: {len(info['findings'])}")

        # Top 3 findings
        sorted_findings = sorted(info["findings"], key=lambda x: (
            0 if x.get("severity") == "CRITICAL" else 1 if x.get("severity") == "HIGH" else 2
        ))
        lines.append("  Top Findings:")
        for f in sorted_findings[:3]:
            lines.append(f"    - [{f.get('severity')}] {f.get('id')}: {f.get('title')}")
        lines.append("")
    return "\n".join(lines)


def build_context(index, targets, query):
    """Build full context for the LLM based on query analysis."""
    query_lower = query.lower() if query else ""
    keywords = extract_keywords(query)

    # Detect query type
    is_comparison = any(w in query_lower for w in ["compare", "versus", "vs", "worst", "best", "most", "across", "all targets", "every"])
    is_pattern = any(w in query_lower for w in ["pattern", "common", "trend", "most common", "frequent", "which bank", "how many"])
    is_specific = bool(keywords) or any(w in query_lower for w in ["show", "find", "list", "give me", "what are"])

    context_parts = []

    if is_comparison or is_pattern:
        # Include summary of all targets
        context_parts.append(build_context_summary(index, targets))
        # Also include some detailed findings
        detailed = select_relevant_findings(index, targets, query, max_context=6000)
        if detailed:
            context_parts.append("\n# Detailed Findings\n")
            context_parts.append("\n".join(format_finding_compact(f) for f in detailed[:20]))
    else:
        # Include relevant findings from specific targets
        detailed = select_relevant_findings(index, targets, query)
        if detailed:
            context_parts.append(f"# Findings for: {', '.join(TARGET_DISPLAY_NAMES.get(t, t) for t in targets)}\n")
            context_parts.append("\n".join(format_finding_compact(f) for f in detailed))
        else:
            # Fallback: include summary
            context_parts.append(build_context_summary(index, targets))

    return "\n".join(context_parts)


# ── LLM interface ──────────────────────────────────────────────────────────

_llm_instance = None

def get_llm():
    global _llm_instance
    if _llm_instance is None:
        _llm_instance = HakaLLM()
    return _llm_instance


# ── Query processing ─────────────────────────────────────────────────────────

def process_query(index, query, args):
    """Process a single query."""
    # Resolve targets
    targets = resolve_targets(query, index, args.target)

    # Build context
    context = build_context(index, targets, query)
    context_chars = len(context)

    # Build full prompt
    prompt = f"""{SYSTEM_PROMPT}

CONTEXT — HAKA Scan Findings:
{context}

USER QUERY: {query}

Answer the query concisely using only the provided finding data. 
If data is insufficient, say so. Use bullet points for lists."""

    if args.dry_run:
        print("=" * 60)
        print(f"DRY RUN — Query: {query}")
        print(f"Targets: {', '.join(TARGET_DISPLAY_NAMES.get(t, t) for t in targets)}")
        print(f"Context: {context_chars} chars (~{context_chars // 4} tokens)")
        print("=" * 60)
        print(context[:3000])
        if len(context) > 3000:
            print(f"\n... ({len(context) - 3000} more chars)")
        return

    # Call LLM
    llm = get_llm()
    response = llm.generate(prompt, model=args.model, temperature=0.2)

    # Clean up  response tags
    response = response.replace("<｜end▁of▁thinking｜>", "").replace("", "")
    response = response.strip()

    print(f"\n{response}\n")
    print(f"[Context: {context_chars} chars, Targets: {len(targets)}]")


# ── Interactive REPL ─────────────────────────────────────────────────────────

def interactive_loop(index, args):
    """Run interactive REPL."""
    print(f"\n{'='*60}")
    print("HAKA Chat — Interactive Security Findings Query")
    print(f"Model: {args.model}  |  Targets: {len(index)} loaded")
    if args.target:
        targets = resolve_targets("", index, args.target)
        print(f"Filter: {', '.join(TARGET_DISPLAY_NAMES.get(t, t) for t in targets)}")
    print(f"{'='*60}")
    print("Type 'help' for commands, 'quit' to exit.\n")

    while True:
        try:
            query = input("HAKA> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not query:
            continue

        if query.lower() in ("quit", "exit", "q"):
            print("Goodbye.")
            break
        elif query.lower() == "help":
            print(textwrap.dedent("""\
            Commands:
              <query>       Ask about findings
              targets       List all available targets
              stats         Show summary stats for all targets
              model <name>  Switch model
              filter <tgt>  Filter to a specific target
              filter all    Remove target filter
              help          Show this help
              quit          Exit
            """))
            continue
        elif query.lower() == "targets":
            print("\nAvailable targets:")
            for target in sorted(index.keys()):
                info = index[target]
                display = TARGET_DISPLAY_NAMES.get(target, target)
                print(f"  {display:45s}  Risk: {info['risk_score']:3d}/100  "
                      f"Findings: {len(info['findings']):3d}  "
                      f"Crit: {info['severity_counts'].get('CRITICAL', 0)}")
            print()
            continue
        elif query.lower() == "stats":
            print("\nAggregate Statistics:")
            total_findings = sum(len(info["findings"]) for info in index.values())
            total_critical = sum(info["severity_counts"].get("CRITICAL", 0) for info in index.values())
            total_high = sum(info["severity_counts"].get("HIGH", 0) for info in index.values())
            avg_risk = sum(info["risk_score"] for info in index.values()) / max(len(index), 1)
            print(f"  Total Targets: {len(index)}")
            print(f"  Total Findings: {total_findings}")
            print(f"  Total CRITICAL: {total_critical}")
            print(f"  Total HIGH: {total_high}")
            print(f"  Average Risk Score: {avg_risk:.1f}/100\n")
            continue
        elif query.lower().startswith("model "):
            new_model = query[6:].strip()
            try:
                llm = get_llm()
                provider, actual = llm.resolve_model(new_model)
                args.model = new_model
                print(f"Switched to model: {new_model} ({provider}/{actual})\n")
            except Exception as e:
                print(f"Model '{new_model}' not found.\n")
            continue
        elif query.lower().startswith("filter "):
            filter_val = query[7:].strip()
            if filter_val.lower() == "all":
                args.target = None
                print("Filter removed.\n")
            else:
                args.target = filter_val
                targets = resolve_targets("", index, args.target)
                print(f"Filter set to: {', '.join(TARGET_DISPLAY_NAMES.get(t, t) for t in targets)}\n")
            continue

        process_query(index, query, args)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HAKA Chat — Query HAKA cybersecurity findings in natural language",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
Examples:
  %(prog)s -q "show me critical findings at CBE"
  %(prog)s -q "which bank has the worst email security"
  %(prog)s -q "compare CBE and Awash Bank"
  %(prog)s -q "what are the most common vulnerabilities"
  %(prog)s --interactive
  %(prog)s -i --target cbe
        """),
    )
    parser.add_argument("--query", "-q", help="One-shot query (exit after answering)")
    parser.add_argument("--model", "-m", default=DEFAULT_MODEL, help=MODEL_HELP)
    parser.add_argument("--context", "-c", type=int, default=None, help="Max context chars (default: ~16000 for 4000 tokens)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive REPL mode")
    parser.add_argument("--target", "-t", help="Filter to specific target (cbe, awash, boa, dashen, etaf, ethiotelecom, telebirr)")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Show context without calling LLM")

    args = parser.parse_args()

    if not args.query and not args.interactive:
        parser.error("Must specify --query/-q or --interactive/-i")

    # Show status
    if not args.dry_run:
        llm = get_llm()
        status = llm.status()
        provider, actual = llm.resolve_model(args.model)
        prov_info = status.get(provider, {})
        if not prov_info.get("available", True) and provider != "ollama":
            print(f"WARNING: {provider} API key missing — falling back to local ollama")
            print(f"  Set {provider.upper()}_API_KEY env var for cloud models.")
            args.model = "r1"
            sys.exit(1)

    # Load all reports
    print(f"Loading scan findings...", file=sys.stderr)
    index = load_all_reports()
    print(f"Loaded {len(index)} targets, {sum(len(v['findings']) for v in index.values())} total findings\n", file=sys.stderr)

    if args.interactive:
        interactive_loop(index, args)
    else:
        process_query(index, args.query, args)


if __name__ == "__main__":
    main()
