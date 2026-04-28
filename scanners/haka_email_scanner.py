#!/usr/bin/env python3
"""
HAKA AI - Email Security Scanner (Tool 1: A1 - Email Spoofing T1566)

Checks domains for email security misconfigurations:
  SPF, DMARC, DKIM, MX records, SMTP banner, SMTP VRFY

Author:  HAKA AI Framework
Version: 1.0.0
"""

import argparse
import json
import os
import re
import smtplib
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import dns.resolver
    import dns.exception
except ImportError:
    sys.exit(
        "[!] dnspython is required.  Install it:\n"
        "    pip install dnspython"
    )

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    sys.exit(
        "[!] colorama is required.  Install it:\n"
        "    pip install colorama"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
TIMEOUT = 5  # seconds for every network operation
REPORTS_DIR = Path("/home/kironix/HAKA-AI/reports")

DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "mx",
    "smtp",
    "mandrill",
    "zendesk",
    "amazonses",
    "cm",
    "postmark",
    "protonmail",
    "everlytickey1",
    "everlytickey2",
]

RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.BLUE,
}


def _tag(severity: str, message: str) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    reset = Style.RESET_ALL
    label = f"[{severity}]"
    return f"  {color}{label:<12}{reset} {message}"


def banner() -> None:
    print(
        f"\n{Fore.CYAN}{Style.BRIGHT}"
        "  ██╗  ██╗ █████╗ ██╗  ██╗ █████╗      █████╗ ██╗\n"
        "  ██║  ██║██╔══██╗██║ ██╔╝██╔══██╗    ██╔══██╗██║\n"
        "  ███████║███████║█████╔╝ ███████║    ███████║██║\n"
        "  ██╔══██║██╔══██║██╔═██╗ ██╔══██║    ██╔══██║██║\n"
        "  ██║  ██║██║  ██║██║  ██╗██║  ██║    ██║  ██║██║\n"
        "  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝\n"
        f"{Style.RESET_ALL}"
        f"  {Fore.WHITE}Email Security Scanner v{VERSION} "
        f"| A1 - Email Spoofing (T1566){Style.RESET_ALL}\n"
    )


# ---------------------------------------------------------------------------
# DNS query helpers
# ---------------------------------------------------------------------------

def _resolve(qname: str, rdtype: str = "TXT") -> list[str]:
    """Return list of rdata strings for *qname*, or empty list on failure."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    resolver.timeout = TIMEOUT
    try:
        answers = resolver.resolve(qname, rdtype)
        results: list[str] = []
        for rdata in answers:
            if rdtype == "TXT":
                # TXT rdata is a tuple of byte strings; join and decode
                results.append(
                    b"".join(rdata.strings).decode("utf-8", errors="replace")
                )
            elif rdtype == "MX":
                results.append(str(rdata))
            else:
                results.append(str(rdata))
        return results
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.name.EmptyLabel,
        Exception,
    ):
        return []


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_spf(domain: str) -> dict[str, Any]:
    """Check SPF (TXT) record for *domain*."""
    result: dict[str, Any] = {
        "exists": False,
        "record": None,
        "mechanism": None,
        "findings": [],
    }
    txt_records = _resolve(domain, "TXT")
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            result["exists"] = True
            result["record"] = txt
            lower = txt.lower()
            if "-all" in lower:
                result["mechanism"] = "hard_fail"
            elif "~all" in lower:
                result["mechanism"] = "soft_fail"
                result["findings"].append({
                    "severity": "MEDIUM",
                    "message": (
                        "SPF record uses ~all (soft fail) instead of -all "
                        "-- spoofed mail may still be delivered"
                    ),
                })
            elif "?all" in lower:
                result["mechanism"] = "neutral"
                result["findings"].append({
                    "severity": "HIGH",
                    "message": (
                        "SPF record uses ?all (neutral) -- provides no "
                        "protection against spoofing"
                    ),
                })
            elif "+all" in lower:
                result["mechanism"] = "pass_all"
                result["findings"].append({
                    "severity": "CRITICAL",
                    "message": (
                        "SPF record uses +all -- explicitly allows ANY "
                        "server to send mail for this domain"
                    ),
                })
            else:
                result["mechanism"] = "other"
            break

    if not result["exists"]:
        result["findings"].append({
            "severity": "HIGH",
            "message": "No SPF record found -- any server can claim to send mail for this domain",
        })

    return result


def check_dmarc(domain: str) -> dict[str, Any]:
    """Check DMARC record at _dmarc.{domain}."""
    result: dict[str, Any] = {
        "exists": False,
        "record": None,
        "policy": None,
        "sub_policy": None,
        "pct": None,
        "rua": None,
        "findings": [],
    }
    txt_records = _resolve(f"_dmarc.{domain}", "TXT")
    for txt in txt_records:
        if "v=dmarc1" in txt.lower():
            result["exists"] = True
            result["record"] = txt

            # Parse policy
            p_match = re.search(r";\s*p\s*=\s*(\w+)", txt, re.IGNORECASE)
            if not p_match:
                # policy may be right after v=DMARC1
                p_match = re.search(r"v=DMARC1\s*;\s*p\s*=\s*(\w+)", txt, re.IGNORECASE)
            if p_match:
                result["policy"] = p_match.group(1).lower()

            # Sub-domain policy
            sp_match = re.search(r";\s*sp\s*=\s*(\w+)", txt, re.IGNORECASE)
            if sp_match:
                result["sub_policy"] = sp_match.group(1).lower()

            # Percentage
            pct_match = re.search(r";\s*pct\s*=\s*(\d+)", txt, re.IGNORECASE)
            if pct_match:
                result["pct"] = int(pct_match.group(1))

            # Aggregate report URI
            rua_match = re.search(r";\s*rua\s*=\s*([^;]+)", txt, re.IGNORECASE)
            if rua_match:
                result["rua"] = rua_match.group(1).strip()

            break

    # Findings
    if not result["exists"]:
        result["findings"].append({
            "severity": "CRITICAL",
            "message": "No DMARC record found -- domain is fully spoofable",
        })
    else:
        policy = result["policy"]
        if policy == "none":
            result["findings"].append({
                "severity": "HIGH",
                "message": (
                    "DMARC policy is p=none -- spoofed emails are "
                    "monitored but still delivered"
                ),
            })
        elif policy == "quarantine":
            result["findings"].append({
                "severity": "LOW",
                "message": (
                    "DMARC policy is p=quarantine -- spoofed emails "
                    "may land in spam but are not outright rejected"
                ),
            })
        elif policy == "reject":
            result["findings"].append({
                "severity": "INFO",
                "message": "DMARC policy is p=reject -- strong anti-spoofing posture",
            })

        if result["pct"] is not None and result["pct"] < 100:
            result["findings"].append({
                "severity": "MEDIUM",
                "message": (
                    f"DMARC pct={result['pct']} -- policy applies to only "
                    f"{result['pct']}% of messages"
                ),
            })

        if result["rua"] is None:
            result["findings"].append({
                "severity": "LOW",
                "message": "No DMARC aggregate report URI (rua) configured",
            })

    return result


def check_dkim(domain: str) -> dict[str, Any]:
    """Probe common DKIM selectors for *domain*."""
    result: dict[str, Any] = {
        "found_selectors": [],
        "checked_selectors": list(DKIM_SELECTORS),
        "findings": [],
    }

    for sel in DKIM_SELECTORS:
        qname = f"{sel}._domainkey.{domain}"
        # DKIM can be TXT or CNAME
        records = _resolve(qname, "TXT")
        if not records:
            records = _resolve(qname, "CNAME")
        if records:
            result["found_selectors"].append({
                "selector": sel,
                "record": records[0][:200],  # truncate long keys
            })

    if not result["found_selectors"]:
        result["findings"].append({
            "severity": "HIGH",
            "message": (
                f"No DKIM record found on any of {len(DKIM_SELECTORS)} "
                "tested selectors -- email authentication weakened"
            ),
        })
    else:
        names = ", ".join(s["selector"] for s in result["found_selectors"])
        result["findings"].append({
            "severity": "INFO",
            "message": f"DKIM found on selector(s): {names}",
        })

    return result


def check_mx(domain: str) -> dict[str, Any]:
    """Retrieve MX records for *domain*."""
    result: dict[str, Any] = {
        "exists": False,
        "records": [],
        "findings": [],
    }
    mx_records = _resolve(domain, "MX")
    if mx_records:
        result["exists"] = True
        for rec in mx_records:
            # Format: "10 mail.example.com."
            parts = str(rec).split()
            if len(parts) >= 2:
                result["records"].append({
                    "priority": int(parts[0]),
                    "host": parts[1].rstrip("."),
                })
            else:
                result["records"].append({"priority": 0, "host": str(rec)})
        result["records"].sort(key=lambda r: r["priority"])
        hosts = ", ".join(
            f"{r['host']} (priority {r['priority']})" for r in result["records"]
        )
        result["findings"].append({
            "severity": "INFO",
            "message": f"MX: {hosts}",
        })
    else:
        result["findings"].append({
            "severity": "LOW",
            "message": "No MX records found -- domain may not receive email",
        })

    return result


def check_smtp_banner(domain: str, mx_hosts: list[str]) -> dict[str, Any]:
    """Grab SMTP banner from MX hosts on port 25."""
    result: dict[str, Any] = {
        "banners": [],
        "findings": [],
    }
    targets = mx_hosts if mx_hosts else [domain]

    for host in targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((host, 25))
            banner_bytes = sock.recv(1024)
            sock.close()
            banner_text = banner_bytes.decode("utf-8", errors="replace").strip()
            result["banners"].append({"host": host, "banner": banner_text})
            result["findings"].append({
                "severity": "INFO",
                "message": f"SMTP banner ({host}): {banner_text}",
            })
            # Check for software disclosure
            disclosure_patterns = [
                (r"postfix", "Postfix"),
                (r"exim", "Exim"),
                (r"sendmail", "Sendmail"),
                (r"microsoft", "Microsoft Exchange"),
                (r"exchange", "Microsoft Exchange"),
                (r"zimbra", "Zimbra"),
                (r"dovecot", "Dovecot"),
            ]
            for pattern, name in disclosure_patterns:
                if re.search(pattern, banner_text, re.IGNORECASE):
                    result["findings"].append({
                        "severity": "LOW",
                        "message": (
                            f"SMTP banner on {host} discloses mail server "
                            f"software: {name}"
                        ),
                    })
                    break
        except (socket.timeout, ConnectionRefusedError, OSError):
            result["findings"].append({
                "severity": "INFO",
                "message": f"Could not connect to {host}:25 (timeout/refused)",
            })

    return result


def check_smtp_vrfy(domain: str, mx_hosts: list[str]) -> dict[str, Any]:
    """Test if SMTP VRFY command is enabled on MX hosts."""
    result: dict[str, Any] = {
        "vrfy_enabled": [],
        "findings": [],
    }
    targets = mx_hosts if mx_hosts else [domain]

    for host in targets:
        try:
            smtp = smtplib.SMTP(timeout=TIMEOUT)
            smtp.connect(host, 25)
            code, message = smtp.verify(f"test@{domain}")
            smtp.quit()
            # Codes 250, 251, 252 indicate VRFY is functional
            if code in (250, 251, 252):
                result["vrfy_enabled"].append(host)
                result["findings"].append({
                    "severity": "MEDIUM",
                    "message": (
                        f"SMTP VRFY command enabled on {host} -- "
                        "attackers can enumerate valid mailboxes"
                    ),
                })
            else:
                result["findings"].append({
                    "severity": "INFO",
                    "message": (
                        f"SMTP VRFY disabled or restricted on {host} "
                        f"(code {code})"
                    ),
                })
        except smtplib.SMTPServerDisconnected:
            result["findings"].append({
                "severity": "INFO",
                "message": f"SMTP server {host} disconnected during VRFY test",
            })
        except (
            smtplib.SMTPException,
            socket.timeout,
            ConnectionRefusedError,
            OSError,
        ) as exc:
            result["findings"].append({
                "severity": "INFO",
                "message": f"Could not test VRFY on {host}: {type(exc).__name__}",
            })

    return result


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

def calculate_risk_score(findings: list[dict[str, str]]) -> tuple[float, str]:
    """
    Calculate a 0-10 risk score from aggregated findings.

    Scoring logic:
      - Sum weighted severity points, cap at a maximum, then scale to 0-10.
      - CRITICAL findings immediately push score >= 8.
    """
    total = 0.0
    severity_counts: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total += RISK_WEIGHTS.get(sev, 0)

    # Normalize to 0-10 scale. Max realistic raw is ~40+ for a badly
    # configured domain; we use a soft cap so it doesn't blow past 10.
    max_raw = 38.0  # rough ceiling for "everything is broken"
    score = min(10.0, round((total / max_raw) * 10.0, 1))

    # Ensure at least 8.0 if any CRITICAL finding exists
    if severity_counts["CRITICAL"] > 0:
        score = max(score, 8.0)

    # Rating label
    if score >= 8.0:
        label = "CRITICAL"
    elif score >= 6.0:
        label = "HIGH"
    elif score >= 4.0:
        label = "MEDIUM"
    elif score >= 2.0:
        label = "LOW"
    else:
        label = "SECURE"

    return score, label


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def scan_domain(domain: str, smtp_check: bool = False) -> dict[str, Any]:
    """Run all checks against a single domain and return structured results."""
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return {}

    print(f"\n{Fore.GREEN}{Style.BRIGHT}  [SCAN] {domain}{Style.RESET_ALL}")
    print(f"  {'=' * 60}")

    result: dict[str, Any] = {
        "domain": domain,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "checks": {},
        "findings": [],
        "risk_score": 0.0,
        "risk_label": "",
    }

    # -- SPF --
    spf = check_spf(domain)
    result["checks"]["spf"] = spf
    result["findings"].extend(spf["findings"])

    # -- DMARC --
    dmarc = check_dmarc(domain)
    result["checks"]["dmarc"] = dmarc
    result["findings"].extend(dmarc["findings"])

    # -- DKIM --
    dkim = check_dkim(domain)
    result["checks"]["dkim"] = dkim
    result["findings"].extend(dkim["findings"])

    # -- MX --
    mx = check_mx(domain)
    result["checks"]["mx"] = mx
    result["findings"].extend(mx["findings"])

    # Derive MX hosts for SMTP checks
    mx_hosts = [r["host"] for r in mx.get("records", [])]

    # -- SMTP checks (optional) --
    if smtp_check:
        smtp_banner = check_smtp_banner(domain, mx_hosts)
        result["checks"]["smtp_banner"] = smtp_banner
        result["findings"].extend(smtp_banner["findings"])

        smtp_vrfy = check_smtp_vrfy(domain, mx_hosts)
        result["checks"]["smtp_vrfy"] = smtp_vrfy
        result["findings"].extend(smtp_vrfy["findings"])
    else:
        result["checks"]["smtp_banner"] = {"skipped": True}
        result["checks"]["smtp_vrfy"] = {"skipped": True}

    # -- Risk score --
    score, label = calculate_risk_score(result["findings"])
    result["risk_score"] = score
    result["risk_label"] = label

    # -- Console output --
    for f in result["findings"]:
        print(_tag(f["severity"], f["message"]))

    # Score line
    score_color = (
        Fore.RED + Style.BRIGHT if score >= 8.0
        else Fore.RED if score >= 6.0
        else Fore.YELLOW if score >= 4.0
        else Fore.GREEN
    )
    print(
        f"\n  {score_color}Risk Score: {score}/10 -- "
        f"{label}{Style.RESET_ALL}\n"
    )

    return result


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def write_report(results: list[dict[str, Any]], output_path: Path) -> Path:
    """Write JSON report and return the file path."""
    report = {
        "tool": "haka_email_scanner",
        "version": VERSION,
        "mitre_technique": "T1566 - Phishing / Email Spoofing",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_domains": len(results),
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "secure": 0,
        },
        "results": results,
    }

    for r in results:
        label = r.get("risk_label", "").lower()
        if label in report["summary"]:
            report["summary"][label] += 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    return output_path


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(results: list[dict[str, Any]]) -> None:
    """Print a compact summary table after all scans."""
    if not results:
        return

    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 66}")
    print(f"  SCAN SUMMARY")
    print(f"{'=' * 66}{Style.RESET_ALL}\n")

    header = f"  {'Domain':<35} {'Score':>7}  {'Rating':<10}"
    print(f"{Style.BRIGHT}{header}{Style.RESET_ALL}")
    print(f"  {'-' * 60}")

    severity_totals: dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for r in results:
        domain = r["domain"]
        score = r["risk_score"]
        label = r["risk_label"]

        color = (
            Fore.RED + Style.BRIGHT if score >= 8.0
            else Fore.RED if score >= 6.0
            else Fore.YELLOW if score >= 4.0
            else Fore.GREEN
        )

        print(f"  {domain:<35} {color}{score:>5}/10  {label:<10}{Style.RESET_ALL}")

        for f in r.get("findings", []):
            sev = f["severity"]
            severity_totals[sev] = severity_totals.get(sev, 0) + 1

    print(f"\n  {'-' * 60}")
    print(f"  Total domains scanned: {len(results)}")
    print(
        f"  Findings: "
        f"{Fore.RED}{Style.BRIGHT}{severity_totals['CRITICAL']} Critical{Style.RESET_ALL}, "
        f"{Fore.RED}{severity_totals['HIGH']} High{Style.RESET_ALL}, "
        f"{Fore.YELLOW}{severity_totals['MEDIUM']} Medium{Style.RESET_ALL}, "
        f"{Fore.CYAN}{severity_totals['LOW']} Low{Style.RESET_ALL}, "
        f"{Fore.BLUE}{severity_totals['INFO']} Info{Style.RESET_ALL}"
    )
    print()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="haka_email_scanner",
        description=(
            "HAKA AI - Email Security Scanner\n"
            "Assess SPF, DMARC, DKIM, MX, and SMTP configurations for "
            "target domains."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --domain example.com\n"
            "  %(prog)s --file domains.txt --smtp-check\n"
            "  %(prog)s --domain example.com --output /tmp/report.json\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-d",
        "--domain",
        type=str,
        help="Single domain to scan",
    )
    group.add_argument(
        "-f",
        "--file",
        type=str,
        help="File containing one domain per line",
    )
    parser.add_argument(
        "--smtp-check",
        action="store_true",
        default=False,
        help="Enable SMTP banner grab and VRFY checks (disabled by default)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help=(
            "Path for JSON report output "
            "(default: /home/kironix/HAKA-AI/reports/email_scan_<timestamp>.json)"
        ),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress banner art",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    colorama_init(autoreset=False)
    args = parse_args()

    if not args.quiet:
        banner()

    # Build domain list
    domains: list[str] = []
    if args.domain:
        domains.append(args.domain.strip())
    elif args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"{Fore.RED}[!] File not found: {args.file}{Style.RESET_ALL}")
            sys.exit(1)
        with open(file_path, "r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    domains.append(stripped)

    if not domains:
        print(f"{Fore.RED}[!] No domains to scan.{Style.RESET_ALL}")
        sys.exit(1)

    print(
        f"  {Fore.WHITE}Targets: {len(domains)} domain(s) | "
        f"SMTP checks: {'ON' if args.smtp_check else 'OFF'}{Style.RESET_ALL}"
    )

    # Run scans
    results: list[dict[str, Any]] = []
    start_time = time.monotonic()

    for domain in domains:
        try:
            result = scan_domain(domain, smtp_check=args.smtp_check)
            if result:
                results.append(result)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
            break
        except Exception as exc:
            print(
                f"\n{Fore.RED}[!] Unexpected error scanning {domain}: "
                f"{exc}{Style.RESET_ALL}"
            )

    elapsed = round(time.monotonic() - start_time, 2)

    # Summary
    print_summary(results)
    print(f"  Scan completed in {elapsed}s\n")

    # Write report
    if args.output:
        report_path = Path(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = REPORTS_DIR / f"email_scan_{ts}.json"

    report_file = write_report(results, report_path)
    print(
        f"  {Fore.GREEN}[+] Report saved to: "
        f"{report_file}{Style.RESET_ALL}\n"
    )


if __name__ == "__main__":
    main()
