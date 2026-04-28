#!/usr/bin/env python3
"""
HAKA Proposal Generator — Generate customized cybersecurity assessment proposals
from CRM data + the HAKA proposal template.

Usage:
  # Generate a proposal from a CRM engagement
  python3 haka_proposal.py --engagement 1 --output proposals/CBE_Proposal.md

  # Preview without saving
  python3 haka_proposal.py --engagement 1 --preview

  # List all generated proposals
  python3 haka_proposal.py --list

  # List engagements available
  python3 haka_proposal.py --list-engagements

Database: Reads from ~/.haka/haka_crm.db
Template: docs/Proposal_Template.md (in same directory as this script)
"""

import argparse
import os
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

# ── Paths ───────────────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_PATH = BASE_DIR / "docs" / "Proposal_Template.md"
DB_PATH = os.path.expanduser("~/.haka/haka_crm.db")

# ── Engagement Scope Descriptions ───────────────────────────────────────────

SCOPE_DESCRIPTIONS = {
    "external_assessment": """
**External Vulnerability Assessment**

The engagement will evaluate the security posture of Internet-facing systems, including web applications, email infrastructure, VPN endpoints, DNS configuration, and TLS/SSL implementation. Assessment includes automated vulnerability scanning, manual validation of findings, and MITRE ATT&CK mapping.

**Typical duration:** 2–3 weeks
**In-scope by default:** External IP ranges, public-facing domains, email security (SPF/DKIM/DMARC), TLS configuration, web application perimeter.""",

    "full_pentest": """
**Full Penetration Test (External + Internal)**

A comprehensive adversarial simulation covering both external perimeter and internal network security. The engagement includes external vulnerability assessment, authenticated internal network testing, Active Directory security review, lateral movement simulation, and privilege escalation testing where applicable.

**Typical duration:** 4–6 weeks
**In-scope by default:** External IP ranges, all public-facing services, internal network segments, Active Directory environment, critical application servers.""",

    "quarterly_retainer": """
**Quarterly Security Reassessment**

Ongoing security monitoring with quarterly reassessments of the client's external attack surface. Each quarter includes a full external vulnerability scan, comparison against the baseline assessment, new finding identification, and verification that previously identified vulnerabilities have been remediated.

**Typical duration:** 1 week per quarter
**In-scope by default:** Same external scope as the baseline assessment, updated quarterly for new services and infrastructure changes.""",

    "ir_retainer": """
**Incident Response Retainer**

Priority access to HAKA Security Consulting incident response services on a retained basis. The retainer includes a pre-positioned incident response plan tailored to the client's environment, tabletop exercise facilitation, and guaranteed response time SLA (24 hours for critical incidents, 48 hours for standard).

**Retainer period:** 12 months
**In-scope by default:** Remote incident response triage, forensic analysis guidance, containment and eradication advisory, post-incident reporting to satisfy NBE notification requirements.""",
}

ENGAGEMENT_TYPE_LABELS = {
    "external_assessment": "External Vulnerability Assessment",
    "full_pentest": "Full Penetration Test (External + Internal)",
    "quarterly_retainer": "Quarterly Security Reassessment",
    "ir_retainer": "Incident Response Retainer",
}


# ── Database Helpers ────────────────────────────────────────────────────────

def get_db():
    if not os.path.exists(DB_PATH):
        print(f"Error: CRM database not found at {DB_PATH}", file=sys.stderr)
        print("Run haka_crm.py first to set up clients and engagements.", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_engagement(conn, engagement_id: int):
    row = conn.execute(
        "SELECT e.*, c.name as client_name, c.organization, c.email, c.phone "
        "FROM engagements e JOIN clients c ON e.client_id = c.id "
        "WHERE e.id = ?",
        (engagement_id,),
    ).fetchone()
    if not row:
        print(f"Error: Engagement #{engagement_id} not found", file=sys.stderr)
        sys.exit(1)
    return row


def list_engagements(conn):
    rows = conn.execute(
        "SELECT e.id, e.type, e.status, e.value, c.name, c.organization "
        "FROM engagements e JOIN clients c ON e.client_id = c.id "
        "ORDER BY e.id"
    ).fetchall()
    if not rows:
        print("No engagements in CRM. Add some with haka_crm.py --add-engagement")
        return
    print(f"{'ID':<5} {'Type':<25} {'Status':<15} {'Value':>8}  Client")
    print("-" * 85)
    for r in rows:
        label = ENGAGEMENT_TYPE_LABELS.get(r["type"], r["type"])
        org = r["organization"] or r["name"]
        print(f"{r['id']:<5} {label:<25} {r['status']:<15} ${r['value']:>7,.0f}  {org}")


def list_proposals(output_dir: Path):
    if not output_dir.exists():
        print("No proposals generated yet (proposals/ directory does not exist)")
        return
    files = sorted(output_dir.glob("*.md"))
    if not files:
        print("No proposals found in proposals/ directory")
        return
    print(f"{'File':<40} {'Size':>8}  {'Modified'}")
    print("-" * 75)
    for f in files:
        stat = f.stat()
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        size_kb = stat.st_size / 1024
        print(f"{f.name:<40} {size_kb:>6.1f}KB  {mtime}")


# ── Proposal Generation ─────────────────────────────────────────────────────

def generate_proposal_number(conn) -> str:
    """Generate HAKA-PROP-YYYY-NNN based on existing proposals."""
    year = datetime.now().year
    prefix = f"HAKA-PROP-{year}-"
    # Count existing proposal files for sequence number
    existing = conn.execute(
        "SELECT number FROM invoices WHERE number LIKE ?", (f"HAKA-PROP-{year}-%",)
    ).fetchall()
    # Also check the proposals directory
    proposals_dir = BASE_DIR / "proposals"
    count = 0
    if proposals_dir.exists():
        for f in proposals_dir.iterdir():
            if f.suffix == ".md" and f"HAKA-PROP-{year}" in f.read_text(encoding="utf-8", errors="ignore"):
                count += 1
    # Also check invoice numbering for cross-reference
    for row in existing:
        try:
            num = int(row["number"].split("-")[-1])
            count = max(count, num)
        except (ValueError, IndexError):
            pass
    # Use max of CRM engagement count and file count
    max_eng = conn.execute("SELECT COUNT(*) as c FROM engagements").fetchone()["c"]
    seq = max(count, max_eng) + 1
    return f"{prefix}{seq:03d}"


def fill_template(template: str, engagement: sqlite3.Row, prop_num: str) -> str:
    """Fill the proposal template with engagement data."""
    org = engagement["organization"] or engagement["client_name"]
    etype = engagement["type"]
    etype_label = ENGAGEMENT_TYPE_LABELS.get(etype, etype)
    scope_text = SCOPE_DESCRIPTIONS.get(etype, SCOPE_DESCRIPTIONS["external_assessment"])
    value = engagement["value"]
    today = datetime.now().strftime("%d %B %Y")

    # Duration estimates
    durations = {
        "external_assessment": "2–3 weeks",
        "full_pentest": "4–6 weeks",
        "quarterly_retainer": "1 week per quarter (12-month retainer)",
        "ir_retainer": "12 months (retainer, as-needed response)",
    }
    duration = durations.get(etype, "2–3 weeks")

    # VAT calculation
    vat_amount = value * 0.15
    total = value + vat_amount

    result = template

    # --- Replace [FILL] placeholders ---
    # Proposal number
    result = re.sub(r'`\[FILL:\s*HAKA-PROP-YYYY-NNN\s*\]`', f'`{prop_num}`', result)
    result = re.sub(r'\[FILL:\s*HAKA-PROP-YYYY-NNN\s*\]', prop_num, result)

    # Client name
    result = result.replace("[FILL: Client Organization Name]", org)
    result = result.replace("[FILL: Client Name]", org)

    # Date
    result = re.sub(r'\[FILL:\s*Proposal Date\s*\]', today, result)

    # Engagement type
    result = re.sub(
        r'\[FILL:\s*Engagement Type\s*.*?\]', f"{etype_label}", result, count=1
    )
    result = re.sub(
        r'`\[FILL:\s*Engagement Type\s*.*?\]`', f"**{etype_label}**", result
    )

    # Number of institutions
    result = re.sub(
        r'\[FILL:\s*Number\s*.*?\]', "seven (7)", result
    )

    # Scope description (replace placeholder scope text)
    scope_placeholder = r'\[FILL:\s*List of in-scope domains, IP ranges.*?\]'
    result = re.sub(scope_placeholder, f"[Client to provide list of in-scope assets]\n\n{scope_text}", result, flags=re.DOTALL)

    # Duration
    result = re.sub(
        r'\[FILL:\s*---\s*e\.g\.,\s*2-3 weeks\s*\]', duration, result
    )
    result = re.sub(
        r'\[FILL:\s*---\s*e\.g\.,\s*2–3 weeks\s*\]', duration, result
    )

    # Timeline placeholders
    result = re.sub(r'\[FILL:\s*Start Date\s*\]', "[Client to confirm]", result)
    result = re.sub(r'\[FILL:\s*Start Date.*?\]', "[Client to confirm]", result)
    result = re.sub(r'\[FILL:\s*Delivery Date\s*\]', "[TBD upon kickoff]", result)

    # Timeline milestones (general)
    result = re.sub(
        r'\[FILL:\s*---\s*e\.g\.,\s*2–5 days\s*\]', "[Per assessment timeline above]", result
    )
    result = re.sub(
        r'\[FILL:\s*---\s*e\.g\.,\s*3–5 days\s*\]', "[Per assessment timeline above]", result
    )

    # Pricing
    result = re.sub(
        r'\[FILL:\s*Engagement Type\s*\]\s*\|\s*\*\$`\[FILL:\s*Amount\s*\]`\*',
        f'{etype_label} | **${value:,.0f}**',
        result
    )

    # Amount
    result = re.sub(
        r'\$`\[FILL:\s*Amount\s*\]`', f'${value:,.0f}', result
    )

    # VAT
    result = re.sub(
        r'\$`\[FILL:\s*VAT amount or 0\s*\]`', f'${vat_amount:,.0f}', result
    )

    # Total
    result = re.sub(
        r'\$`\[FILL:\s*Total\s*\]`', f'${total:,.0f}', result
    )

    # Payment terms days
    result = re.sub(
        r'\[FILL:\s*---\s*e\.g\.,\s*fifteen \(15\).*?\]', "fifteen (15)", result
    )

    # Non-solicitation months
    result = re.sub(
        r'\[FILL:\s*---\s*e\.g\.,\s*twelve \(12\).*?\]', "twelve (12)", result
    )

    # Validity period
    result = re.sub(
        r'\[FILL:\s*---\s*e\.g\.,\s*thirty \(30\).*?\]', "thirty (30)", result
    )

    # Deliverables timeline
    result = re.sub(
        r'\[FILL:\s*Days\s*---\s*e\.g\.,\s*five \(5\).*?\]', "five (5)", result
    )

    # Signature block client name
    result = result.replace("[FILL: Client Organization Name]", org, 1)
    # Any remaining [FILL: Signatory...] placeholders
    result = re.sub(r'\[FILL:\s*Signatory full name\s*\]', "[Authorized Signatory Name]", result)
    result = re.sub(r'\[FILL:\s*Signatory title\s*\]', "[Title — CISO, CTO, CEO]", result)

    # Clean up any remaining [FILL: ...] placeholders
    result = re.sub(r'`\[FILL:[^]]*\]`', '[FILL]', result)
    result = re.sub(r'\[FILL:[^]]*\]', '[FILL]', result)

    return result


def generate_proposal(engagement_id: int, output_path: str = None, preview: bool = False):
    """Generate a proposal for an engagement."""
    conn = get_db()
    engagement = get_engagement(conn, engagement_id)
    prop_num = generate_proposal_number(conn)

    # Load template
    if not TEMPLATE_PATH.exists():
        print(f"Error: Template not found at {TEMPLATE_PATH}", file=sys.stderr)
        sys.exit(1)

    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        template = f.read()

    # Fill template
    proposal = fill_template(template, engagement, prop_num)

    if preview:
        print(proposal)
        return

    # Determine output path
    if output_path:
        out = Path(output_path)
    else:
        org = (engagement["organization"] or engagement["client_name"]).replace(" ", "_")
        proposals_dir = BASE_DIR / "proposals"
        proposals_dir.mkdir(exist_ok=True)
        out = proposals_dir / f"{org}_Proposal.md"

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write(proposal)

    org = engagement["organization"] or engagement["client_name"]
    print(f"✅ Proposal generated: {out}")
    print(f"   #{engagement_id} — {org} — {engagement['type']} — ${engagement['value']:,.0f}")
    print(f"   Number: {prop_num}")

    conn.close()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HAKA Proposal Generator — Generate proposals from CRM data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 haka_proposal.py --engagement 1 --output proposals/CBE_Proposal.md
  python3 haka_proposal.py --engagement 1 --preview
  python3 haka_proposal.py --list
  python3 haka_proposal.py --list-engagements
        """,
    )
    parser.add_argument(
        "--engagement", "-e", type=int, help="CRM engagement ID to generate proposal for"
    )
    parser.add_argument(
        "--output", "-o", type=str, help="Output file path (default: proposals/<Client>_Proposal.md)"
    )
    parser.add_argument(
        "--preview", "-p", action="store_true", help="Print proposal to stdout without saving"
    )
    parser.add_argument(
        "--list", "-l", action="store_true", help="List all generated proposals in proposals/"
    )
    parser.add_argument(
        "--list-engagements", action="store_true", help="List all CRM engagements"
    )
    args = parser.parse_args()

    if args.list:
        proposals_dir = BASE_DIR / "proposals"
        list_proposals(proposals_dir)
    elif args.list_engagements:
        conn = get_db()
        list_engagements(conn)
        conn.close()
    elif args.engagement:
        generate_proposal(args.engagement, args.output, args.preview)
    else:
        parser.print_help()
        print("\nTip: Use --list-engagements to see available engagements in CRM.")


if __name__ == "__main__":
    main()
