#!/usr/bin/env python3
"""
HAKA Invoice Generator — Professional invoices for security consulting work.

Uses the same SQLite DB as haka_crm.py (~/.haka/haka_crm.db).
Outputs polished Markdown invoices suitable for email or PDF conversion.

Usage:
  python3 haka_invoice.py --client "CBE" --items "External Security Assessment:8000"
  python3 haka_invoice.py --engagement 1
  python3 haka_invoice.py --list
  python3 haka_invoice.py --paid HAKA-2026-001
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta
from textwrap import dedent

DB_DIR = os.path.expanduser("~/.haka")
DB_PATH = os.path.join(DB_DIR, "haka_crm.db")

TAX_RATE = 0.15  # 15% VAT (Ethiopia)

PAYMENT_INSTRUCTIONS = """\
**Bank:** Dashen Bank
**Account Name:** HAKA Security Consulting
**Account Number:** 0102789005413
**Reference:** Invoice number (required)"""


# ── Database ─────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Open (and create if needed) the CRM/invoice database."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection):
    """Ensure tables exist."""
    conn.executescript(dedent("""
        CREATE TABLE IF NOT EXISTS clients (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            organization TEXT,
            contact     TEXT,
            email       TEXT,
            phone       TEXT,
            status      TEXT DEFAULT 'prospect',
            notes       TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS engagements (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id   INTEGER NOT NULL REFERENCES clients(id),
            type        TEXT NOT NULL,
            status      TEXT DEFAULT 'proposed',
            value       REAL DEFAULT 0,
            start_date  TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            number      TEXT NOT NULL UNIQUE,
            client_id   INTEGER REFERENCES clients(id),
            engagement_id INTEGER REFERENCES engagements(id),
            client_name TEXT,
            items       TEXT,
            subtotal    REAL,
            tax         REAL,
            total       REAL,
            issue_date  TEXT,
            due_date    TEXT,
            status      TEXT DEFAULT 'unpaid',
            output_path TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );
    """))


def _next_invoice_number(conn: sqlite3.Connection) -> str:
    """Generate next invoice number: HAKA-YYYY-NNN."""
    year = datetime.now().strftime("%Y")
    row = conn.execute(
        "SELECT number FROM invoices WHERE number LIKE ? ORDER BY number DESC LIMIT 1",
        (f"HAKA-{year}-%",),
    ).fetchone()
    if row:
        seq = int(row["number"].split("-")[-1]) + 1
    else:
        seq = 1
    return f"HAKA-{year}-{seq:03d}"


# ── Invoice generation ───────────────────────────────────────────────────────

def generate(args):
    """Generate a professional invoice and save as markdown."""
    conn = get_db()

    # Resolve client info
    client_name = None
    client_id = None
    engagement_id = None
    eng_type = None
    eng_value = None

    # Try CRM engagement lookup
    if args.engagement:
        eng = conn.execute(dedent("""
            SELECT e.id, e.type, e.value, e.client_id, c.name AS client_name, c.organization, c.email, c.phone
            FROM engagements e
            JOIN clients c ON e.client_id = c.id
            WHERE e.id = ?
        """), (args.engagement,)).fetchone()
        if not eng:
            print(f"❌ Engagement ID {args.engagement} not found.")
            conn.close()
            sys.exit(1)
        engagement_id = eng["id"]
        client_id = eng["client_id"]
        client_name = eng["client_name"]
        eng_type = eng["type"]
        eng_value = eng["value"]

        # Auto-fill items from engagement if none provided
        if not args.items:
            type_label = eng_type.replace("_", " ").title()
            args.items = [f"{type_label}:{eng_value:.2f}"]

    elif args.client:
        # Try as client ID first, then as name search
        try:
            cid = int(args.client)
            client = conn.execute("SELECT id, name, organization, email, phone FROM clients WHERE id = ?", (cid,)).fetchone()
        except ValueError:
            client = conn.execute(
                "SELECT id, name, organization, email, phone FROM clients WHERE name LIKE ? OR organization LIKE ?",
                (f"%{args.client}%", f"%{args.client}%"),
            ).fetchone()

        if client:
            client_name = client["name"]
            client_id = client["id"]
        else:
            # Just use the raw string as client name
            client_name = args.client

    if not client_name:
        print("❌ Could not determine client. Provide --client or --engagement.")
        conn.close()
        sys.exit(1)

    # Invoice number
    invoice_number = args.number or _next_invoice_number(conn)

    # Dates
    issue_date = args.date or datetime.now().strftime("%Y-%m-%d")
    if args.due:
        due_date = args.due
    else:
        due_dt = datetime.strptime(issue_date, "%Y-%m-%d") + timedelta(days=30)
        due_date = due_dt.strftime("%Y-%m-%d")

    # Parse line items
    if not args.items:
        print("❌ No line items provided. Use --items 'Description:Amount'.")
        conn.close()
        sys.exit(1)

    items = []
    for item_str in args.items:
        if ":" in item_str:
            desc, amt = item_str.rsplit(":", 1)
            items.append((desc.strip(), float(amt.strip())))
        else:
            print(f"⚠ Skipping malformed item (use 'desc:amount'): {item_str}")

    if not items:
        print("❌ No valid line items.")
        conn.close()
        sys.exit(1)

    # Calculate totals
    subtotal = sum(amt for _, amt in items)
    tax = round(subtotal * TAX_RATE, 2)
    total = round(subtotal + tax, 2)

    # Build markdown
    md = _build_invoice_markdown(
        invoice_number=invoice_number,
        client_name=client_name,
        client_info=_get_client_info(conn, client_id),
        items=items,
        subtotal=subtotal,
        tax=tax,
        total=total,
        issue_date=issue_date,
        due_date=due_date,
        eng_type=eng_type,
        engagement_id=engagement_id,
    )

    # Save to file
    output_path = args.output or f"/tmp/{invoice_number}.md"
    with open(output_path, "w") as f:
        f.write(md)

    # Save to DB
    items_json = "; ".join(f"{d}:{a:.2f}" for d, a in items)
    conn.execute(
        """INSERT INTO invoices (number, client_id, engagement_id, client_name, items,
           subtotal, tax, total, issue_date, due_date, output_path)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (invoice_number, client_id, engagement_id, client_name, items_json,
         subtotal, tax, total, issue_date, due_date, output_path),
    )
    conn.commit()
    conn.close()

    print(f"✅ Invoice generated: {invoice_number}")
    print(f"   Client: {client_name}")
    print(f"   Amount: ${total:,.2f} (subtotal ${subtotal:,.2f} + ${tax:,.2f} VAT)")
    print(f"   Due:    {due_date}")
    print(f"   Saved:  {output_path}")
    print(f"\n─── Preview (first 30 lines) ───")
    for line in md.split("\n")[:30]:
        print(line)


def _get_client_info(conn, client_id):
    """Get formatted client info block."""
    if not client_id:
        return ""
    c = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not c:
        return ""
    lines = []
    if c["organization"]:
        lines.append(c["organization"])
    if c["email"]:
        lines.append(c["email"])
    if c["phone"]:
        lines.append(c["phone"])
    return "\n".join(lines)


def _build_invoice_markdown(invoice_number, client_name, client_info, items,
                            subtotal, tax, total, issue_date, due_date,
                            eng_type=None, engagement_id=None):
    """Build the full invoice markdown document."""
    lines = []

    # Calculate column widths
    max_desc = max(len(d) for d, _ in items)
    max_desc = max(max_desc, len("Description"))

    # Header
    lines.append(f"# HAKA Security — Invoice")
    lines.append("")
    lines.append(f"**Invoice #:** {invoice_number}")
    lines.append(f"**Date:** {issue_date}")
    lines.append(f"**Due Date:** {due_date}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Bill to
    lines.append("## Bill To")
    lines.append("")
    lines.append(f"**{client_name}**")
    if client_info:
        for line in client_info.split("\n"):
            if line.strip():
                lines.append(line)
    lines.append("")
    lines.append("---")
    lines.append("")

    # Engagement reference
    if eng_type or engagement_id:
        lines.append("## Engagement")
        lines.append("")
        if engagement_id:
            lines.append(f"- **Engagement ID:** #{engagement_id}")
        if eng_type:
            lines.append(f"- **Type:** {eng_type.replace('_', ' ').title()}")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Line items
    lines.append("## Services")
    lines.append("")
    lines.append(f"| Description | Amount |")
    lines.append(f"|-------------|--------|")
    for desc, amt in items:
        lines.append(f"| {desc} | ${amt:,.2f} |")
    lines.append("")

    # Totals
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| | |")
    lines.append(f"|---|---|")
    lines.append(f"| Subtotal | ${subtotal:,.2f} |")
    lines.append(f"| VAT (15%) | ${tax:,.2f} |")
    lines.append(f"| **Total Due** | **${total:,.2f}** |")
    lines.append("")

    # Payment instructions
    lines.append("---")
    lines.append("")
    lines.append("## Payment Instructions")
    lines.append("")
    for line in PAYMENT_INSTRUCTIONS.split("\n"):
        lines.append(line)
    lines.append("")
    lines.append("---")
    lines.append("")

    # Footer
    lines.append("*HAKA Security Consulting PLC — Protecting Ethiopia's Digital Infrastructure*")
    lines.append(f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*")
    lines.append("")

    return "\n".join(lines)


# ── List invoices ────────────────────────────────────────────────────────────

def list_invoices(_args):
    """List all generated invoices."""
    conn = get_db()
    rows = conn.execute(dedent("""
        SELECT number, client_name, total, issue_date, due_date, status, output_path
        FROM invoices ORDER BY created_at DESC
    """)).fetchall()
    conn.close()

    if not rows:
        print("📭 No invoices generated yet.")
        return

    print(f"\n{'Number':<16} {'Client':<22} {'Total':>10}  {'Status':<10} {'Due':<12} {'File'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['number']:<16} {(r['client_name'] or '—'):<22} "
              f"${r['total']:>9,.2f}  {r['status']:<10} "
              f"{(r['due_date'] or '—'):<12} {r['output_path'] or '—'}")
    print(f"\n{len(rows)} invoice(s) total\n")


# ── Mark paid ────────────────────────────────────────────────────────────────

def mark_paid(args):
    """Mark an invoice as paid."""
    conn = get_db()
    conn.execute("UPDATE invoices SET status = 'paid' WHERE number = ?", (args.paid,))
    if conn.total_changes == 0:
        print(f"❌ Invoice '{args.paid}' not found.")
    else:
        conn.commit()
        print(f"✅ Invoice {args.paid} marked as PAID.")
    conn.close()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HAKA Invoice Generator — Professional invoices for security consulting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""\
            Examples:
              %(prog)s --client "CBE" --items "External Security Assessment:8000" --items "Remediation Roadmap:2000"
              %(prog)s --engagement 1
              %(prog)s --list
              %(prog)s --paid HAKA-2026-001
        """),
    )

    # Mutually exclusive operations
    op_group = parser.add_mutually_exclusive_group()
    op_group.add_argument("--generate", action="store_true", help="Generate an invoice (default if --client/--engagement given)")
    op_group.add_argument("--list", action="store_true", help="List all generated invoices")
    op_group.add_argument("--paid", help="Mark invoice as paid (provide invoice number)")

    # Invoice fields
    parser.add_argument("--client", help="Client name or CRM client ID")
    parser.add_argument("--engagement", type=int, help="CRM engagement ID (auto-fills type + value)")
    parser.add_argument("--number", help="Invoice number (auto: HAKA-YYYY-NNN)")
    parser.add_argument("--items", action="append", help='Line item as "description:amount" (repeatable)')
    parser.add_argument("--date", help="Invoice date (default: today, YYYY-MM-DD)")
    parser.add_argument("--due", help="Due date (default: +30 days, YYYY-MM-DD)")
    parser.add_argument("--output", help="Output markdown file path")
    parser.add_argument("--bank", help="Override bank name for payment instructions")
    parser.add_argument("--account-name", help="Override account name")
    parser.add_argument("--account-number", help="Override account number")

    args = parser.parse_args()

    if args.paid:
        mark_paid(args)
    elif args.list:
        list_invoices(args)
    elif args.client or args.engagement or args.items:
        generate(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
