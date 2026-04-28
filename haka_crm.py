#!/usr/bin/env python3
"""
HAKA CRM — Lightweight Client & Pipeline Tracker for security consulting.

Uses SQLite (stdlib) at ~/.haka/haka_crm.db — no external DB needed.

Usage:
  python3 haka_crm.py --add-client --name "Abebe Kebede" --org "CBE" --email "ak@cbe.com.et" --status prospect
  python3 haka_crm.py --list-clients
  python3 haka_crm.py --add-engagement --client 1 --type external_assessment --value 8000 --status proposed
  python3 haka_crm.py --list-engagements
  python3 haka_crm.py --pipeline
  python3 haka_crm.py --pipeline --export
  python3 haka_crm.py --update --client 1 --status active
  python3 haka_crm.py --update --engagement 1 --status signed
"""

import argparse
import os
import sqlite3
import sys
from datetime import datetime
from textwrap import dedent

DB_DIR = os.path.expanduser("~/.haka")
DB_PATH = os.path.join(DB_DIR, "haka_crm.db")

ENGAGEMENT_TYPES = [
    "external_assessment",
    "full_pentest",
    "quarterly_retainer",
    "ir_retainer",
]

CLIENT_STATUSES = ["prospect", "active", "inactive"]
ENGAGEMENT_STATUSES = ["proposed", "signed", "in_progress", "delivered", "paid"]


# ── Database ─────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Open (and create if needed) the CRM database."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection):
    """Create tables if they don't exist."""
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


# ── Client operations ────────────────────────────────────────────────────────

def add_client(args):
    """Add a new client/prospect."""
    conn = get_db()
    conn.execute(
        """INSERT INTO clients (name, organization, contact, email, phone, status, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (args.name, args.org, args.contact, args.email, args.phone, args.status, args.notes),
    )
    conn.commit()
    row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
    print(f"✅ Client added: [{row['id']}] {args.name} ({args.status})")
    conn.close()


def list_clients(_args):
    """List all clients with status."""
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, organization, status, email, created_at FROM clients ORDER BY id"
    ).fetchall()
    conn.close()

    if not rows:
        print("📭 No clients in database.")
        return

    print(f"\n{'ID':<4} {'Name':<25} {'Organization':<25} {'Status':<12} {'Email'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:<4} {r['name']:<25} {(r['organization'] or ''):<25} {r['status']:<12} {r['email'] or ''}")
    print(f"\n{len(rows)} client(s) total\n")


# ── Engagement operations ────────────────────────────────────────────────────

def add_engagement(args):
    """Create a new engagement for a client."""
    conn = get_db()

    # Validate client exists
    client = conn.execute("SELECT id, name FROM clients WHERE id = ?", (args.client,)).fetchone()
    if not client:
        print(f"❌ Client ID {args.client} not found. Use --list-clients to see clients.")
        conn.close()
        sys.exit(1)

    if args.eng_type not in ENGAGEMENT_TYPES:
        print(f"❌ Invalid type '{args.eng_type}'. Choose from: {', '.join(ENGAGEMENT_TYPES)}")
        conn.close()
        sys.exit(1)

    if args.status not in ENGAGEMENT_STATUSES:
        print(f"❌ Invalid status '{args.status}'. Choose from: {', '.join(ENGAGEMENT_STATUSES)}")
        conn.close()
        sys.exit(1)

    conn.execute(
        """INSERT INTO engagements (client_id, type, status, value, start_date)
           VALUES (?, ?, ?, ?, ?)""",
        (args.client, args.eng_type, args.status, args.value, args.start_date),
    )
    conn.commit()
    row = conn.execute("SELECT last_insert_rowid() AS id").fetchone()
    print(f"✅ Engagement added: [{row['id']}] {args.eng_type} for {client['name']} "
          f"(${args.value:,.2f} — {args.status})")
    conn.close()


def list_engagements(_args):
    """List all engagements with status and client info."""
    conn = get_db()
    rows = conn.execute(dedent("""
        SELECT e.id, e.type, e.status, e.value, e.start_date, c.name AS client_name
        FROM engagements e
        JOIN clients c ON e.client_id = c.id
        ORDER BY e.id
    """)).fetchall()
    conn.close()

    if not rows:
        print("📭 No engagements in database.")
        return

    print(f"\n{'ID':<4} {'Client':<22} {'Type':<25} {'Status':<14} {'Value':>10}  {'Start Date'}")
    print("-" * 100)
    for r in rows:
        print(f"{r['id']:<4} {r['client_name']:<22} {r['type']:<25} {r['status']:<14} "
              f"${r['value']:>9,.2f}  {r['start_date'] or '—'}")
    print(f"\n{len(rows)} engagement(s) total\n")


# ── Pipeline ─────────────────────────────────────────────────────────────────

def pipeline(args):
    """Show sales pipeline summary and optionally export to markdown."""
    conn = get_db()

    # Client stats
    clients = conn.execute("SELECT status, COUNT(*) AS cnt FROM clients GROUP BY status").fetchall()
    client_stats = {r["status"]: r["cnt"] for r in clients}

    # Engagement value by status
    engs = conn.execute(
        "SELECT status, COUNT(*) AS cnt, COALESCE(SUM(value), 0) AS total "
        "FROM engagements GROUP BY status"
    ).fetchall()
    eng_stats = {r["status"]: (r["cnt"], r["total"]) for r in engs}

    conn.close()

    total_prospects = client_stats.get("prospect", 0) + client_stats.get("active", 0)
    proposed = eng_stats.get("proposed", (0, 0))
    signed = eng_stats.get("signed", (0, 0))
    delivered = eng_stats.get("delivered", (0, 0))
    paid = eng_stats.get("paid", (0, 0))
    in_progress = eng_stats.get("in_progress", (0, 0))

    total_value = proposed[1] + signed[1] + in_progress[1] + delivered[1] + paid[1]

    if args.export:
        md = _pipeline_markdown(total_prospects, proposed, signed, in_progress, delivered, paid, total_value)
        print(md)
    else:
        _pipeline_terminal(total_prospects, proposed, signed, in_progress, delivered, paid, total_value)


def _pipeline_terminal(prospects, proposed, signed, in_progress, delivered, paid, total):
    """Print pipeline summary to terminal."""
    print("\n╔══════════════════════════════════════════════════╗")
    print("║           HAKA Security — Sales Pipeline         ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  Prospects (open):          {prospects:>8}              ║")
    print(f"║  Proposed:    {proposed[0]:>3} deals  ${proposed[1]:>12,.2f}  ║")
    print(f"║  Signed:      {signed[0]:>3} deals  ${signed[1]:>12,.2f}  ║")
    print(f"║  In Progress: {in_progress[0]:>3} deals  ${in_progress[1]:>12,.2f}  ║")
    print(f"║  Delivered:   {delivered[0]:>3} deals  ${delivered[1]:>12,.2f}  ║")
    print(f"║  Paid:        {paid[0]:>3} deals  ${paid[1]:>12,.2f}  ║")
    print("╠══════════════════════════════════════════════════╣")
    print(f"║  Pipeline Total:          ${total:>15,.2f}  ║")
    print("╚══════════════════════════════════════════════════╝\n")


def _pipeline_markdown(prospects, proposed, signed, in_progress, delivered, paid, total):
    """Generate pipeline markdown report."""
    return dedent(f"""\
    # HAKA Security — Sales Pipeline Report
    **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

    ## Summary

    | Stage       | Deals | Value       |
    |-------------|-------|-------------|
    | Prospects   | {prospects}     | —           |
    | Proposed    | {proposed[0]}     | ${proposed[1]:,.2f} |
    | Signed      | {signed[0]}     | ${signed[1]:,.2f} |
    | In Progress | {in_progress[0]}     | ${in_progress[1]:,.2f} |
    | Delivered   | {delivered[0]}     | ${delivered[1]:,.2f} |
    | **Paid**    | **{paid[0]}**     | **${paid[1]:,.2f}** |
    | **Pipeline Total** | | **${total:,.2f}** |

    ---
    *Generated by HAKA CRM*
    """)


# ── Update ───────────────────────────────────────────────────────────────────

def update(args):
    """Update client or engagement status."""
    conn = get_db()

    if args.client:
        if args.status not in CLIENT_STATUSES:
            print(f"❌ Invalid client status. Choose from: {', '.join(CLIENT_STATUSES)}")
            conn.close()
            sys.exit(1)
        conn.execute(
            "UPDATE clients SET status = ?, updated_at = datetime('now') WHERE id = ?",
            (args.status, args.client),
        )
        if conn.total_changes == 0:
            print(f"❌ Client ID {args.client} not found.")
        else:
            conn.commit()
            print(f"✅ Client {args.client} status → {args.status}")

    elif args.engagement:
        if args.status not in ENGAGEMENT_STATUSES:
            print(f"❌ Invalid engagement status. Choose from: {', '.join(ENGAGEMENT_STATUSES)}")
            conn.close()
            sys.exit(1)
        conn.execute(
            "UPDATE engagements SET status = ?, updated_at = datetime('now') WHERE id = ?",
            (args.status, args.engagement),
        )
        if conn.total_changes == 0:
            print(f"❌ Engagement ID {args.engagement} not found.")
        else:
            conn.commit()
            print(f"✅ Engagement {args.engagement} status → {args.status}")

    else:
        print("❌ Specify --client <id> or --engagement <id> to update.")

    conn.close()


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HAKA CRM — Client & Pipeline Tracker for security consulting engagements.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""\
            Examples:
              %(prog)s --add-client --name "Abebe Kebede" --org "CBE" --email "ak@cbe.com.et" --status prospect
              %(prog)s --list-clients
              %(prog)s --add-engagement --client 1 --type external_assessment --value 8000 --status proposed
              %(prog)s --list-engagements
              %(prog)s --pipeline
              %(prog)s --pipeline --export
              %(prog)s --update --client 1 --status active
              %(prog)s --update --engagement 1 --status signed
        """),
    )

    # Mutually exclusive operations
    op_group = parser.add_mutually_exclusive_group()
    op_group.add_argument("--add-client", action="store_true", help="Add a new client/prospect")
    op_group.add_argument("--list-clients", action="store_true", help="List all clients")
    op_group.add_argument("--add-engagement", action="store_true", help="Create a new engagement")
    op_group.add_argument("--list-engagements", action="store_true", help="List all engagements")
    op_group.add_argument("--pipeline", action="store_true", help="Show sales pipeline summary")
    op_group.add_argument("--update", action="store_true", help="Update client or engagement status")

    # Client fields
    parser.add_argument("--name", help="Client full name")
    parser.add_argument("--org", help="Organization / company name")
    parser.add_argument("--contact", help="Additional contact person")
    parser.add_argument("--email", help="Email address")
    parser.add_argument("--phone", help="Phone number")
    parser.add_argument("--status", default="prospect",
                        help=f"Status: {', '.join(CLIENT_STATUSES)} (default: prospect)")
    parser.add_argument("--notes", help="Additional notes")

    # Engagement fields
    parser.add_argument("--client", type=int, help="Client ID for engagement")
    parser.add_argument("--type", dest="eng_type",
                        help=f"Engagement type: {', '.join(ENGAGEMENT_TYPES)}")
    parser.add_argument("--value", type=float, default=0, help="Engagement value (USD)")
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD)")

    # Update fields
    parser.add_argument("--engagement", type=int, help="Engagement ID to update")

    # Export
    parser.add_argument("--export", action="store_true", help="Export pipeline as markdown")

    args = parser.parse_args()

    if args.add_client:
        if not args.name:
            parser.error("--name is required for --add-client")
        add_client(args)
    elif args.list_clients:
        list_clients(args)
    elif args.add_engagement:
        if not args.client:
            parser.error("--client <id> is required for --add-engagement")
        if not args.eng_type:
            parser.error("--type is required for --add-engagement")
        add_engagement(args)
    elif args.list_engagements:
        list_engagements(args)
    elif args.pipeline:
        pipeline(args)
    elif args.update:
        if not args.client and not args.engagement:
            parser.error("--update requires --client <id> or --engagement <id>")
        update(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
