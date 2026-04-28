#!/usr/bin/env python3
"""
HAKA AI Dashboard Server
Serves the dashboard and provides API endpoints that auto-detect
installed tools and read scan results from disk.
"""
import json
import os
import glob
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse

HAKA_DIR = Path(__file__).parent
SCANNERS_DIR = HAKA_DIR / "scanners"
DETECTORS_DIR = HAKA_DIR / "detectors"
REPORTS_DIR = HAKA_DIR / "reports"

TOOL_MAP = {
    "haka_email_scanner.py": {"num": "01", "name": "Email Security Scanner", "dir": "scanners"},
    "haka_dns_scanner.py": {"num": "02", "name": "DNS Recon Scanner", "dir": "scanners"},
    "haka_exchange_scanner.py": {"num": "03", "name": "Exchange & NTLM Scanner", "dir": "scanners"},
    "haka_spray_detector.py": {"num": "04", "name": "Password Spray Detector", "dir": "detectors"},
    "haka_kerberos_detector.py": {"num": "05", "name": "Kerberos Attack Detector", "dir": "detectors"},
    "haka_web_scanner.py": {"num": "06", "name": "Web Application Scanner", "dir": "scanners"},
    "haka_s3_scanner.py": {"num": "07", "name": "S3 Bucket Scanner", "dir": "scanners"},
    "haka_tls_scanner.py": {"num": "08", "name": "TLS/SSL Analyzer", "dir": "scanners"},
    "haka_ct_scanner.py": {"num": "09", "name": "CT OSINT Scanner", "dir": "scanners"},
    "haka_collab_scanner.py": {"num": "10", "name": "Collaboration Scanner", "dir": "scanners"},
    "haka_vpn_scanner.py": {"num": "11", "name": "VPN Gateway Scanner", "dir": "scanners"},
    "haka_wazuh_ai.py": {"num": "12", "name": "Wazuh Rule Generator", "dir": "detectors"},
    "haka_ai.py": {"num": "13", "name": "HAKA AI Unified Scanner (Master)", "dir": "scanners"},
}


def get_tool_status():
    """Check which tools are installed on disk."""
    tools = []
    for filename, info in TOOL_MAP.items():
        d = SCANNERS_DIR if info["dir"] == "scanners" else DETECTORS_DIR
        path = d / filename
        installed = path.exists()
        size = path.stat().st_size if installed else 0
        lines = sum(1 for _ in open(path)) if installed else 0
        tools.append({
            "num": info["num"],
            "name": info["name"],
            "file": filename,
            "installed": installed,
            "size": size,
            "lines": lines,
        })
    return tools


def get_scan_reports():
    """Read all JSON scan reports from the reports directory."""
    reports = []
    if not REPORTS_DIR.exists():
        return reports
    for f in sorted(REPORTS_DIR.glob("*.json"), key=os.path.getmtime, reverse=True)[:50]:
        try:
            data = json.loads(f.read_text())
            reports.append({
                "file": f.name,
                "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                "size": f.stat().st_size,
                "data": data,
            })
        except (json.JSONDecodeError, Exception):
            pass
    return reports


def get_aggregate_stats():
    """Aggregate severity counts across all reports."""
    reports = get_scan_reports()
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    all_findings = []
    targets_scanned = set()

    for r in reports:
        d = r["data"]
        # Handle different report formats: severity_counts, finding_counts, or compute from findings
        sc = d.get("severity_counts") or d.get("finding_counts") or {}
        has_counts = bool(sc)
        for sev in totals:
            totals[sev] += sc.get(sev, sc.get(sev.upper(), 0))

        findings = d.get("findings") or d.get("all_findings") or d.get("detections") or []
        all_findings.extend(findings)

        # If no severity_counts field, compute from individual findings
        if not has_counts:
            for f in findings:
                if not isinstance(f, dict):
                    continue
                sev = (f.get("severity") or f.get("risk") or "info").lower()
                if sev in totals:
                    totals[sev] += 1

        target = d.get("target", d.get("domain", d.get("host", "")))
        if target:
            targets_scanned.add(target)

    total_findings = sum(totals.values())
    risk = min(100, totals["critical"] * 15 + totals["high"] * 8 + totals["medium"] * 3 + totals["low"] * 1)

    return {
        "severity_counts": totals,
        "total_findings": total_findings,
        "risk_score": risk,
        "targets_scanned": list(targets_scanned),
        "report_count": len(reports),
    }


class DashboardHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html_path = HAKA_DIR / "dashboard.html"
            self.wfile.write(html_path.read_bytes())

        elif path == "/api/tools":
            self._json_response(get_tool_status())

        elif path == "/api/reports":
            self._json_response(get_scan_reports())

        elif path == "/api/stats":
            self._json_response(get_aggregate_stats())

        elif path == "/api/status":
            tools = get_tool_status()
            installed = sum(1 for t in tools if t["installed"])
            self._json_response({
                "online": True,
                "tools_installed": installed,
                "tools_total": len(tools),
                "reports_dir": str(REPORTS_DIR),
                "report_count": len(get_scan_reports()),
            })
        else:
            super().do_GET()

    def _json_response(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def log_message(self, fmt, *args):
        pass  # suppress log noise


def main():
    port = 7100
    os.chdir(str(HAKA_DIR))
    server = HTTPServer(("0.0.0.0", port), DashboardHandler)
    print(f"\n  HAKA AI Dashboard running at http://localhost:{port}")
    print(f"  Tools dir: {SCANNERS_DIR}")
    print(f"  Reports dir: {REPORTS_DIR}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
