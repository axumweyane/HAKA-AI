#!/usr/bin/env python3
"""
HAKA AI - Tool 9: Certificate Transparency OSINT Scanner
=========================================================
Section E2 - CT OSINT (MITRE ATT&CK T1596.003)
Findings: CRIT-ET-01, CRIT-AWB-05, CRIT-CBE-05, CRIT-CBE-07, CRIT-TB-03

Queries crt.sh for certificate transparency logs, extracts subdomains,
maps infrastructure, detects naming patterns, identifies exposed internal
services, and provides real-time certificate monitoring via certstream.

Author : HAKA AI Framework
Version: 1.0.0
"""

import argparse
import csv
import json
import os
import re
import signal
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    # Stub out colorama if not installed
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = rf"""
{Fore.CYAN}
  _   _    _    _  __    _           ____ _____
 | | | |  / \  | |/ /   / \         / ___|_   _|
 | |_| | / _ \ | ' /   / _ \       | |     | |
 |  _  |/ ___ \| . \  / ___ \      | |___  | |
 |_| |_/_/   \_\_|\_\/_/   \_\      \____| |_|
{Fore.YELLOW}
  Certificate Transparency OSINT Scanner
  MITRE ATT&CK T1596.003 | HAKA AI Tool 9
{Style.RESET_ALL}"""

CRT_SH_URL = "https://crt.sh/"
REPORTS_DIR = "/home/kironix/HAKA-AI/reports"

# Infrastructure keyword categories for hostname classification
INFRA_KEYWORDS: Dict[str, List[str]] = {
    "internal_infra": [
        "jenkins", "gitlab", "git", "svn", "bitbucket", "sonar", "nexus",
        "artifactory", "jira", "confluence", "wiki", "intranet", "internal",
        "portal", "staff", "admin", "mgmt", "manage", "monitor", "nagios",
        "zabbix", "grafana", "kibana", "elastic", "prometheus", "ansible",
        "puppet", "chef", "terraform", "docker", "kube", "k8s", "rancher",
        "consul", "vault", "nomad",
    ],
    "mail_and_comms": [
        "mail", "smtp", "imap", "pop3", "exchange", "owa", "outlook",
        "webmail", "mx", "autodiscover", "mta", "relay", "postfix",
    ],
    "remote_access": [
        "vpn", "remote", "rdp", "citrix", "gateway", "gw", "proxy",
        "bastion", "jump", "sslvpn", "ras", "anyconnect", "f5", "bigip",
        "big-ip", "netscaler", "pulse", "forticlient", "globalprotect",
    ],
    "identity_and_directory": [
        "dc", "ad", "ldap", "sso", "adfs", "okta", "auth", "iam",
        "radius", "kerberos", "idp", "identity", "saml", "cas",
        "active-directory", "domain-controller",
    ],
    "security_infra": [
        "siem", "splunk", "qradar", "arcsight", "waf", "firewall",
        "fw", "ids", "ips", "edr", "av", "antivirus", "cyberark",
        "beyondtrust", "thycotic", "fortinet", "paloalto", "checkpoint",
        "crowdstrike", "sentinel", "defender", "carbonblack", "sophos",
        "nessus", "qualys", "rapid7", "tenable", "scanner",
    ],
    "financial_infra": [
        "swift", "payment", "pay", "core-banking", "corebanking",
        "banking", "finacle", "flexcube", "temenos", "t24", "fimi",
        "card", "atm", "pos", "ecommerce", "merchant", "clearing",
        "settlement", "treasury", "trade", "forex", "mobile-banking",
        "mobilebank", "internetbanking", "ibank", "ussd",
    ],
    "development": [
        "dev", "test", "qa", "uat", "sandbox", "staging", "stg",
        "preprod", "pre-prod", "beta", "alpha", "demo", "lab", "poc",
        "debug", "ci", "cd", "build", "release", "deploy",
    ],
    "database": [
        "db", "database", "sql", "mysql", "postgres", "oracle", "mongo",
        "redis", "memcache", "elastic", "cassandra", "mariadb", "mssql",
    ],
    "cloud_and_cdn": [
        "cdn", "cache", "cloudfront", "akamai", "cloudflare", "aws",
        "azure", "gcp", "s3", "blob", "bucket", "lambda", "api-gw",
    ],
    "web_services": [
        "api", "rest", "graphql", "soap", "ws", "service", "svc",
        "backend", "frontend", "app", "web", "www", "portal",
        "cms", "wordpress", "drupal", "joomla", "sharepoint",
    ],
}

# High-risk categories that get flagged as critical
HIGH_RISK_CATEGORIES = {
    "internal_infra", "security_infra", "financial_infra",
    "identity_and_directory", "remote_access", "database",
}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def timestamp_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_filename(domain: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", domain)


def build_session() -> requests.Session:
    """Build a requests session with retry / back-off."""
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "HAKA-AI-CT-Scanner/1.0 (Security Research)",
        "Accept": "application/json",
    })
    return session


def print_section(title: str) -> None:
    width = 70
    print(f"\n{Fore.CYAN}{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}{Style.RESET_ALL}")


def print_finding(severity: str, text: str) -> None:
    colors = {
        "CRITICAL": Fore.RED,
        "HIGH": Fore.YELLOW,
        "MEDIUM": Fore.MAGENTA,
        "LOW": Fore.BLUE,
        "INFO": Fore.GREEN,
    }
    color = colors.get(severity, Fore.WHITE)
    print(f"  {color}[{severity}]{Style.RESET_ALL} {text}")


# ---------------------------------------------------------------------------
# Core: crt.sh query
# ---------------------------------------------------------------------------

class CTScanner:
    """Certificate Transparency log scanner using crt.sh."""

    def __init__(self, domain: str, include_expired: bool = True,
                 wildcard: bool = True, verbose: bool = False):
        self.domain = domain.lower().strip().lstrip("*.")
        self.include_expired = include_expired
        self.wildcard = wildcard
        self.verbose = verbose
        self.session = build_session()

        # Result containers
        self.raw_certs: List[Dict[str, Any]] = []
        self.hostnames: Set[str] = set()
        self.categorized: Dict[str, Set[str]] = defaultdict(set)
        self.cas: Counter = Counter()
        self.cert_stats: Dict[str, Any] = {}
        self.naming_patterns: Dict[str, int] = Counter()
        self.findings: List[Dict[str, Any]] = []
        self.wildcards: Set[str] = set()
        self.expired: List[Dict[str, Any]] = []
        self.active: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # crt.sh queries
    # ------------------------------------------------------------------

    def query_crtsh(self) -> List[Dict[str, Any]]:
        """Query crt.sh JSON API for the target domain."""
        queries = [f"%.{self.domain}"] if self.wildcard else []
        queries.append(self.domain)

        all_results: List[Dict[str, Any]] = []
        seen_ids: Set[int] = set()

        for query in queries:
            params = {"q": query, "output": "json"}
            if not self.include_expired:
                params["exclude"] = "expired"

            if self.verbose:
                print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} Querying crt.sh for: {query}")

            try:
                resp = self.session.get(CRT_SH_URL, params=params, timeout=30)
                if resp.status_code == 200 and resp.text.strip():
                    data = resp.json()
                    for entry in data:
                        cid = entry.get("id")
                        if cid and cid not in seen_ids:
                            seen_ids.add(cid)
                            all_results.append(entry)
                elif resp.status_code == 429:
                    print(f"  {Fore.YELLOW}[!] Rate-limited by crt.sh, waiting 30s...{Style.RESET_ALL}")
                    time.sleep(30)
                    # Retry once
                    resp = self.session.get(CRT_SH_URL, params=params, timeout=30)
                    if resp.status_code == 200 and resp.text.strip():
                        data = resp.json()
                        for entry in data:
                            cid = entry.get("id")
                            if cid and cid not in seen_ids:
                                seen_ids.add(cid)
                                all_results.append(entry)
                else:
                    if self.verbose:
                        print(f"  {Fore.YELLOW}[!] crt.sh returned HTTP {resp.status_code}{Style.RESET_ALL}")
            except requests.exceptions.RequestException as exc:
                print(f"  {Fore.RED}[ERROR] crt.sh request failed: {exc}{Style.RESET_ALL}")

            # Be polite between queries
            if len(queries) > 1:
                time.sleep(2)

        self.raw_certs = all_results
        return all_results

    # ------------------------------------------------------------------
    # Hostname extraction and dedup
    # ------------------------------------------------------------------

    def extract_hostnames(self) -> Set[str]:
        """Extract and deduplicate all hostnames from certificate name fields."""
        for cert in self.raw_certs:
            name_value = cert.get("name_value", "")
            common_name = cert.get("common_name", "")

            # name_value can be newline-separated list of SANs
            for raw in name_value.split("\n"):
                raw = raw.strip().lower()
                if raw:
                    self._process_hostname(raw)

            if common_name:
                self._process_hostname(common_name.strip().lower())

        # Filter to only hostnames belonging to our target domain
        filtered: Set[str] = set()
        for h in self.hostnames:
            clean = h.lstrip("*.")
            if clean == self.domain or clean.endswith(f".{self.domain}"):
                filtered.add(h)

        self.hostnames = filtered
        return self.hostnames

    def _process_hostname(self, hostname: str) -> None:
        """Normalize and store a hostname."""
        hostname = hostname.strip().lower()
        # Remove leading wildcard prefix for the clean set but track wildcards
        if hostname.startswith("*."):
            self.wildcards.add(hostname)
            # Also add the base form
            self.hostnames.add(hostname[2:])
        if hostname:
            self.hostnames.add(hostname)

    # ------------------------------------------------------------------
    # Certificate analysis
    # ------------------------------------------------------------------

    def analyze_certificates(self) -> None:
        """Analyze certificates for expiry, CA usage, stats."""
        now = datetime.now(timezone.utc)

        for cert in self.raw_certs:
            # CA tracking
            issuer = cert.get("issuer_name", "Unknown")
            # Extract CN from issuer
            cn_match = re.search(r"CN=([^,]+)", issuer)
            ca_name = cn_match.group(1).strip() if cn_match else issuer
            self.cas[ca_name] += 1

            # Expiry analysis
            not_after = cert.get("not_after")
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry < now:
                        self.expired.append(cert)
                    else:
                        self.active.append(cert)
                except (ValueError, TypeError):
                    pass

        self.cert_stats = {
            "total_certificates": len(self.raw_certs),
            "unique_hostnames": len(self.hostnames),
            "wildcard_certificates": len(self.wildcards),
            "active_certificates": len(self.active),
            "expired_certificates": len(self.expired),
            "certificate_authorities": len(self.cas),
            "top_cas": dict(self.cas.most_common(10)),
        }

    # ------------------------------------------------------------------
    # Hostname categorization
    # ------------------------------------------------------------------

    def categorize_hostnames(self) -> Dict[str, Set[str]]:
        """Classify each hostname into infrastructure categories."""
        for hostname in sorted(self.hostnames):
            # Strip wildcard prefix for classification
            clean = hostname.lstrip("*.")
            # Get the subdomain part(s) relative to base domain
            if clean == self.domain:
                self.categorized["apex_domain"].add(hostname)
                continue

            subdomain_part = clean[: -(len(self.domain) + 1)]  # remove .domain.tld
            labels = re.split(r"[.\-_]", subdomain_part.lower())

            matched = False
            for category, keywords in INFRA_KEYWORDS.items():
                for kw in keywords:
                    if kw in labels or kw in subdomain_part:
                        self.categorized[category].add(hostname)
                        matched = True
                        break

            if not matched:
                self.categorized["uncategorized"].add(hostname)

        return self.categorized

    # ------------------------------------------------------------------
    # Naming pattern detection
    # ------------------------------------------------------------------

    def detect_naming_patterns(self) -> Dict[str, int]:
        """Detect naming conventions and numbering patterns."""
        patterns = {
            "numbered_hosts": r"[a-z]+-?\d+\.",           # host1, server-02
            "env_prefixed": r"^(dev|stg|uat|prd|prod|staging|test)\-",
            "dc_location": r"^(dc|az|us|eu|af|et)\d*\-",  # dc1-xxx, eu-west
            "f5_bigip": r"(bigip|f5|ltm|gtm|asm)\-?",
            "exchange_pattern": r"(exch|cas|hub|edge|owa|autodiscover)",
            "sequential_numbering": r"\d{2,}",
            "hyphenated_fqdn": r"[a-z]+-[a-z]+-[a-z]+",
            "version_in_name": r"v\d+",
        }

        for hostname in self.hostnames:
            clean = hostname.lstrip("*.")
            sub = clean[: -(len(self.domain) + 1)] if clean != self.domain else ""
            if not sub:
                continue
            for pat_name, pat_regex in patterns.items():
                if re.search(pat_regex, sub, re.IGNORECASE):
                    self.naming_patterns[pat_name] += 1

        return dict(self.naming_patterns)

    # ------------------------------------------------------------------
    # Security findings generation
    # ------------------------------------------------------------------

    def generate_findings(self) -> List[Dict[str, Any]]:
        """Produce actionable findings from the analysis."""
        for category in HIGH_RISK_CATEGORIES:
            hosts = self.categorized.get(category, set())
            if not hosts:
                continue

            severity = "CRITICAL" if category in (
                "financial_infra", "security_infra", "identity_and_directory"
            ) else "HIGH"

            finding = {
                "id": f"CT-{category.upper().replace('_', '-')}-{len(hosts):03d}",
                "severity": severity,
                "category": category,
                "title": f"Exposed {category.replace('_', ' ').title()} hostnames in CT logs",
                "description": (
                    f"{len(hosts)} hostname(s) classified as '{category}' were discovered "
                    f"in Certificate Transparency logs for {self.domain}. These reveal "
                    f"internal infrastructure naming to any observer."
                ),
                "hostnames": sorted(hosts),
                "recommendation": (
                    "Review whether these certificates need to be publicly logged. "
                    "Consider private CAs for internal infrastructure or use generic "
                    "naming that does not expose function or technology."
                ),
                "mitre_attack": "T1596.003",
            }
            self.findings.append(finding)

        # Wildcard abuse check
        if len(self.wildcards) > 3:
            self.findings.append({
                "id": "CT-WILDCARD-OVERUSE",
                "severity": "MEDIUM",
                "category": "wildcard_certificates",
                "title": "Excessive wildcard certificate usage",
                "description": (
                    f"{len(self.wildcards)} wildcard certificates detected. "
                    f"Overuse of wildcards increases the blast radius of key compromise."
                ),
                "hostnames": sorted(self.wildcards),
                "recommendation": (
                    "Minimize wildcard certificate usage. Use specific SANs where possible."
                ),
                "mitre_attack": "T1596.003",
            })

        # Multiple CA usage
        if len(self.cas) > 3:
            self.findings.append({
                "id": "CT-MULTI-CA",
                "severity": "LOW",
                "category": "certificate_management",
                "title": "Multiple Certificate Authorities in use",
                "description": (
                    f"{len(self.cas)} different CAs issue certificates for {self.domain}. "
                    f"This complicates certificate lifecycle management and CAA enforcement."
                ),
                "cas": dict(self.cas.most_common()),
                "recommendation": (
                    "Consolidate CA usage and enforce CAA DNS records to limit "
                    "which CAs can issue for your domains."
                ),
                "mitre_attack": "T1596.003",
            })

        return self.findings

    # ------------------------------------------------------------------
    # Full scan orchestration
    # ------------------------------------------------------------------

    def run_scan(self) -> Dict[str, Any]:
        """Execute the full CT scan pipeline."""
        print_section(f"Certificate Transparency Scan: {self.domain}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Started at {timestamp_now()}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Target domain: {self.domain}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Include expired: {self.include_expired}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Wildcard query: {self.wildcard}")

        # Step 1: Query crt.sh
        print_section("Phase 1: Querying crt.sh")
        certs = self.query_crtsh()
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Retrieved {len(certs)} certificate entries")

        if not certs:
            print(f"  {Fore.YELLOW}[!] No certificates found. Domain may have no CT-logged certs.{Style.RESET_ALL}")
            return self._build_report()

        # Step 2: Extract hostnames
        print_section("Phase 2: Extracting Hostnames")
        hostnames = self.extract_hostnames()
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Extracted {len(hostnames)} unique hostnames")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Wildcard certs: {len(self.wildcards)}")

        # Step 3: Analyze certificates
        print_section("Phase 3: Certificate Analysis")
        self.analyze_certificates()
        stats = self.cert_stats
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Active certificates : {stats['active_certificates']}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Expired certificates: {stats['expired_certificates']}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Certificate authorities: {stats['certificate_authorities']}")
        if self.cas:
            print(f"\n  {Fore.CYAN}Top Certificate Authorities:{Style.RESET_ALL}")
            for ca, count in self.cas.most_common(5):
                print(f"    {Fore.WHITE}{count:>5}x{Style.RESET_ALL}  {ca}")

        # Step 4: Categorize
        print_section("Phase 4: Hostname Categorization")
        self.categorize_hostnames()
        for cat, hosts in sorted(self.categorized.items(), key=lambda x: -len(x[1])):
            is_risky = cat in HIGH_RISK_CATEGORIES
            color = Fore.RED if is_risky else Fore.GREEN
            marker = "!!!" if is_risky else "   "
            print(f"  {color}{marker} {cat:<30}{Style.RESET_ALL} {len(hosts):>4} host(s)")
            if is_risky and self.verbose:
                for h in sorted(hosts)[:15]:
                    print(f"        {Fore.YELLOW}- {h}{Style.RESET_ALL}")
                if len(hosts) > 15:
                    print(f"        {Fore.YELLOW}  ... and {len(hosts)-15} more{Style.RESET_ALL}")

        # Step 5: Naming patterns
        print_section("Phase 5: Naming Pattern Analysis")
        pats = self.detect_naming_patterns()
        if pats:
            for pname, pcount in sorted(pats.items(), key=lambda x: -x[1]):
                print(f"  {Fore.MAGENTA}[P]{Style.RESET_ALL} {pname:<30} {pcount:>4} match(es)")
        else:
            print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} No significant naming patterns detected")

        # Step 6: Findings
        print_section("Phase 6: Security Findings")
        findings = self.generate_findings()
        if findings:
            for f in findings:
                print_finding(f["severity"], f["title"])
                if self.verbose:
                    print(f"        {Fore.WHITE}{f['description']}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} No critical findings generated")

        # Step 7: Full subdomain list
        print_section("Discovered Subdomains")
        for h in sorted(self.hostnames):
            prefix = f"{Fore.RED}*" if h.startswith("*.") else f"{Fore.GREEN} "
            print(f"  {prefix} {h}{Style.RESET_ALL}")

        return self._build_report()

    # ------------------------------------------------------------------
    # Report building
    # ------------------------------------------------------------------

    def _build_report(self) -> Dict[str, Any]:
        """Assemble the full JSON report."""
        # Convert sets to sorted lists for JSON serialization
        categorized_serializable = {
            k: sorted(v) for k, v in self.categorized.items()
        }

        report = {
            "tool": "HAKA AI - Certificate Transparency OSINT Scanner",
            "version": "1.0.0",
            "mitre_technique": "T1596.003",
            "scan_metadata": {
                "target_domain": self.domain,
                "scan_timestamp": timestamp_now(),
                "include_expired": self.include_expired,
                "wildcard_query": self.wildcard,
            },
            "statistics": self.cert_stats,
            "hostnames": {
                "total_unique": len(self.hostnames),
                "all_subdomains": sorted(self.hostnames),
                "wildcard_certificates": sorted(self.wildcards),
            },
            "categorization": categorized_serializable,
            "naming_patterns": dict(self.naming_patterns),
            "certificate_authorities": dict(self.cas.most_common()),
            "findings": self.findings,
            "finding_summary": {
                "total": len(self.findings),
                "critical": sum(1 for f in self.findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in self.findings if f["severity"] == "HIGH"),
                "medium": sum(1 for f in self.findings if f["severity"] == "MEDIUM"),
                "low": sum(1 for f in self.findings if f["severity"] == "LOW"),
            },
        }
        return report


# ---------------------------------------------------------------------------
# Real-time certificate monitoring (certstream)
# ---------------------------------------------------------------------------

class CTMonitor:
    """Real-time certificate monitoring using certstream websocket."""

    def __init__(self, domain: str, verbose: bool = False):
        self.domain = domain.lower().strip()
        self.verbose = verbose
        self.running = True
        self.match_count = 0
        self.matches: List[Dict[str, Any]] = []

    def _signal_handler(self, sig, frame):
        print(f"\n\n{Fore.YELLOW}[!] Interrupt received. Stopping monitor...{Style.RESET_ALL}")
        self.running = False

    def start(self) -> None:
        """Start real-time certificate monitoring."""
        try:
            import certstream
        except ImportError:
            print(f"{Fore.RED}[ERROR] certstream library not installed.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  Install with: pip install certstream{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}  Falling back to polling mode...{Style.RESET_ALL}")
            self._polling_fallback()
            return

        signal.signal(signal.SIGINT, self._signal_handler)
        print_section(f"Real-Time CT Monitor: {self.domain}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Listening for new certificates...")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Press Ctrl+C to stop\n")

        def callback(message, context):
            if not self.running:
                raise KeyboardInterrupt

            if message["message_type"] == "certificate_update":
                all_domains = message["data"]["leaf_cert"].get("all_domains", [])
                for d in all_domains:
                    d_lower = d.lower().lstrip("*.")
                    if d_lower == self.domain or d_lower.endswith(f".{self.domain}"):
                        self.match_count += 1
                        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                        issuer = message["data"]["leaf_cert"].get("issuer", {})
                        ca_org = issuer.get("O", "Unknown CA")
                        san_list = ", ".join(all_domains[:5])
                        if len(all_domains) > 5:
                            san_list += f" (+{len(all_domains)-5} more)"

                        print(
                            f"  {Fore.RED}[ALERT #{self.match_count}]{Style.RESET_ALL} "
                            f"{ts} | New cert for {Fore.YELLOW}{d}{Style.RESET_ALL}"
                        )
                        print(f"           CA: {ca_org}")
                        print(f"           SANs: {san_list}\n")

                        self.matches.append({
                            "timestamp": timestamp_now(),
                            "domain_matched": d,
                            "all_domains": all_domains,
                            "issuer": dict(issuer),
                        })

        def on_error(instance, exception):
            if self.verbose:
                print(f"  {Fore.YELLOW}[!] Certstream error: {exception}{Style.RESET_ALL}")

        try:
            certstream.listen_for_events(callback, on_error=on_error, url="wss://certstream.calidog.io/")
        except KeyboardInterrupt:
            pass

        self._save_monitor_results()

    def _polling_fallback(self) -> None:
        """Fallback: poll crt.sh periodically for new certificates."""
        signal.signal(signal.SIGINT, self._signal_handler)
        print_section(f"CT Polling Monitor (fallback): {self.domain}")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Polling crt.sh every 60 seconds")
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Press Ctrl+C to stop\n")

        session = build_session()
        known_ids: Set[int] = set()

        # Initial seed
        try:
            resp = session.get(CRT_SH_URL, params={"q": f"%.{self.domain}", "output": "json"}, timeout=30)
            if resp.status_code == 200 and resp.text.strip():
                for entry in resp.json():
                    known_ids.add(entry.get("id", 0))
                print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} Baseline: {len(known_ids)} known certificates")
        except Exception as exc:
            print(f"  {Fore.YELLOW}[!] Baseline fetch failed: {exc}{Style.RESET_ALL}")

        while self.running:
            try:
                time.sleep(60)
                if not self.running:
                    break
                resp = session.get(
                    CRT_SH_URL,
                    params={"q": f"%.{self.domain}", "output": "json"},
                    timeout=30,
                )
                if resp.status_code == 200 and resp.text.strip():
                    for entry in resp.json():
                        cid = entry.get("id", 0)
                        if cid and cid not in known_ids:
                            known_ids.add(cid)
                            self.match_count += 1
                            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                            name = entry.get("name_value", "")
                            cn = entry.get("common_name", "")
                            issuer = entry.get("issuer_name", "Unknown")

                            print(
                                f"  {Fore.RED}[NEW CERT #{self.match_count}]{Style.RESET_ALL} "
                                f"{ts} | CN={cn}"
                            )
                            print(f"           SANs: {name[:120]}")
                            print(f"           Issuer: {issuer[:80]}\n")

                            self.matches.append({
                                "timestamp": timestamp_now(),
                                "id": cid,
                                "common_name": cn,
                                "name_value": name,
                                "issuer": issuer,
                            })
            except KeyboardInterrupt:
                break
            except Exception as exc:
                if self.verbose:
                    print(f"  {Fore.YELLOW}[!] Poll error: {exc}{Style.RESET_ALL}")

        self._save_monitor_results()

    def _save_monitor_results(self) -> None:
        """Save monitoring session results."""
        if not self.matches:
            print(f"\n  {Fore.BLUE}[*]{Style.RESET_ALL} No new certificates detected during session")
            return

        report = {
            "tool": "HAKA AI - CT Monitor",
            "domain": self.domain,
            "session_end": timestamp_now(),
            "total_alerts": self.match_count,
            "matches": self.matches,
        }
        os.makedirs(REPORTS_DIR, exist_ok=True)
        fname = f"ct_monitor_{safe_filename(self.domain)}_{int(time.time())}.json"
        path = os.path.join(REPORTS_DIR, fname)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\n  {Fore.GREEN}[+]{Style.RESET_ALL} Monitor report saved: {path}")


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------

def save_json_report(report: Dict[str, Any], domain: str) -> str:
    """Save JSON report to reports directory."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    fname = f"ct_scan_{safe_filename(domain)}_{int(time.time())}.json"
    path = os.path.join(REPORTS_DIR, fname)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    return path


def export_csv(report: Dict[str, Any], output_path: str) -> str:
    """Export subdomain list to CSV with categorization."""
    # Build hostname -> categories mapping
    cat_map: Dict[str, List[str]] = defaultdict(list)
    for category, hosts in report.get("categorization", {}).items():
        for h in hosts:
            cat_map[h].append(category)

    all_hosts = sorted(report.get("hostnames", {}).get("all_subdomains", []))
    is_wildcard = set(report.get("hostnames", {}).get("wildcard_certificates", []))

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "hostname", "is_wildcard", "categories", "high_risk",
        ])
        for h in all_hosts:
            cats = cat_map.get(h, ["uncategorized"])
            risky = any(c in HIGH_RISK_CATEGORIES for c in cats)
            writer.writerow([
                h,
                h in is_wildcard or h.startswith("*."),
                "; ".join(cats),
                risky,
            ])

    return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HAKA AI - Certificate Transparency OSINT Scanner (T1596.003)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --domain ethiotelecom.et
  %(prog)s --domain awashbank.com --export subdomains.csv
  %(prog)s --domain combanketh.et --monitor
  %(prog)s --domain example.com --no-expired --verbose
        """,
    )
    parser.add_argument(
        "--domain", "-d", required=True,
        help="Target domain to scan (e.g., example.com)",
    )
    parser.add_argument(
        "--export", "-e", metavar="FILE",
        help="Export subdomain list to CSV file",
    )
    parser.add_argument(
        "--monitor", "-m", action="store_true",
        help="Enable real-time certificate monitoring mode",
    )
    parser.add_argument(
        "--no-expired", action="store_true",
        help="Exclude expired certificates from results",
    )
    parser.add_argument(
        "--no-wildcard", action="store_true",
        help="Disable wildcard query (skip %%.domain.com)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output with extra detail",
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Suppress console output, only save JSON report",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print(BANNER)

    # Monitor mode
    if args.monitor:
        monitor = CTMonitor(args.domain, verbose=args.verbose)
        monitor.start()
        return

    # Standard scan mode
    scanner = CTScanner(
        domain=args.domain,
        include_expired=not args.no_expired,
        wildcard=not args.no_wildcard,
        verbose=args.verbose,
    )

    report = scanner.run_scan()

    # Save JSON report
    json_path = save_json_report(report, args.domain)
    print_section("Report Output")
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} JSON report: {json_path}")

    # CSV export
    if args.export:
        csv_path = export_csv(report, args.export)
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} CSV export : {csv_path}")

    # Summary
    print_section("Scan Summary")
    stats = report.get("statistics", {})
    fsum = report.get("finding_summary", {})
    print(f"  Total certificates   : {stats.get('total_certificates', 0)}")
    print(f"  Unique subdomains    : {stats.get('unique_hostnames', 0)}")
    print(f"  Wildcard certs       : {stats.get('wildcard_certificates', 0)}")
    print(f"  Active / Expired     : {stats.get('active_certificates', 0)} / {stats.get('expired_certificates', 0)}")
    print(f"  Certificate Authorities: {stats.get('certificate_authorities', 0)}")
    print(f"  Findings             : {fsum.get('total', 0)} "
          f"({Fore.RED}{fsum.get('critical', 0)} CRIT{Style.RESET_ALL}, "
          f"{Fore.YELLOW}{fsum.get('high', 0)} HIGH{Style.RESET_ALL}, "
          f"{Fore.MAGENTA}{fsum.get('medium', 0)} MED{Style.RESET_ALL}, "
          f"{Fore.BLUE}{fsum.get('low', 0)} LOW{Style.RESET_ALL})")
    print(f"\n  {Fore.GREEN}Scan completed at {timestamp_now()}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
