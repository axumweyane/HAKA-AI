#!/usr/bin/env python3
"""
HAKA AI - Tool 2: DNS Reconnaissance Scanner
Section A2 - DNS Recon (MITRE ATT&CK T1590.002)

Comprehensive DNS enumeration and security assessment tool.
Performs record enumeration, DNSSEC validation, zone transfer attempts,
reverse DNS sweeps, subdomain brute forcing, and risk scoring.

Author : HAKA AI Framework
Version: 1.0.0
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import random
import socket
import string
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import dns.exception
    import dns.flags
    import dns.name
    import dns.query
    import dns.rdatatype
    import dns.resolver
    import dns.reversename
    import dns.zone
except ImportError:
    print("[!] dnspython is required: pip install dnspython")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[!] colorama is required: pip install colorama")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = rf"""
{Fore.CYAN}{Style.BRIGHT}
  _   _    _    _  __    _        ____  _   _ ____
 | | | |  / \  | |/ /   / \      |  _ \| \ | / ___|
 | |_| | / _ \ | ' /   / _ \     | | | |  \| \___ \
 |  _  |/ ___ \| . \  / ___ \    | |_| | |\  |___) |
 |_| |_/_/   \_\_|\_\/_/   \_\   |____/|_| \_|____/
{Style.RESET_ALL}
{Fore.WHITE}  HAKA AI - DNS Reconnaissance Scanner v1.0.0{Style.RESET_ALL}
{Fore.WHITE}  Section A2 - DNS Recon (T1590.002){Style.RESET_ALL}
"""

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR"]

DNSSEC_TYPES = ["DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3"]

DEFAULT_TIMEOUT = 5.0

REPORTS_DIR = "/home/kironix/HAKA-AI/reports"

# Built-in wordlist: 200 common subdomains
BUILTIN_SUBDOMAINS = [
    "admin", "administrator", "api", "api-docs", "api-gateway", "api-v2",
    "app", "apps", "archive", "assets", "auth", "autodiscover", "autoconfig",
    "backup", "beta", "billing", "blog", "board", "build", "cache",
    "calendar", "cdn", "cdn1", "cdn2", "chat", "ci", "client", "cloud",
    "cluster", "cms", "code", "confluence", "connect", "console", "contact",
    "control", "cpanel", "crm", "cron", "dashboard", "data", "database",
    "db", "db1", "db2", "demo", "deploy", "dev", "dev1", "dev2",
    "developer", "devops", "directory", "dl", "dns", "dns1", "dns2",
    "docs", "download", "edge", "elastic", "elasticsearch", "email",
    "erp", "exchange", "extern", "external", "extranet", "fileserver",
    "firewall", "forum", "ftp", "ftp2", "gateway", "git", "github",
    "gitlab", "grafana", "graphql", "graylog", "help", "helpdesk",
    "home", "host", "hosting", "hr", "hub", "iam", "id", "imap",
    "img", "img1", "img2", "info", "internal", "intranet", "inventory",
    "irc", "it", "jenkins", "jira", "kafka", "kb", "kerberos", "kibana",
    "kubernetes", "lab", "landing", "ldap", "legacy", "library", "linux",
    "lists", "live", "load", "log", "login", "logs", "m", "mail",
    "mail2", "mailgw", "manage", "management", "manager", "map", "media",
    "meet", "mobile", "monitor", "monitoring", "mssql", "mx", "mx1",
    "mx2", "mysql", "nagios", "nas", "netscaler", "newrelic", "news",
    "nexus", "noc", "node", "ns", "ns1", "ns2", "ns3", "ntp", "office",
    "ops", "oracle", "origin", "owa", "pam", "panel", "payments",
    "pbx", "phpmyadmin", "platform", "pop", "pop3", "portal", "postgres",
    "print", "prod", "production", "prometheus", "proxy", "qa", "queue",
    "radius", "rdp", "redis", "relay", "remote", "repo", "report",
    "reports", "rest", "router", "rss", "s3", "sandbox", "search",
    "secure", "security", "server", "service", "sftp", "share", "shop",
    "siem", "signin", "signup", "site", "smtp", "smtp2", "sonar",
    "splunk", "sql", "sso", "staff", "stage", "staging", "static",
    "stats", "status", "storage", "store", "support", "svn", "syslog",
    "teams", "terminal", "test", "test1", "test2", "testing", "ticket",
    "time", "tools", "tracker", "ts", "updates", "upload", "vault",
    "video", "voip", "vpn", "vpn2", "vps", "waf", "web", "web1",
    "web2", "webdisk", "webmail", "webmin", "webproxy", "wiki", "win",
    "wireless", "wordpress", "work", "www", "www1", "www2", "zabbix",
]

# Risk severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: Fore.RED + Style.BRIGHT,
    SEVERITY_HIGH: Fore.RED,
    SEVERITY_MEDIUM: Fore.YELLOW,
    SEVERITY_LOW: Fore.BLUE,
    SEVERITY_INFO: Fore.CYAN,
}

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log_info(msg: str) -> None:
    print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")

def log_success(msg: str) -> None:
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def log_warning(msg: str) -> None:
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def log_error(msg: str) -> None:
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def log_finding(severity: str, msg: str) -> None:
    color = SEVERITY_COLORS.get(severity, "")
    tag = f"[{severity}]"
    print(f"  {color}{tag:12s}{Style.RESET_ALL} {msg}")

def section_header(title: str) -> None:
    width = 60
    print()
    print(f"{Fore.WHITE}{Style.BRIGHT}{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}{Style.RESET_ALL}")

# ---------------------------------------------------------------------------
# DNS Scanner class
# ---------------------------------------------------------------------------

class HAKADnsScanner:
    """Comprehensive DNS reconnaissance scanner."""

    def __init__(
        self,
        domain: str,
        dns_server: Optional[str] = None,
        wordlist_path: Optional[str] = None,
        delay: float = 0.0,
        timeout: float = DEFAULT_TIMEOUT,
        workers: int = 20,
        no_brute: bool = False,
        quiet: bool = False,
    ):
        self.domain = domain.rstrip(".")
        self.dns_server = dns_server
        self.delay = delay
        self.timeout = timeout
        self.workers = workers
        self.no_brute = no_brute
        self.quiet = quiet

        # Build resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout * 2
        if self.dns_server:
            self.resolver.nameservers = [self.dns_server]

        # Load wordlist
        self.subdomains_wordlist = self._load_wordlist(wordlist_path)

        # Result containers
        self.records: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.nameservers: List[str] = []
        self.discovered_ips: Set[str] = set()
        self.discovered_subdomains: Dict[str, List[str]] = {}
        self.zone_transfer_results: Dict[str, Any] = {}
        self.dnssec_status: Dict[str, Any] = {}
        self.reverse_dns: Dict[str, Optional[str]] = {}
        self.wildcard_detected: bool = False
        self.wildcard_ips: Set[str] = set()
        self.soa_validation: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.risk_score: int = 0
        self.scan_start: Optional[datetime] = None
        self.scan_end: Optional[datetime] = None

    # ------------------------------------------------------------------
    # Wordlist
    # ------------------------------------------------------------------

    def _load_wordlist(self, path: Optional[str]) -> List[str]:
        if path:
            try:
                with open(path, "r") as fh:
                    words = [
                        line.strip()
                        for line in fh
                        if line.strip() and not line.startswith("#")
                    ]
                log_info(f"Loaded {len(words)} entries from custom wordlist: {path}")
                return words
            except FileNotFoundError:
                log_error(f"Wordlist not found: {path} -- falling back to built-in")
            except PermissionError:
                log_error(f"Cannot read wordlist: {path} -- falling back to built-in")
        return list(BUILTIN_SUBDOMAINS)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def _query(
        self, qname: str, rdtype: str, raise_on_fail: bool = False
    ) -> Optional[dns.resolver.Answer]:
        """Execute a DNS query with error handling."""
        try:
            answer = self.resolver.resolve(qname, rdtype)
            return answer
        except dns.resolver.NoAnswer:
            return None
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.NoNameservers:
            return None
        except dns.exception.Timeout:
            if raise_on_fail:
                raise
            return None
        except dns.resolver.NoMetaqueries:
            return None
        except Exception:
            if raise_on_fail:
                raise
            return None

    def _sleep(self) -> None:
        if self.delay > 0:
            time.sleep(self.delay)

    # ------------------------------------------------------------------
    # Phase 1: Record enumeration
    # ------------------------------------------------------------------

    def enumerate_records(self) -> None:
        section_header("Phase 1: DNS Record Enumeration")
        for rtype in RECORD_TYPES:
            self._sleep()
            answer = self._query(self.domain, rtype)
            if answer:
                for rdata in answer:
                    entry = {
                        "type": rtype,
                        "value": str(rdata),
                        "ttl": answer.rrset.ttl,
                    }
                    self.records[rtype].append(entry)

                    # Harvest IPs
                    if rtype == "A":
                        self.discovered_ips.add(str(rdata))
                    elif rtype == "AAAA":
                        self.discovered_ips.add(str(rdata))
                    elif rtype == "MX":
                        mx_host = str(rdata.exchange).rstrip(".")
                        entry["priority"] = rdata.preference
                        entry["exchange"] = mx_host
                        # resolve MX to IP
                        mx_a = self._query(mx_host, "A")
                        if mx_a:
                            for r in mx_a:
                                self.discovered_ips.add(str(r))
                    elif rtype == "NS":
                        ns_host = str(rdata).rstrip(".")
                        self.nameservers.append(ns_host)

                count = len(self.records[rtype])
                log_success(f"{rtype:6s} -> {count} record(s) found")
                for entry in self.records[rtype]:
                    detail = entry["value"]
                    if rtype == "MX":
                        detail = f"[pri {entry.get('priority', '?')}] {entry.get('exchange', entry['value'])}"
                    print(f"         {Fore.WHITE}{detail}{Style.RESET_ALL}  (TTL {entry['ttl']})")
            else:
                log_info(f"{rtype:6s} -> no records")

        # Also resolve NS to IPs
        for ns in self.nameservers:
            ns_a = self._query(ns, "A")
            if ns_a:
                for r in ns_a:
                    self.discovered_ips.add(str(r))

        log_info(f"Total unique IPs discovered so far: {len(self.discovered_ips)}")

    # ------------------------------------------------------------------
    # Phase 2: DNSSEC validation
    # ------------------------------------------------------------------

    def check_dnssec(self) -> None:
        section_header("Phase 2: DNSSEC Validation")
        self.dnssec_status = {
            "enabled": False,
            "dnskey_present": False,
            "ds_present": False,
            "rrsig_present": False,
            "details": [],
        }

        for rtype in DNSSEC_TYPES:
            self._sleep()
            answer = self._query(self.domain, rtype)
            if answer:
                self.dnssec_status["details"].append(
                    {"type": rtype, "count": len(list(answer)), "records": [str(r) for r in answer]}
                )
                log_success(f"{rtype:8s} -> {len(list(answer))} record(s)")
                if rtype == "DNSKEY":
                    self.dnssec_status["dnskey_present"] = True
                elif rtype == "DS":
                    self.dnssec_status["ds_present"] = True
                elif rtype == "RRSIG":
                    self.dnssec_status["rrsig_present"] = True
            else:
                log_info(f"{rtype:8s} -> not found")

        # DNSSEC is considered enabled if DNSKEY or DS records exist
        if self.dnssec_status["dnskey_present"] or self.dnssec_status["ds_present"]:
            self.dnssec_status["enabled"] = True
            log_success(f"DNSSEC is {Fore.GREEN}ENABLED{Style.RESET_ALL} for {self.domain}")
        else:
            self.dnssec_status["enabled"] = False
            log_warning(f"DNSSEC is {Fore.RED}NOT ENABLED{Style.RESET_ALL} for {self.domain}")
            self.findings.append({
                "severity": SEVERITY_HIGH,
                "id": "DNS-001",
                "title": "DNSSEC Not Enabled",
                "description": (
                    f"Domain {self.domain} does not have DNSSEC enabled. "
                    "This leaves DNS responses vulnerable to spoofing and "
                    "cache poisoning attacks."
                ),
                "reference": "CRIT-TB-04, CRIT-CBE-06",
                "mitre": "T1590.002",
            })
            log_finding(SEVERITY_HIGH, "DNSSEC not enabled - vulnerable to DNS spoofing (CRIT-TB-04, CRIT-CBE-06)")

    # ------------------------------------------------------------------
    # Phase 3: Zone transfer
    # ------------------------------------------------------------------

    def attempt_zone_transfers(self) -> None:
        section_header("Phase 3: Zone Transfer (AXFR) Attempts")

        if not self.nameservers:
            log_warning("No nameservers discovered; skipping zone transfer tests")
            return

        for ns in self.nameservers:
            self._sleep()
            log_info(f"Attempting AXFR against {ns}...")

            # Resolve NS to IP
            ns_ip = None
            try:
                ns_a = self._query(ns, "A")
                if ns_a:
                    ns_ip = str(list(ns_a)[0])
                else:
                    # Try socket fallback
                    ns_ip = socket.gethostbyname(ns)
            except Exception:
                log_error(f"  Cannot resolve nameserver {ns}")
                self.zone_transfer_results[ns] = {"status": "unresolvable"}
                continue

            try:
                z = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, self.domain, timeout=self.timeout)
                )
                names = z.nodes.keys()
                records_found = []
                for name in sorted(names):
                    node = z.get_node(name)
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records_found.append({
                                "name": str(name),
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "value": str(rdata),
                                "ttl": rdataset.ttl,
                            })
                            # Harvest IPs from zone transfer
                            if rdataset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                                self.discovered_ips.add(str(rdata))
                            # Harvest subdomains
                            sub = str(name)
                            if sub != "@":
                                fqdn = f"{sub}.{self.domain}"
                                if fqdn not in self.discovered_subdomains:
                                    self.discovered_subdomains[fqdn] = []
                                self.discovered_subdomains[fqdn].append(str(rdata))

                self.zone_transfer_results[ns] = {
                    "status": "success",
                    "ip": ns_ip,
                    "records_count": len(records_found),
                    "records": records_found,
                }
                log_success(
                    f"  {Fore.RED}{Style.BRIGHT}ZONE TRANSFER SUCCESSFUL!{Style.RESET_ALL} "
                    f"from {ns} ({ns_ip}) -- {len(records_found)} records"
                )
                self.findings.append({
                    "severity": SEVERITY_CRITICAL,
                    "id": "DNS-002",
                    "title": "Zone Transfer Allowed",
                    "description": (
                        f"Nameserver {ns} ({ns_ip}) allows zone transfer (AXFR). "
                        f"Leaked {len(records_found)} records. An attacker can "
                        "enumerate all DNS records for the domain."
                    ),
                    "nameserver": ns,
                    "mitre": "T1590.002",
                })
                log_finding(SEVERITY_CRITICAL, f"Zone transfer allowed on {ns} ({ns_ip})")

            except dns.exception.FormError:
                self.zone_transfer_results[ns] = {"status": "refused", "ip": ns_ip}
                log_info(f"  Refused by {ns} ({ns_ip})")
            except dns.exception.Timeout:
                self.zone_transfer_results[ns] = {"status": "timeout", "ip": ns_ip}
                log_info(f"  Timeout against {ns} ({ns_ip})")
            except ConnectionRefusedError:
                self.zone_transfer_results[ns] = {"status": "connection_refused", "ip": ns_ip}
                log_info(f"  Connection refused by {ns} ({ns_ip})")
            except OSError as e:
                self.zone_transfer_results[ns] = {"status": "error", "ip": ns_ip, "error": str(e)}
                log_info(f"  Error: {e}")
            except Exception as e:
                self.zone_transfer_results[ns] = {"status": "error", "ip": ns_ip, "error": str(e)}
                log_info(f"  Error: {e}")

    # ------------------------------------------------------------------
    # Phase 4: Wildcard detection
    # ------------------------------------------------------------------

    def detect_wildcard(self) -> None:
        section_header("Phase 4: Wildcard DNS Detection")

        # Generate random subdomain unlikely to exist
        random_sub = "".join(random.choices(string.ascii_lowercase + string.digits, k=24))
        test_fqdn = f"{random_sub}.{self.domain}"
        log_info(f"Testing random subdomain: {test_fqdn}")

        answer = self._query(test_fqdn, "A")
        if answer:
            self.wildcard_detected = True
            for rdata in answer:
                self.wildcard_ips.add(str(rdata))
            log_warning(
                f"Wildcard DNS detected! Random subdomain resolves to: "
                f"{', '.join(self.wildcard_ips)}"
            )
            self.findings.append({
                "severity": SEVERITY_MEDIUM,
                "id": "DNS-003",
                "title": "Wildcard DNS Enabled",
                "description": (
                    f"Domain {self.domain} has wildcard DNS enabled. "
                    f"Non-existent subdomains resolve to {', '.join(self.wildcard_ips)}. "
                    "This can interfere with subdomain enumeration accuracy and "
                    "may expose internal services."
                ),
                "wildcard_ips": list(self.wildcard_ips),
                "mitre": "T1590.002",
            })
            log_finding(SEVERITY_MEDIUM, "Wildcard DNS enabled")
        else:
            self.wildcard_detected = False
            log_success("No wildcard DNS detected")

    # ------------------------------------------------------------------
    # Phase 5: SOA validation
    # ------------------------------------------------------------------

    def validate_soa(self) -> None:
        section_header("Phase 5: SOA Record Validation")

        soa_answer = self._query(self.domain, "SOA")
        if not soa_answer:
            log_warning("No SOA record found")
            self.soa_validation = {"found": False}
            return

        soa = list(soa_answer)[0]
        primary_ns = str(soa.mname).rstrip(".")
        responsible = str(soa.rname).rstrip(".")
        serial = soa.serial
        refresh = soa.refresh
        retry = soa.retry
        expire = soa.expire
        minimum = soa.minimum

        self.soa_validation = {
            "found": True,
            "primary_ns": primary_ns,
            "responsible_party": responsible,
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum_ttl": minimum,
            "primary_ns_valid": False,
        }

        log_info(f"Primary NS : {primary_ns}")
        log_info(f"Responsible: {responsible}")
        log_info(f"Serial     : {serial}")
        log_info(f"Refresh    : {refresh}s / Retry: {retry}s / Expire: {expire}s")

        # Validate that primary NS actually exists and responds
        self._sleep()
        ns_a = self._query(primary_ns, "A")
        if ns_a:
            ns_ip = str(list(ns_a)[0])
            self.soa_validation["primary_ns_ip"] = ns_ip
            self.discovered_ips.add(ns_ip)

            # Try to query the NS directly
            test_resolver = dns.resolver.Resolver()
            test_resolver.nameservers = [ns_ip]
            test_resolver.timeout = self.timeout
            test_resolver.lifetime = self.timeout * 2
            try:
                test_resolver.resolve(self.domain, "SOA")
                self.soa_validation["primary_ns_valid"] = True
                log_success(f"Primary NS {primary_ns} ({ns_ip}) responds correctly")
            except Exception:
                self.soa_validation["primary_ns_valid"] = False
                log_warning(f"Primary NS {primary_ns} ({ns_ip}) resolved but did not respond to SOA query")
                self.findings.append({
                    "severity": SEVERITY_HIGH,
                    "id": "DNS-004",
                    "title": "SOA Primary NS Non-Responsive",
                    "description": (
                        f"SOA record references primary nameserver {primary_ns} ({ns_ip}) "
                        "which exists but does not respond to DNS queries. "
                        "This may indicate a misconfigured or decommissioned server."
                    ),
                    "mitre": "T1590.002",
                })
                log_finding(SEVERITY_HIGH, f"SOA primary NS {primary_ns} does not respond")
        else:
            log_error(f"Primary NS {primary_ns} does NOT resolve!")
            self.soa_validation["primary_ns_valid"] = False
            self.findings.append({
                "severity": SEVERITY_HIGH,
                "id": "DNS-005",
                "title": "SOA References Nonexistent Nameserver",
                "description": (
                    f"SOA record references primary nameserver {primary_ns} "
                    "which does not resolve to any IP address. "
                    "This is a misconfiguration that could lead to DNS instability."
                ),
                "mitre": "T1590.002",
            })
            log_finding(SEVERITY_HIGH, f"SOA references nonexistent nameserver: {primary_ns}")

    # ------------------------------------------------------------------
    # Phase 6: Subdomain brute force
    # ------------------------------------------------------------------

    def _resolve_subdomain(self, subdomain: str) -> Optional[Tuple[str, List[str]]]:
        """Resolve a single subdomain. Returns (fqdn, [ips]) or None."""
        fqdn = f"{subdomain}.{self.domain}"
        self._sleep()
        try:
            answer = self.resolver.resolve(fqdn, "A")
            ips = [str(rdata) for rdata in answer]

            # If wildcard detected, skip if result matches wildcard IPs
            if self.wildcard_detected and set(ips) == self.wildcard_ips:
                return None

            return (fqdn, ips)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return None
        except Exception:
            return None

    def brute_force_subdomains(self) -> None:
        section_header("Phase 6: Subdomain Brute Force")

        if self.no_brute:
            log_info("Subdomain brute force skipped (--no-brute)")
            return

        total = len(self.subdomains_wordlist)
        log_info(f"Testing {total} subdomains with {self.workers} workers...")
        if self.wildcard_detected:
            log_warning(
                f"Wildcard DNS detected -- filtering out results matching {', '.join(self.wildcard_ips)}"
            )

        found_count = 0
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            future_to_sub = {
                executor.submit(self._resolve_subdomain, sub): sub
                for sub in self.subdomains_wordlist
            }
            for future in concurrent.futures.as_completed(future_to_sub):
                completed += 1
                if not self.quiet and completed % 50 == 0:
                    pct = (completed / total) * 100
                    sys.stdout.write(
                        f"\r{Fore.CYAN}[*]{Style.RESET_ALL} Progress: {completed}/{total} ({pct:.0f}%)"
                    )
                    sys.stdout.flush()

                result = future.result()
                if result:
                    fqdn, ips = result
                    self.discovered_subdomains[fqdn] = ips
                    for ip in ips:
                        self.discovered_ips.add(ip)
                    found_count += 1

        if not self.quiet:
            sys.stdout.write("\r" + " " * 60 + "\r")
            sys.stdout.flush()

        log_success(f"Found {found_count} subdomains")
        for fqdn in sorted(self.discovered_subdomains.keys()):
            ips = self.discovered_subdomains[fqdn]
            print(f"         {Fore.GREEN}{fqdn:40s}{Style.RESET_ALL} -> {', '.join(ips)}")

    # ------------------------------------------------------------------
    # Phase 7: Reverse DNS sweep
    # ------------------------------------------------------------------

    def reverse_dns_sweep(self) -> None:
        section_header("Phase 7: Reverse DNS Sweep")

        if not self.discovered_ips:
            log_warning("No IPs discovered; skipping reverse DNS")
            return

        # Expand /24 ranges for discovered IPs (only for IPv4)
        sweep_ips: Set[str] = set()
        networks_expanded: Set[str] = set()

        for ip_str in self.discovered_ips:
            try:
                addr = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv4Address):
                    # Add the IP itself
                    sweep_ips.add(ip_str)
                    # Expand /24 -- but cap to a reasonable range around the IP
                    network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
                    net_str = str(network)
                    if net_str not in networks_expanded:
                        networks_expanded.add(net_str)
                        # Only sweep .1 through .20 and nearby range to avoid huge sweeps
                        base_int = int(addr) & 0xFFFFFF00
                        host_part = int(addr) & 0xFF
                        start = max(1, host_part - 5)
                        end = min(254, host_part + 5)
                        for i in range(start, end + 1):
                            sweep_ips.add(str(ipaddress.IPv4Address(base_int + i)))
                        # Also check common hosts
                        for common in [1, 2, 3, 10, 100, 200, 254]:
                            sweep_ips.add(str(ipaddress.IPv4Address(base_int + common)))
                elif isinstance(addr, ipaddress.IPv6Address):
                    sweep_ips.add(ip_str)
            except ValueError:
                continue

        log_info(f"Sweeping {len(sweep_ips)} IPs for PTR records...")

        no_ptr_count = 0
        server_ips_without_ptr: List[str] = []

        def _reverse_lookup(ip: str) -> Tuple[str, Optional[str]]:
            try:
                rev_name = dns.reversename.from_address(ip)
                answer = self.resolver.resolve(rev_name, "PTR")
                hostname = str(list(answer)[0]).rstrip(".")
                return (ip, hostname)
            except Exception:
                return (ip, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(_reverse_lookup, ip): ip for ip in sweep_ips}
            for future in concurrent.futures.as_completed(futures):
                ip, hostname = future.result()
                self.reverse_dns[ip] = hostname
                if hostname:
                    log_success(f"  {ip:18s} -> {hostname}")
                    # Check if this reveals new subdomains
                    if hostname.endswith(f".{self.domain}") or hostname == self.domain:
                        if hostname not in self.discovered_subdomains:
                            self.discovered_subdomains[hostname] = [ip]
                else:
                    if ip in self.discovered_ips:
                        no_ptr_count += 1
                        server_ips_without_ptr.append(ip)

        if server_ips_without_ptr:
            self.findings.append({
                "severity": SEVERITY_MEDIUM,
                "id": "DNS-006",
                "title": "Server IPs Missing Reverse DNS (PTR)",
                "description": (
                    f"{len(server_ips_without_ptr)} server IP(s) have no reverse DNS (PTR) record. "
                    "Missing PTR records can cause issues with mail delivery and "
                    "complicate incident response."
                ),
                "affected_ips": server_ips_without_ptr,
                "mitre": "T1590.002",
            })
            log_finding(
                SEVERITY_MEDIUM,
                f"{len(server_ips_without_ptr)} server IP(s) lack reverse DNS (PTR)"
            )

        ptr_count = sum(1 for v in self.reverse_dns.values() if v is not None)
        log_info(f"PTR records found: {ptr_count}/{len(sweep_ips)}")

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def calculate_risk_score(self) -> None:
        section_header("Risk Assessment Summary")

        score = 0
        severity_weights = {
            SEVERITY_CRITICAL: 40,
            SEVERITY_HIGH: 25,
            SEVERITY_MEDIUM: 10,
            SEVERITY_LOW: 5,
            SEVERITY_INFO: 0,
        }

        for finding in self.findings:
            sev = finding["severity"]
            score += severity_weights.get(sev, 0)

        self.risk_score = min(score, 100)

        # Color-code the overall score
        if self.risk_score >= 75:
            score_color = Fore.RED + Style.BRIGHT
            rating = "CRITICAL"
        elif self.risk_score >= 50:
            score_color = Fore.RED
            rating = "HIGH"
        elif self.risk_score >= 25:
            score_color = Fore.YELLOW
            rating = "MEDIUM"
        elif self.risk_score > 0:
            score_color = Fore.BLUE
            rating = "LOW"
        else:
            score_color = Fore.GREEN
            rating = "SECURE"

        print(f"\n  Overall Risk Score: {score_color}{self.risk_score}/100 ({rating}){Style.RESET_ALL}\n")

        if self.findings:
            print(f"  Findings ({len(self.findings)}):")
            for f in self.findings:
                log_finding(f["severity"], f"{f['id']} - {f['title']}")
        else:
            log_success("  No significant findings")

    # ------------------------------------------------------------------
    # Network map
    # ------------------------------------------------------------------

    def print_network_map(self) -> None:
        section_header("Discovered Network Map")

        if not self.discovered_ips:
            log_info("No IPs discovered")
            return

        # Group IPs by /24 network
        networks: Dict[str, List[Tuple[str, Optional[str], List[str]]]] = defaultdict(list)

        for ip_str in sorted(self.discovered_ips, key=lambda x: (ipaddress.ip_address(x).version, ipaddress.ip_address(x))):
            try:
                addr = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv4Address):
                    net = str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
                else:
                    net = str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
            except ValueError:
                net = "unknown"

            ptr = self.reverse_dns.get(ip_str)
            # Find subdomains mapping to this IP
            subs = [
                s for s, ips in self.discovered_subdomains.items() if ip_str in ips
            ]
            networks[net].append((ip_str, ptr, subs))

        for net, hosts in sorted(networks.items()):
            print(f"\n  {Fore.CYAN}{Style.BRIGHT}Network: {net}{Style.RESET_ALL}")
            for ip, ptr, subs in hosts:
                label_parts = []
                if ptr:
                    label_parts.append(f"PTR={ptr}")
                if subs:
                    label_parts.append(f"names={','.join(subs)}")
                label = f"  ({'; '.join(label_parts)})" if label_parts else ""
                print(f"    {Fore.WHITE}{ip:18s}{Style.RESET_ALL}{label}")

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self) -> str:
        os.makedirs(REPORTS_DIR, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_domain = self.domain.replace(".", "_")
        filename = f"dns_recon_{safe_domain}_{timestamp}.json"
        filepath = os.path.join(REPORTS_DIR, filename)

        report = {
            "tool": "HAKA AI DNS Reconnaissance Scanner",
            "version": "1.0.0",
            "mitre_attack": "T1590.002",
            "scan_metadata": {
                "target_domain": self.domain,
                "dns_server": self.dns_server or "system default",
                "scan_start": self.scan_start.isoformat() if self.scan_start else None,
                "scan_end": self.scan_end.isoformat() if self.scan_end else None,
                "duration_seconds": (
                    (self.scan_end - self.scan_start).total_seconds()
                    if self.scan_start and self.scan_end
                    else None
                ),
                "wordlist_size": len(self.subdomains_wordlist),
                "workers": self.workers,
            },
            "risk_assessment": {
                "score": self.risk_score,
                "rating": (
                    "CRITICAL" if self.risk_score >= 75
                    else "HIGH" if self.risk_score >= 50
                    else "MEDIUM" if self.risk_score >= 25
                    else "LOW" if self.risk_score > 0
                    else "SECURE"
                ),
                "findings_count": len(self.findings),
                "findings": self.findings,
            },
            "dns_records": {rtype: recs for rtype, recs in self.records.items()},
            "dnssec": self.dnssec_status,
            "zone_transfers": self.zone_transfer_results,
            "wildcard_dns": {
                "detected": self.wildcard_detected,
                "wildcard_ips": list(self.wildcard_ips),
            },
            "soa_validation": self.soa_validation,
            "discovered_subdomains": self.discovered_subdomains,
            "discovered_ips": sorted(self.discovered_ips, key=lambda x: (ipaddress.ip_address(x).version, ipaddress.ip_address(x))),
            "reverse_dns": {
                ip: ptr for ip, ptr in self.reverse_dns.items() if ptr is not None
            },
            "network_map": self._build_network_map_data(),
        }

        with open(filepath, "w") as fh:
            json.dump(report, fh, indent=2, default=str)

        return filepath

    def _build_network_map_data(self) -> Dict[str, Any]:
        networks: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ip_str in sorted(self.discovered_ips, key=lambda x: (ipaddress.ip_address(x).version, ipaddress.ip_address(x))):
            try:
                addr = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv4Address):
                    net = str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
                else:
                    net = str(ipaddress.ip_network(f"{ip_str}/64", strict=False))
            except ValueError:
                net = "unknown"

            ptr = self.reverse_dns.get(ip_str)
            subs = [s for s, ips in self.discovered_subdomains.items() if ip_str in ips]
            networks[net].append({
                "ip": ip_str,
                "ptr": ptr,
                "subdomains": subs,
            })
        return dict(networks)

    # ------------------------------------------------------------------
    # Main scan orchestration
    # ------------------------------------------------------------------

    def run(self) -> str:
        """Execute the full scan pipeline. Returns path to JSON report."""
        print(BANNER)
        self.scan_start = datetime.now(timezone.utc)
        log_info(f"Target domain : {Fore.WHITE}{Style.BRIGHT}{self.domain}{Style.RESET_ALL}")
        log_info(f"DNS server    : {self.dns_server or 'system default'}")
        log_info(f"Wordlist size : {len(self.subdomains_wordlist)}")
        log_info(f"Workers       : {self.workers}")
        log_info(f"Delay         : {self.delay}s")
        log_info(f"Scan started  : {self.scan_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Phase 1: Record enumeration
        self.enumerate_records()

        # Phase 2: DNSSEC check
        self.check_dnssec()

        # Phase 3: Zone transfer
        self.attempt_zone_transfers()

        # Phase 4: Wildcard detection
        self.detect_wildcard()

        # Phase 5: SOA validation
        self.validate_soa()

        # Phase 6: Subdomain brute force
        self.brute_force_subdomains()

        # Phase 7: Reverse DNS
        self.reverse_dns_sweep()

        # Risk scoring
        self.calculate_risk_score()

        # Network map
        self.print_network_map()

        # Generate report
        self.scan_end = datetime.now(timezone.utc)
        report_path = self.generate_report()

        section_header("Scan Complete")
        duration = (self.scan_end - self.scan_start).total_seconds()
        log_info(f"Duration          : {duration:.1f}s")
        log_info(f"Records found     : {sum(len(v) for v in self.records.values())}")
        log_info(f"Subdomains found  : {len(self.discovered_subdomains)}")
        log_info(f"Unique IPs        : {len(self.discovered_ips)}")
        log_info(f"Findings          : {len(self.findings)}")
        log_success(f"Report saved to   : {Fore.WHITE}{report_path}{Style.RESET_ALL}")

        return report_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="haka_dns_scanner",
        description=(
            "HAKA AI - DNS Reconnaissance Scanner (T1590.002)\n"
            "Comprehensive DNS enumeration and security assessment."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --domain haka.local\n"
            "  %(prog)s --domain haka.local --dns-server 192.168.122.210\n"
            "  %(prog)s --domain haka.local --wordlist custom_subs.txt --delay 0.5\n"
            "  %(prog)s --domain haka.local --no-brute --workers 10\n"
        ),
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target domain to scan (e.g., haka.local)",
    )
    parser.add_argument(
        "-s", "--dns-server",
        default=None,
        help="Custom DNS server IP to use for queries",
    )
    parser.add_argument(
        "-w", "--wordlist",
        default=None,
        help="Path to custom subdomain wordlist (one per line)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay in seconds between queries for rate limiting (default: 0)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"DNS query timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Number of concurrent workers for brute force (default: 20)",
    )
    parser.add_argument(
        "--no-brute",
        action="store_true",
        help="Skip subdomain brute force phase",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress output during brute force",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    scanner = HAKADnsScanner(
        domain=args.domain,
        dns_server=args.dns_server,
        wordlist_path=args.wordlist,
        delay=args.delay,
        timeout=args.timeout,
        workers=args.workers,
        no_brute=args.no_brute,
        quiet=args.quiet,
    )

    try:
        report_path = scanner.run()
        sys.exit(0)
    except KeyboardInterrupt:
        print()
        log_warning("Scan interrupted by user")
        # Still try to save partial results
        scanner.scan_end = datetime.now(timezone.utc)
        try:
            report_path = scanner.generate_report()
            log_info(f"Partial report saved to: {report_path}")
        except Exception:
            pass
        sys.exit(130)
    except Exception as e:
        log_error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
