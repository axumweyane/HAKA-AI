#!/usr/bin/env python3
"""
HAKA AI - Kerberos Attack Detector (Tool 5: B4/B5 - Kerberoasting & AS-REP Roasting)

Detects Kerberoasting (T1558.003) and AS-REP Roasting (T1558.004) attacks by
analysing Windows Security Event Logs and optionally auditing Active Directory
for vulnerable configurations.

Findings: CRIT-CBE-10, CRIT-AWB-09

Capabilities:
  - Parse EVTX / CSV logs for Event IDs 4768, 4769, 4771
  - Detect RC4 TGS requests (Kerberoasting signature)
  - Detect missing pre-authentication (AS-REP Roasting signature)
  - Mass-request burst detection with configurable thresholds
  - LDAP audit for SPN accounts, pre-auth-disabled accounts, weak encryption
  - Service-account risk scoring
  - Wazuh rule generation (100550, 100551, 100555)
  - JSON + console reporting

Author:  HAKA AI Framework
Version: 1.0.0
"""

import argparse
import csv
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dependency imports (graceful degradation)
# ---------------------------------------------------------------------------

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    sys.exit(
        "[!] colorama is required.  Install it:\n"
        "    pip install colorama"
    )

try:
    import pandas as pd
except ImportError:
    sys.exit(
        "[!] pandas is required.  Install it:\n"
        "    pip install pandas"
    )

EVTX_AVAILABLE = False
try:
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
    EVTX_AVAILABLE = True
except ImportError:
    pass

LDAP_AVAILABLE = False
try:
    from ldap3 import Server, Connection, ALL, SUBTREE, NTLM
    LDAP_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
REPORTS_DIR = Path("/home/kironix/HAKA-AI/reports")

# Kerberos encryption type constants
ETYPE_MAP = {
    "0x1": "DES-CBC-CRC",
    "0x3": "DES-CBC-MD5",
    "0x11": "AES128-CTS-HMAC-SHA1",
    "0x12": "AES256-CTS-HMAC-SHA1",
    "0x17": "RC4-HMAC",
    "0x18": "RC4-HMAC-EXP",
    "1":  "DES-CBC-CRC",
    "3":  "DES-CBC-MD5",
    "17": "AES128-CTS-HMAC-SHA1",
    "18": "AES256-CTS-HMAC-SHA1",
    "23": "RC4-HMAC",
    "24": "RC4-HMAC-EXP",
}

WEAK_ETYPES = {"0x17", "0x18", "0x1", "0x3", "23", "24", "1", "3"}
RC4_ETYPES = {"0x17", "0x18", "23", "24"}

# Event IDs
EID_TGS_REQUEST = 4769
EID_TGT_REQUEST = 4768
EID_PREAUTH_FAIL = 4771

# Default thresholds
DEFAULT_BURST_COUNT = 10
DEFAULT_BURST_WINDOW = 60  # seconds
DEFAULT_ENUM_COUNT = 5
DEFAULT_ENUM_WINDOW = 30   # seconds

RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH":     7,
    "MEDIUM":   4,
    "LOW":      1,
    "INFO":     0,
}

# Kerberos status codes
KRB_STATUS_CODES = {
    "0x0":  "KDC_ERR_NONE (Success)",
    "0x6":  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    "0x12": "KDC_ERR_CLIENT_REVOKED",
    "0x17": "KDC_ERR_KEY_EXPIRED",
    "0x18": "KDC_ERR_PREAUTH_FAILED",
    "0x19": "KDC_ERR_PREAUTH_REQUIRED",
    "0x1f": "KDC_ERR_INTEGRITY_CHECK_FAILED",
    "0x25": "KDC_ERR_PREAUTH_REQUIRED",
}

# EVTX XML namespace
EVTX_NS = {
    "ev": "http://schemas.microsoft.com/win/2004/08/events/event",
}

# ---------------------------------------------------------------------------
# Banner / output helpers
# ---------------------------------------------------------------------------

def banner() -> None:
    colorama_init(autoreset=True)
    b = rf"""
{Fore.RED}
  _  __          _                              ____       _            _
 | |/ /___ _ __ | |__   ___ _ __ ___  ___      |  _ \  ___| |_ ___  ___| |_
 | ' // _ \ '_ \| '_ \ / _ \ '__/ _ \/ __|     | | | |/ _ \ __/ _ \/ __| __|
 | . \  __/ |   | |_) |  __/ | | (_) \__ \     | |_| |  __/ ||  __/ (__| |_
 |_|\_\___|_|   |_.__/ \___|_|  \___/|___/     |____/ \___|\__\___|\___|\__|
{Style.RESET_ALL}
 {Fore.CYAN}HAKA AI - Kerberos Attack Detector v{VERSION}{Style.RESET_ALL}
 {Fore.WHITE}T1558.003 Kerberoasting  |  T1558.004 AS-REP Roasting{Style.RESET_ALL}
 {Fore.WHITE}Findings: CRIT-CBE-10, CRIT-AWB-09{Style.RESET_ALL}
"""
    print(b)


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str) -> None:
    print(f"  {Fore.BLUE}[{_ts()}] [*]{Style.RESET_ALL} {msg}")


def good(msg: str) -> None:
    print(f"  {Fore.GREEN}[{_ts()}] [+]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"  {Fore.YELLOW}[{_ts()}] [!]{Style.RESET_ALL} {msg}")


def critical(msg: str) -> None:
    print(f"  {Fore.RED}[{_ts()}] [!!!]{Style.RESET_ALL} {Fore.RED}{msg}{Style.RESET_ALL}")


def section(title: str) -> None:
    width = 70
    print()
    print(f"  {Fore.CYAN}{'=' * width}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{title.center(width)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'=' * width}{Style.RESET_ALL}")
    print()


def severity_color(sev: str) -> str:
    return {
        "CRITICAL": Fore.RED,
        "HIGH":     Fore.LIGHTRED_EX,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.WHITE,
        "INFO":     Fore.BLUE,
    }.get(sev.upper(), "")


# ---------------------------------------------------------------------------
# Data classes / containers
# ---------------------------------------------------------------------------

class KerberosEvent:
    """Represents a single parsed Kerberos event."""

    __slots__ = (
        "timestamp", "event_id", "source_ip", "source_port",
        "target_user", "target_domain", "service_name", "service_id",
        "ticket_encryption", "ticket_options", "status_code",
        "pre_auth_type", "cert_issuer", "raw_xml",
    )

    def __init__(self, **kwargs: Any):
        for slot in self.__slots__:
            setattr(self, slot, kwargs.get(slot, ""))

    def to_dict(self) -> Dict[str, str]:
        return {s: getattr(self, s, "") for s in self.__slots__ if s != "raw_xml"}


class Alert:
    """Security alert generated by analysis."""

    def __init__(
        self,
        severity: str,
        attack_type: str,
        description: str,
        source_ip: str = "",
        target_account: str = "",
        evidence: Optional[List[str]] = None,
        timestamp: str = "",
        mitre_id: str = "",
        finding_id: str = "",
        recommendation: str = "",
    ):
        self.severity = severity
        self.attack_type = attack_type
        self.description = description
        self.source_ip = source_ip
        self.target_account = target_account
        self.evidence = evidence or []
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.mitre_id = mitre_id
        self.finding_id = finding_id
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "attack_type": self.attack_type,
            "description": self.description,
            "source_ip": self.source_ip,
            "target_account": self.target_account,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "mitre_id": self.mitre_id,
            "finding_id": self.finding_id,
            "recommendation": self.recommendation,
        }


# ---------------------------------------------------------------------------
# EVTX / CSV Parser
# ---------------------------------------------------------------------------

class KerberosLogParser:
    """Parse Windows Security Event Log entries for Kerberos events."""

    TARGET_EIDS = {EID_TGS_REQUEST, EID_TGT_REQUEST, EID_PREAUTH_FAIL}

    # ---- EVTX parsing ----

    @staticmethod
    def _extract_data_field(xml_root: ET.Element, field_name: str) -> str:
        """Extract a named Data field from EVTX XML EventData."""
        for data_el in xml_root.iter():
            if data_el.tag.endswith("}Data") or data_el.tag == "Data":
                if data_el.get("Name") == field_name:
                    return (data_el.text or "").strip()
        return ""

    @classmethod
    def _parse_evtx_record(cls, xml_str: str) -> Optional[KerberosEvent]:
        """Parse a single EVTX XML record into a KerberosEvent."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        # Get Event ID
        eid_el = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
        if eid_el is None:
            eid_el = root.find(".//EventID")
        if eid_el is None or eid_el.text is None:
            return None

        try:
            event_id = int(eid_el.text.strip())
        except ValueError:
            return None

        if event_id not in cls.TARGET_EIDS:
            return None

        # Get timestamp
        time_created = root.find(
            ".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated"
        )
        if time_created is None:
            time_created = root.find(".//TimeCreated")
        timestamp = ""
        if time_created is not None:
            timestamp = time_created.get("SystemTime", "")

        extract = lambda f: cls._extract_data_field(root, f)

        ev = KerberosEvent(
            timestamp=timestamp,
            event_id=str(event_id),
            target_user=extract("TargetUserName"),
            target_domain=extract("TargetDomainName"),
            service_name=extract("ServiceName"),
            service_id=extract("ServiceSid"),
            source_ip=extract("IpAddress").lstrip(":").lstrip("f").lstrip(":"),
            source_port=extract("IpPort"),
            ticket_encryption=extract("TicketEncryptionType"),
            ticket_options=extract("TicketOptions"),
            status_code=extract("Status") or extract("ResultCode"),
            pre_auth_type=extract("PreAuthType"),
            cert_issuer=extract("CertIssuerName"),
            raw_xml=xml_str,
        )
        return ev

    @classmethod
    def parse_evtx(cls, filepath: str) -> List[KerberosEvent]:
        """Parse an EVTX file and return Kerberos events."""
        if not EVTX_AVAILABLE:
            warn("python-evtx not installed. Attempting CSV fallback...")
            return []

        events: List[KerberosEvent] = []
        info(f"Parsing EVTX file: {filepath}")
        count = 0
        try:
            with evtx.Evtx(filepath) as log:
                for record in log.records():
                    count += 1
                    xml_str = record.xml()
                    ev = cls._parse_evtx_record(xml_str)
                    if ev is not None:
                        events.append(ev)
        except Exception as exc:
            warn(f"EVTX parse error: {exc}")
            return events

        info(f"Scanned {count} total records, extracted {len(events)} Kerberos events")
        return events

    # ---- CSV fallback ----

    @classmethod
    def parse_csv(cls, filepath: str) -> List[KerberosEvent]:
        """
        Parse a CSV export of Windows Security logs.

        Expected columns (flexible matching):
          TimeGenerated/TimeCreated/Timestamp, EventID/Id,
          TargetUserName, TargetDomainName, ServiceName,
          IpAddress/SourceAddress, IpPort, TicketEncryptionType,
          TicketOptions, Status/ResultCode, PreAuthType
        """
        events: List[KerberosEvent] = []
        info(f"Parsing CSV file: {filepath}")

        # Column name normalization map
        col_map = {
            "timegenerated": "timestamp",
            "timecreated": "timestamp",
            "timestamp": "timestamp",
            "eventid": "event_id",
            "id": "event_id",
            "event_id": "event_id",
            "targetusername": "target_user",
            "target_user": "target_user",
            "targetdomainname": "target_domain",
            "target_domain": "target_domain",
            "servicename": "service_name",
            "service_name": "service_name",
            "servicesid": "service_id",
            "ipaddress": "source_ip",
            "sourceaddress": "source_ip",
            "source_ip": "source_ip",
            "ipport": "source_port",
            "source_port": "source_port",
            "ticketencryptiontype": "ticket_encryption",
            "ticket_encryption": "ticket_encryption",
            "ticketoptions": "ticket_options",
            "ticket_options": "ticket_options",
            "status": "status_code",
            "resultcode": "status_code",
            "status_code": "status_code",
            "preauthtype": "pre_auth_type",
            "pre_auth_type": "pre_auth_type",
        }

        try:
            with open(filepath, "r", encoding="utf-8-sig") as fh:
                reader = csv.DictReader(fh)
                if reader.fieldnames is None:
                    warn("CSV file has no headers")
                    return events

                # Build mapping from CSV columns -> our field names
                mapping: Dict[str, str] = {}
                for col in reader.fieldnames:
                    norm = col.strip().lower().replace(" ", "")
                    if norm in col_map:
                        mapping[col] = col_map[norm]

                for row in reader:
                    kwargs: Dict[str, str] = {}
                    for csv_col, field in mapping.items():
                        kwargs[field] = (row.get(csv_col) or "").strip()

                    # Filter for target event IDs
                    try:
                        eid = int(kwargs.get("event_id", "0"))
                    except ValueError:
                        continue
                    if eid not in cls.TARGET_EIDS:
                        continue

                    # Clean IP
                    ip = kwargs.get("source_ip", "")
                    kwargs["source_ip"] = ip.lstrip(":").lstrip("f").lstrip(":")

                    events.append(KerberosEvent(**kwargs))

        except Exception as exc:
            warn(f"CSV parse error: {exc}")

        info(f"Extracted {len(events)} Kerberos events from CSV")
        return events

    # ---- Unified entry point ----

    @classmethod
    def parse(cls, filepath: str) -> List[KerberosEvent]:
        """Auto-detect file format and parse."""
        path = Path(filepath)
        if not path.exists():
            warn(f"File not found: {filepath}")
            return []

        if path.suffix.lower() == ".evtx":
            events = cls.parse_evtx(filepath)
            if not events and not EVTX_AVAILABLE:
                warn("python-evtx unavailable. Provide a CSV export instead.")
            return events
        elif path.suffix.lower() in (".csv", ".tsv", ".txt"):
            return cls.parse_csv(filepath)
        else:
            # Try EVTX first, fall back to CSV
            if EVTX_AVAILABLE:
                events = cls.parse_evtx(filepath)
                if events:
                    return events
            return cls.parse_csv(filepath)


# ---------------------------------------------------------------------------
# Analysis Engine
# ---------------------------------------------------------------------------

class KerberosAnalyzer:
    """Analyze parsed Kerberos events for attack indicators."""

    def __init__(
        self,
        burst_count: int = DEFAULT_BURST_COUNT,
        burst_window: int = DEFAULT_BURST_WINDOW,
        enum_count: int = DEFAULT_ENUM_COUNT,
        enum_window: int = DEFAULT_ENUM_WINDOW,
    ):
        self.burst_count = burst_count
        self.burst_window = burst_window
        self.enum_count = enum_count
        self.enum_window = enum_window
        self.alerts: List[Alert] = []
        self.tgs_events: List[KerberosEvent] = []
        self.tgt_events: List[KerberosEvent] = []
        self.preauth_events: List[KerberosEvent] = []
        self.service_account_risk: Dict[str, Dict[str, Any]] = {}

    # ---- Timestamp parsing ----

    @staticmethod
    def _parse_ts(ts_str: str) -> Optional[datetime]:
        """Best-effort timestamp parsing."""
        if not ts_str:
            return None
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    # ---- Classify events ----

    def ingest(self, events: List[KerberosEvent]) -> None:
        """Sort events into buckets by Event ID."""
        for ev in events:
            try:
                eid = int(ev.event_id)
            except (ValueError, TypeError):
                continue
            if eid == EID_TGS_REQUEST:
                self.tgs_events.append(ev)
            elif eid == EID_TGT_REQUEST:
                self.tgt_events.append(ev)
            elif eid == EID_PREAUTH_FAIL:
                self.preauth_events.append(ev)

        info(
            f"Event breakdown: {len(self.tgs_events)} TGS (4769), "
            f"{len(self.tgt_events)} TGT (4768), "
            f"{len(self.preauth_events)} PreAuth-Fail (4771)"
        )

    # ---- Kerberoasting Detection ----

    def detect_kerberoasting(self) -> None:
        """Detect Kerberoasting via RC4 TGS requests and burst patterns."""
        section("KERBEROASTING DETECTION (T1558.003)")

        # 1) Individual RC4 TGS requests
        rc4_requests: List[KerberosEvent] = []
        for ev in self.tgs_events:
            enc = ev.ticket_encryption.strip().lower()
            if enc in RC4_ETYPES or enc in {"rc4-hmac", "rc4_hmac", "rc4"}:
                rc4_requests.append(ev)

        if rc4_requests:
            critical(
                f"Found {len(rc4_requests)} TGS requests using RC4 encryption "
                f"(Kerberoasting indicator)"
            )
            # Show top targets
            svc_counts: Dict[str, int] = defaultdict(int)
            ip_counts: Dict[str, int] = defaultdict(int)
            for ev in rc4_requests:
                svc = ev.service_name or ev.target_user or "<unknown>"
                svc_counts[svc] += 1
                if ev.source_ip:
                    ip_counts[ev.source_ip] += 1

            print()
            info("Targeted service accounts (by RC4 TGS count):")
            for svc, cnt in sorted(svc_counts.items(), key=lambda x: -x[1])[:20]:
                sev = "CRITICAL" if cnt >= 5 else "HIGH" if cnt >= 2 else "MEDIUM"
                print(
                    f"    {severity_color(sev)}{sev:<10}{Style.RESET_ALL}"
                    f"  {svc:<40}  ({cnt} requests)"
                )
                self._update_svc_risk(svc, sev, f"RC4 TGS x{cnt}")

            print()
            info("Source IPs requesting RC4 TGS tickets:")
            for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
                sev = "CRITICAL" if cnt >= 10 else "HIGH" if cnt >= 5 else "MEDIUM"
                print(
                    f"    {severity_color(sev)}{sev:<10}{Style.RESET_ALL}"
                    f"  {ip:<20}  ({cnt} RC4 TGS requests)"
                )

            # Generate alerts per service
            for svc, cnt in svc_counts.items():
                sev = "CRITICAL" if cnt >= 5 else "HIGH"
                self.alerts.append(Alert(
                    severity=sev,
                    attack_type="Kerberoasting",
                    description=(
                        f"Service account '{svc}' received {cnt} TGS request(s) "
                        f"using RC4 encryption (0x17). This is a strong indicator of "
                        f"Kerberoasting — an attacker is requesting service tickets "
                        f"to crack offline."
                    ),
                    target_account=svc,
                    source_ip=", ".join(
                        ip for ev in rc4_requests
                        if (ev.service_name or ev.target_user) == svc and ev.source_ip
                        for ip in [ev.source_ip]
                    ),
                    evidence=[
                        f"Event ID 4769, EncryptionType=RC4 (0x17), Count={cnt}"
                    ],
                    mitre_id="T1558.003",
                    finding_id="CRIT-CBE-10",
                    recommendation=(
                        "1. Convert service account to gMSA (Group Managed Service Account)\n"
                        "2. Enforce AES-only encryption on the account (disable RC4)\n"
                        "3. Set a long (25+ char), random password and rotate every 30 days\n"
                        "4. Restrict account delegation and permissions to minimum required"
                    ),
                ))
        else:
            good("No RC4 TGS requests detected (no Kerberoasting indicator)")

        # 2) Burst detection — mass TGS from same IP in time window
        self._detect_tgs_burst(rc4_requests)

    def _detect_tgs_burst(self, rc4_requests: List[KerberosEvent]) -> None:
        """Detect bursts of RC4 TGS requests from a single source."""
        if not rc4_requests:
            return

        print()
        info(
            f"Checking for TGS request bursts "
            f"(>={self.burst_count} RC4 requests within {self.burst_window}s) ..."
        )

        # Group by source IP
        by_ip: Dict[str, List[datetime]] = defaultdict(list)
        for ev in rc4_requests:
            ip = ev.source_ip or "unknown"
            ts = self._parse_ts(ev.timestamp)
            if ts:
                by_ip[ip].append(ts)

        burst_detected = False
        for ip, timestamps in by_ip.items():
            timestamps.sort()
            # Sliding window
            for i in range(len(timestamps)):
                window_end = timestamps[i] + timedelta(seconds=self.burst_window)
                window_events = [
                    t for t in timestamps[i:] if t <= window_end
                ]
                if len(window_events) >= self.burst_count:
                    burst_detected = True
                    critical(
                        f"BURST DETECTED: {len(window_events)} RC4 TGS from {ip} "
                        f"within {self.burst_window}s "
                        f"(starting {timestamps[i].isoformat()})"
                    )
                    self.alerts.append(Alert(
                        severity="CRITICAL",
                        attack_type="Kerberoasting - Mass Request Burst",
                        description=(
                            f"Detected {len(window_events)} RC4-encrypted TGS requests "
                            f"from {ip} within a {self.burst_window}-second window. This is "
                            f"a strong indicator of automated Kerberoasting (e.g., Rubeus, "
                            f"Impacket GetUserSPNs)."
                        ),
                        source_ip=ip,
                        evidence=[
                            f"Burst: {len(window_events)} requests in {self.burst_window}s",
                            f"Start: {timestamps[i].isoformat()}",
                            f"End: {window_events[-1].isoformat()}",
                        ],
                        timestamp=timestamps[i].isoformat(),
                        mitre_id="T1558.003",
                        finding_id="CRIT-CBE-10",
                        recommendation=(
                            "1. Immediately investigate source IP for compromise\n"
                            "2. Check if the source corresponds to a known workstation\n"
                            "3. Rotate all targeted service account passwords NOW\n"
                            "4. Deploy honeypot SPN accounts to detect future attempts"
                        ),
                    ))
                    break  # One burst alert per IP is enough

        if not burst_detected:
            good(f"No TGS request bursts detected (threshold: {self.burst_count}/{self.burst_window}s)")

    # ---- AS-REP Roasting Detection ----

    def detect_asrep_roasting(self) -> None:
        """Detect AS-REP Roasting via pre-auth disabled TGT requests."""
        section("AS-REP ROASTING DETECTION (T1558.004)")

        # 1) TGT requests with PreAuthType = 0 or missing preauth
        no_preauth: List[KerberosEvent] = []
        for ev in self.tgt_events:
            pat = ev.pre_auth_type.strip()
            if pat in ("0", "", "-"):
                no_preauth.append(ev)

        if no_preauth:
            critical(
                f"Found {len(no_preauth)} TGT requests with NO pre-authentication "
                f"(AS-REP Roasting indicator)"
            )

            user_counts: Dict[str, int] = defaultdict(int)
            ip_counts: Dict[str, int] = defaultdict(int)
            for ev in no_preauth:
                user = ev.target_user or "<unknown>"
                user_counts[user] += 1
                if ev.source_ip:
                    ip_counts[ev.source_ip] += 1

            print()
            info("Accounts requested without pre-authentication:")
            for user, cnt in sorted(user_counts.items(), key=lambda x: -x[1])[:20]:
                sev = "CRITICAL" if cnt >= 3 else "HIGH"
                print(
                    f"    {severity_color(sev)}{sev:<10}{Style.RESET_ALL}"
                    f"  {user:<40}  ({cnt} requests)"
                )
                self._update_svc_risk(user, sev, f"AS-REP no-preauth x{cnt}")

            print()
            info("Source IPs performing AS-REP requests:")
            for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
                sev = "CRITICAL" if cnt >= 5 else "HIGH" if cnt >= 2 else "MEDIUM"
                print(
                    f"    {severity_color(sev)}{sev:<10}{Style.RESET_ALL}"
                    f"  {ip:<20}  ({cnt} no-preauth TGT requests)"
                )

            # Alert per user
            for user, cnt in user_counts.items():
                self.alerts.append(Alert(
                    severity="CRITICAL" if cnt >= 3 else "HIGH",
                    attack_type="AS-REP Roasting",
                    description=(
                        f"Account '{user}' had {cnt} TGT request(s) with pre-authentication "
                        f"disabled (PreAuthType=0). The AS-REP can be captured and cracked "
                        f"offline to recover the user's password."
                    ),
                    target_account=user,
                    source_ip=", ".join(
                        ip for ev in no_preauth
                        if ev.target_user == user and ev.source_ip
                        for ip in [ev.source_ip]
                    ),
                    evidence=[
                        f"Event ID 4768, PreAuthType=0, Count={cnt}"
                    ],
                    mitre_id="T1558.004",
                    finding_id="CRIT-AWB-09",
                    recommendation=(
                        "1. ENABLE Kerberos pre-authentication on this account immediately\n"
                        "2. Reset the account password (assume it may be compromised)\n"
                        "3. Enforce AES-only encryption types\n"
                        "4. Review why pre-auth was disabled (legacy app requirement?)"
                    ),
                ))
        else:
            good("No AS-REP Roasting indicators detected (all TGT requests have pre-auth)")

        # 2) Enumeration pattern: rapid TGT requests for different users
        self._detect_asrep_enumeration(no_preauth)

        # 3) Pre-auth failure analysis (4771)
        self._analyze_preauth_failures()

    def _detect_asrep_enumeration(self, no_preauth: List[KerberosEvent]) -> None:
        """Detect user enumeration via rapid AS-REP requests."""
        if not no_preauth:
            return

        print()
        info(
            f"Checking for AS-REP enumeration patterns "
            f"(>={self.enum_count} different users within {self.enum_window}s) ..."
        )

        by_ip: Dict[str, List[Tuple[datetime, str]]] = defaultdict(list)
        for ev in no_preauth:
            ip = ev.source_ip or "unknown"
            ts = self._parse_ts(ev.timestamp)
            user = ev.target_user or ""
            if ts and user:
                by_ip[ip].append((ts, user))

        enum_detected = False
        for ip, entries in by_ip.items():
            entries.sort(key=lambda x: x[0])
            for i in range(len(entries)):
                window_end = entries[i][0] + timedelta(seconds=self.enum_window)
                window = [(t, u) for t, u in entries[i:] if t <= window_end]
                unique_users = set(u for _, u in window)
                if len(unique_users) >= self.enum_count:
                    enum_detected = True
                    critical(
                        f"ENUMERATION DETECTED: {ip} queried {len(unique_users)} "
                        f"different accounts within {self.enum_window}s"
                    )
                    self.alerts.append(Alert(
                        severity="CRITICAL",
                        attack_type="AS-REP Roasting - User Enumeration",
                        description=(
                            f"Source IP {ip} queried {len(unique_users)} different user "
                            f"accounts for AS-REP tickets within {self.enum_window} seconds. "
                            f"This indicates automated enumeration of accounts without "
                            f"pre-authentication (e.g., Rubeus, kerbrute)."
                        ),
                        source_ip=ip,
                        target_account=", ".join(sorted(unique_users)[:10]),
                        evidence=[
                            f"Unique users queried: {len(unique_users)}",
                            f"Window: {self.enum_window}s",
                            f"Users: {', '.join(sorted(unique_users)[:10])}",
                        ],
                        mitre_id="T1558.004",
                        finding_id="CRIT-AWB-09",
                        recommendation=(
                            "1. Block or investigate source IP immediately\n"
                            "2. Enable pre-auth on ALL discovered accounts\n"
                            "3. Reset passwords for all enumerated accounts\n"
                            "4. Consider implementing honeypot accounts"
                        ),
                    ))
                    break

        if not enum_detected:
            good(
                f"No AS-REP enumeration patterns detected "
                f"(threshold: {self.enum_count} users/{self.enum_window}s)"
            )

    def _analyze_preauth_failures(self) -> None:
        """Analyze Event 4771 pre-authentication failures."""
        if not self.preauth_events:
            return

        print()
        info(f"Analyzing {len(self.preauth_events)} pre-authentication failure events (4771)...")

        user_failures: Dict[str, int] = defaultdict(int)
        ip_failures: Dict[str, int] = defaultdict(int)
        status_counts: Dict[str, int] = defaultdict(int)

        for ev in self.preauth_events:
            user = ev.target_user or "<unknown>"
            user_failures[user] += 1
            if ev.source_ip:
                ip_failures[ev.source_ip] += 1
            sc = ev.status_code or "unknown"
            status_counts[sc] += 1

        # High failure counts may indicate password spraying alongside roasting
        suspicious = {u: c for u, c in user_failures.items() if c >= 3}
        if suspicious:
            warn("Accounts with elevated pre-auth failures (possible spray/brute-force):")
            for user, cnt in sorted(suspicious.items(), key=lambda x: -x[1])[:15]:
                print(f"    {Fore.YELLOW}{user:<40}  {cnt} failures{Style.RESET_ALL}")

        print()
        info("Pre-auth failure status code distribution:")
        for code, cnt in sorted(status_counts.items(), key=lambda x: -x[1]):
            desc = KRB_STATUS_CODES.get(code, "Unknown")
            print(f"    {code:<10}  {desc:<45}  ({cnt})")

    # ---- Service Account Risk Scoring ----

    def _update_svc_risk(self, account: str, severity: str, reason: str) -> None:
        """Accumulate risk score for a service account."""
        if account not in self.service_account_risk:
            self.service_account_risk[account] = {
                "score": 0,
                "reasons": [],
                "max_severity": "INFO",
            }
        entry = self.service_account_risk[account]
        entry["score"] += RISK_WEIGHTS.get(severity, 0)
        entry["reasons"].append(f"[{severity}] {reason}")
        # Track highest severity
        sev_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if sev_order.index(severity) > sev_order.index(entry["max_severity"]):
            entry["max_severity"] = severity

    def print_risk_summary(self) -> None:
        """Print service account risk summary."""
        if not self.service_account_risk:
            return

        section("SERVICE ACCOUNT RISK SUMMARY")

        sorted_accounts = sorted(
            self.service_account_risk.items(),
            key=lambda x: -x[1]["score"],
        )

        for account, data in sorted_accounts:
            sev = data["max_severity"]
            score = data["score"]
            color = severity_color(sev)
            print(
                f"  {color}{sev:<10}{Style.RESET_ALL}  "
                f"Score: {Fore.WHITE}{score:>3}{Style.RESET_ALL}  "
                f"{account}"
            )
            for reason in data["reasons"]:
                print(f"             {Fore.WHITE}{reason}{Style.RESET_ALL}")
            print()

    # ---- Source IP Analysis ----

    def analyze_source_ips(self) -> Dict[str, Dict[str, Any]]:
        """Aggregate attack activity by source IP."""
        section("ATTACKER SOURCE IP ANALYSIS")

        ip_data: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "rc4_tgs": 0,
            "asrep": 0,
            "preauth_fail": 0,
            "total": 0,
            "targeted_services": set(),
            "targeted_users": set(),
            "first_seen": None,
            "last_seen": None,
        })

        all_events = self.tgs_events + self.tgt_events + self.preauth_events
        for ev in all_events:
            ip = ev.source_ip or "unknown"
            d = ip_data[ip]
            d["total"] += 1

            ts = self._parse_ts(ev.timestamp)
            if ts:
                if d["first_seen"] is None or ts < d["first_seen"]:
                    d["first_seen"] = ts
                if d["last_seen"] is None or ts > d["last_seen"]:
                    d["last_seen"] = ts

            try:
                eid = int(ev.event_id)
            except (ValueError, TypeError):
                continue

            if eid == EID_TGS_REQUEST:
                enc = ev.ticket_encryption.strip().lower()
                if enc in RC4_ETYPES or enc in {"rc4-hmac", "rc4_hmac", "rc4"}:
                    d["rc4_tgs"] += 1
                svc = ev.service_name or ev.target_user
                if svc:
                    d["targeted_services"].add(svc)
            elif eid == EID_TGT_REQUEST:
                pat = ev.pre_auth_type.strip()
                if pat in ("0", "", "-"):
                    d["asrep"] += 1
                if ev.target_user:
                    d["targeted_users"].add(ev.target_user)
            elif eid == EID_PREAUTH_FAIL:
                d["preauth_fail"] += 1

        # Print summary
        for ip, d in sorted(ip_data.items(), key=lambda x: -(x[1]["rc4_tgs"] + x[1]["asrep"])):
            if ip == "unknown" and d["total"] == 0:
                continue
            attack_score = d["rc4_tgs"] * 3 + d["asrep"] * 3 + d["preauth_fail"]
            if attack_score == 0:
                sev = "INFO"
            elif attack_score < 5:
                sev = "LOW"
            elif attack_score < 15:
                sev = "MEDIUM"
            elif attack_score < 30:
                sev = "HIGH"
            else:
                sev = "CRITICAL"

            color = severity_color(sev)
            first = d["first_seen"].isoformat() if d["first_seen"] else "N/A"
            last = d["last_seen"].isoformat() if d["last_seen"] else "N/A"

            print(f"  {color}{sev:<10}{Style.RESET_ALL}  {Fore.WHITE}{ip}{Style.RESET_ALL}")
            print(f"             RC4 TGS: {d['rc4_tgs']}  |  AS-REP: {d['asrep']}  |  PreAuth Fail: {d['preauth_fail']}")
            print(f"             First seen: {first}")
            print(f"             Last seen:  {last}")
            if d["targeted_services"]:
                svcs = ", ".join(sorted(d["targeted_services"])[:8])
                print(f"             Services:   {svcs}")
            if d["targeted_users"]:
                users = ", ".join(sorted(d["targeted_users"])[:8])
                print(f"             Users:      {users}")
            print()

        # Convert sets to lists for JSON serialization
        result = {}
        for ip, d in ip_data.items():
            result[ip] = {
                "rc4_tgs": d["rc4_tgs"],
                "asrep": d["asrep"],
                "preauth_fail": d["preauth_fail"],
                "total": d["total"],
                "targeted_services": sorted(d["targeted_services"]),
                "targeted_users": sorted(d["targeted_users"]),
                "first_seen": d["first_seen"].isoformat() if d["first_seen"] else None,
                "last_seen": d["last_seen"].isoformat() if d["last_seen"] else None,
            }
        return result


# ---------------------------------------------------------------------------
# Active Directory Auditor (LDAP)
# ---------------------------------------------------------------------------

class ADKerberosAuditor:
    """Query Active Directory for Kerberos attack surface."""

    def __init__(
        self,
        server: str,
        username: str,
        password: str,
        use_ssl: bool = False,
        base_dn: str = "",
    ):
        self.server_addr = server
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.base_dn = base_dn
        self.conn: Optional[Any] = None
        self.spn_accounts: List[Dict[str, Any]] = []
        self.no_preauth_accounts: List[Dict[str, Any]] = []
        self.weak_crypto_accounts: List[Dict[str, Any]] = []
        self.alerts: List[Alert] = []

    def connect(self) -> bool:
        """Establish LDAP connection."""
        if not LDAP_AVAILABLE:
            warn("ldap3 library not installed. Cannot perform AD audit.")
            warn("Install with: pip install ldap3")
            return False

        try:
            port = 636 if self.use_ssl else 389
            server = Server(self.server_addr, port=port, use_ssl=self.use_ssl, get_info=ALL)

            # Detect authentication method
            if "\\" in self.username:
                # NTLM auth (DOMAIN\\user)
                self.conn = Connection(
                    server,
                    user=self.username,
                    password=self.password,
                    authentication=NTLM,
                    auto_bind=True,
                )
            else:
                self.conn = Connection(
                    server,
                    user=self.username,
                    password=self.password,
                    auto_bind=True,
                )

            # Auto-detect base DN if not provided
            if not self.base_dn and self.conn.server.info:
                naming = self.conn.server.info.naming_contexts
                if naming:
                    self.base_dn = str(naming[0])

            good(f"Connected to {self.server_addr} (Base DN: {self.base_dn})")
            return True
        except Exception as exc:
            warn(f"LDAP connection failed: {exc}")
            return False

    def _search(
        self,
        search_filter: str,
        attributes: List[str],
    ) -> List[Dict[str, Any]]:
        """Execute LDAP search and return results as list of dicts."""
        if not self.conn or not self.base_dn:
            return []
        try:
            self.conn.search(
                self.base_dn,
                search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
            )
            results = []
            for entry in self.conn.entries:
                d: Dict[str, Any] = {"dn": str(entry.entry_dn)}
                for attr in attributes:
                    try:
                        val = entry[attr].value
                        if isinstance(val, list):
                            d[attr] = [str(v) for v in val]
                        elif isinstance(val, bytes):
                            d[attr] = val.hex()
                        else:
                            d[attr] = str(val) if val is not None else ""
                    except Exception:
                        d[attr] = ""
                results.append(d)
            return results
        except Exception as exc:
            warn(f"LDAP search error: {exc}")
            return []

    def find_spn_accounts(self) -> List[Dict[str, Any]]:
        """Find all user accounts with Service Principal Names (Kerberoast targets)."""
        section("AD AUDIT: ACCOUNTS WITH SPN (KERBEROAST TARGETS)")

        # Filter: user accounts (not computer accounts) with SPN set
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"  # Not disabled
        )
        attributes = [
            "sAMAccountName", "servicePrincipalName", "pwdLastSet",
            "memberOf", "userAccountControl", "whenCreated",
            "msDS-SupportedEncryptionTypes", "description",
        ]

        results = self._search(search_filter, attributes)
        self.spn_accounts = results

        if results:
            critical(f"Found {len(results)} enabled user accounts with SPN set")
            print()

            for acct in results:
                name = acct.get("sAMAccountName", "?")
                spns = acct.get("servicePrincipalName", [])
                if isinstance(spns, str):
                    spns = [spns]
                pwd_set = acct.get("pwdLastSet", "")
                enc_types = acct.get("msDS-SupportedEncryptionTypes", "")

                # Determine risk
                risk = "HIGH"
                risk_reasons = ["Has SPN set (Kerberoastable)"]

                # Check if RC4 is supported
                try:
                    enc_int = int(enc_types) if enc_types else 0
                except (ValueError, TypeError):
                    enc_int = 0
                if enc_int == 0 or (enc_int & 0x4):  # RC4 bit
                    risk = "CRITICAL"
                    risk_reasons.append("RC4 encryption enabled/default")

                # Check password age
                pwd_age_warn = ""
                if pwd_set and pwd_set not in ("0", ""):
                    try:
                        pwd_dt = self._parse_ad_timestamp(pwd_set)
                        if pwd_dt:
                            age = (datetime.now(timezone.utc) - pwd_dt).days
                            pwd_age_warn = f"{age} days"
                            if age > 365:
                                risk = "CRITICAL"
                                risk_reasons.append(f"Password {age} days old (>{365}d)")
                            elif age > 90:
                                risk_reasons.append(f"Password {age} days old (>{90}d)")
                    except Exception:
                        pass

                color = severity_color(risk)
                print(f"  {color}{risk:<10}{Style.RESET_ALL}  {name}")
                for spn in (spns[:5] if isinstance(spns, list) else [spns]):
                    print(f"             SPN: {spn}")
                if pwd_age_warn:
                    print(f"             Password age: {pwd_age_warn}")
                if enc_types:
                    print(f"             Encryption types: {enc_types}")
                for r in risk_reasons:
                    print(f"             -> {r}")
                print()

                self.alerts.append(Alert(
                    severity=risk,
                    attack_type="Kerberoast Target (AD Audit)",
                    description=(
                        f"Account '{name}' has SPN set and is vulnerable to Kerberoasting. "
                        f"Reasons: {'; '.join(risk_reasons)}"
                    ),
                    target_account=name,
                    evidence=[f"SPN: {s}" for s in (spns[:5] if isinstance(spns, list) else [spns])],
                    mitre_id="T1558.003",
                    finding_id="CRIT-CBE-10",
                    recommendation=(
                        "1. Convert to gMSA if possible\n"
                        "2. Set msDS-SupportedEncryptionTypes to AES-only (0x18)\n"
                        "3. Enforce 25+ character random password\n"
                        "4. Rotate password every 30 days\n"
                        "5. Minimize group memberships and privileges"
                    ),
                ))
        else:
            good("No enabled user accounts with SPN found (low Kerberoast risk)")

        return results

    def find_no_preauth_accounts(self) -> List[Dict[str, Any]]:
        """Find accounts with Kerberos pre-authentication disabled (AS-REP targets)."""
        section("AD AUDIT: ACCOUNTS WITHOUT PRE-AUTH (AS-REP TARGETS)")

        # UAC flag 0x400000 = DONT_REQUIRE_PREAUTH
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        attributes = [
            "sAMAccountName", "pwdLastSet", "memberOf",
            "userAccountControl", "whenCreated", "description",
        ]

        results = self._search(search_filter, attributes)
        self.no_preauth_accounts = results

        if results:
            critical(
                f"Found {len(results)} enabled accounts with pre-authentication DISABLED"
            )
            print()

            for acct in results:
                name = acct.get("sAMAccountName", "?")
                desc = acct.get("description", "")
                pwd_set = acct.get("pwdLastSet", "")

                pwd_age_warn = ""
                try:
                    pwd_dt = self._parse_ad_timestamp(pwd_set)
                    if pwd_dt:
                        age = (datetime.now(timezone.utc) - pwd_dt).days
                        pwd_age_warn = f"{age} days"
                except Exception:
                    pass

                print(
                    f"  {Fore.RED}CRITICAL  {Style.RESET_ALL}  {name}"
                    f"  {Fore.WHITE}({desc}){Style.RESET_ALL}"
                )
                if pwd_age_warn:
                    print(f"             Password age: {pwd_age_warn}")
                print(
                    f"             {Fore.RED}-> DONT_REQUIRE_PREAUTH is SET{Style.RESET_ALL}"
                )
                print()

                self.alerts.append(Alert(
                    severity="CRITICAL",
                    attack_type="AS-REP Roast Target (AD Audit)",
                    description=(
                        f"Account '{name}' has Kerberos pre-authentication disabled "
                        f"(DONT_REQUIRE_PREAUTH). Any user can request an AS-REP for "
                        f"this account and crack the password offline."
                    ),
                    target_account=name,
                    evidence=["userAccountControl includes DONT_REQUIRE_PREAUTH (0x400000)"],
                    mitre_id="T1558.004",
                    finding_id="CRIT-AWB-09",
                    recommendation=(
                        "1. ENABLE pre-authentication immediately (clear DONT_REQUIRE_PREAUTH)\n"
                        "2. Reset the account password\n"
                        "3. Audit why pre-auth was disabled\n"
                        "4. Monitor for AS-REP requests targeting this account"
                    ),
                ))
        else:
            good("No accounts with pre-authentication disabled found")

        return results

    def find_weak_encryption_accounts(self) -> List[Dict[str, Any]]:
        """Find accounts configured with weak encryption types."""
        section("AD AUDIT: WEAK ENCRYPTION TYPES")

        # Accounts with DES or RC4 explicitly enabled
        # msDS-SupportedEncryptionTypes with DES (0x1, 0x2) or RC4 (0x4)
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(msDS-SupportedEncryptionTypes=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        attributes = [
            "sAMAccountName", "msDS-SupportedEncryptionTypes",
            "userAccountControl", "servicePrincipalName",
        ]

        results = self._search(search_filter, attributes)

        weak_accounts = []
        for acct in results:
            enc_raw = acct.get("msDS-SupportedEncryptionTypes", "0")
            try:
                enc_val = int(enc_raw)
            except (ValueError, TypeError):
                continue

            # Decode encryption flags
            flags = []
            if enc_val & 0x1:
                flags.append("DES-CBC-CRC")
            if enc_val & 0x2:
                flags.append("DES-CBC-MD5")
            if enc_val & 0x4:
                flags.append("RC4-HMAC")
            if enc_val & 0x8:
                flags.append("AES128-CTS")
            if enc_val & 0x10:
                flags.append("AES256-CTS")

            is_weak = bool(enc_val & 0x7)  # DES or RC4 bits
            if is_weak:
                acct["_enc_flags"] = flags
                acct["_enc_value"] = enc_val
                weak_accounts.append(acct)

        self.weak_crypto_accounts = weak_accounts

        if weak_accounts:
            warn(f"Found {len(weak_accounts)} accounts with weak encryption types enabled")
            print()
            for acct in weak_accounts:
                name = acct.get("sAMAccountName", "?")
                flags = acct.get("_enc_flags", [])
                has_spn = bool(acct.get("servicePrincipalName"))

                sev = "CRITICAL" if has_spn else "HIGH"
                color = severity_color(sev)

                print(
                    f"  {color}{sev:<10}{Style.RESET_ALL}  {name}  "
                    f"Encryption: {', '.join(flags)}"
                    f"{'  [HAS SPN]' if has_spn else ''}"
                )
        else:
            good("No accounts with explicitly weak encryption types found")

        return weak_accounts

    @staticmethod
    def _parse_ad_timestamp(ts_str: str) -> Optional[datetime]:
        """Parse AD timestamp (Windows FILETIME or ISO string)."""
        if not ts_str or ts_str in ("0", "None"):
            return None

        # Try as Windows FILETIME (100-ns intervals since 1601-01-01)
        try:
            ft = int(ts_str)
            if ft > 100000000000000:  # Looks like FILETIME
                epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                delta = timedelta(microseconds=ft // 10)
                return epoch + delta
        except (ValueError, OverflowError):
            pass

        # Try common date formats
        for fmt in [
            "%Y%m%d%H%M%S.0Z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]:
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self.conn:
            try:
                self.conn.unbind()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Wazuh Rule Generator
# ---------------------------------------------------------------------------

class WazuhRuleGenerator:
    """Generate Wazuh detection rules for Kerberos attacks."""

    @staticmethod
    def generate(
        burst_count: int = DEFAULT_BURST_COUNT,
        burst_window: int = DEFAULT_BURST_WINDOW,
    ) -> str:
        """Generate Wazuh XML rules for Kerberos attack detection."""

        rules = f"""<!--
  HAKA AI - Kerberos Attack Detection Rules
  Generated: {datetime.now(timezone.utc).isoformat()}

  Deploy to: /var/ossec/etc/rules/kerberos_attack_rules.xml
  Restart Wazuh manager after deployment: systemctl restart wazuh-manager
-->

<group name="kerberos_attack,">

  <!-- ============================================================ -->
  <!-- Rule 100550: Kerberoasting - RC4 TGS Ticket Request          -->
  <!-- MITRE: T1558.003 | Finding: CRIT-CBE-10                      -->
  <!-- ============================================================ -->
  <rule id="100550" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">4769</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>Kerberoasting: TGS ticket requested with RC4 encryption (0x17). Service: $(win.eventdata.serviceName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <options>no_full_log</options>
    <group>kerberoasting,credential_access,</group>
  </rule>

  <!-- ============================================================ -->
  <!-- Rule 100551: Kerberoasting Burst - Mass RC4 TGS Requests     -->
  <!-- MITRE: T1558.003 | Finding: CRIT-CBE-10                      -->
  <!-- Triggers when {burst_count}+ RC4 TGS from same IP in {burst_window}s     -->
  <!-- ============================================================ -->
  <rule id="100551" level="14" frequency="{burst_count}" timeframe="{burst_window}">
    <if_matched_sid>100550</if_matched_sid>
    <same_source_ip />
    <description>Kerberoasting BURST: $(win.eventdata.ipAddress) sent {burst_count}+ RC4 TGS requests in {burst_window}s — likely automated Kerberoasting tool (Rubeus/Impacket)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
    <group>kerberoasting,credential_access,active_response,</group>
  </rule>

  <!-- ============================================================ -->
  <!-- Rule 100555: AS-REP Roasting - No Pre-Authentication         -->
  <!-- MITRE: T1558.004 | Finding: CRIT-AWB-09                      -->
  <!-- ============================================================ -->
  <rule id="100555" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">4768</field>
    <field name="win.eventdata.preAuthType">0</field>
    <description>AS-REP Roasting: TGT requested without pre-authentication for $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
    <options>no_full_log</options>
    <group>asrep_roasting,credential_access,</group>
  </rule>

  <!-- ============================================================ -->
  <!-- Rule 100556: AS-REP Enumeration Burst                        -->
  <!-- MITRE: T1558.004 | Finding: CRIT-AWB-09                      -->
  <!-- ============================================================ -->
  <rule id="100556" level="14" frequency="5" timeframe="30">
    <if_matched_sid>100555</if_matched_sid>
    <same_source_ip />
    <description>AS-REP Roasting ENUMERATION: $(win.eventdata.ipAddress) querying multiple accounts without pre-auth — automated user enumeration detected</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
    <group>asrep_roasting,credential_access,active_response,</group>
  </rule>

  <!-- ============================================================ -->
  <!-- Rule 100557: Kerberos Pre-Auth Failure Spray                 -->
  <!-- MITRE: T1110.003 | Supplementary detection                   -->
  <!-- ============================================================ -->
  <rule id="100557" level="10" frequency="15" timeframe="120">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">4771</field>
    <same_source_ip />
    <description>Kerberos pre-auth failure spray from $(win.eventdata.ipAddress) — possible password spraying alongside Kerberos attacks</description>
    <mitre>
      <id>T1110.003</id>
    </mitre>
    <group>kerberos_preauth,credential_access,</group>
  </rule>

</group>
"""
        return rules


# ---------------------------------------------------------------------------
# Report Builder
# ---------------------------------------------------------------------------

class ReportBuilder:
    """Build and save the JSON report."""

    def __init__(self) -> None:
        self.data: Dict[str, Any] = {
            "tool": "HAKA AI - Kerberos Attack Detector",
            "version": VERSION,
            "mitre_techniques": ["T1558.003", "T1558.004"],
            "findings": ["CRIT-CBE-10", "CRIT-AWB-09"],
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "summary": {},
            "alerts": [],
            "kerberoasting": {},
            "asrep_roasting": {},
            "source_ip_analysis": {},
            "service_account_risk": {},
            "ad_audit": {},
            "wazuh_rules": {},
            "remediation": {},
        }

    def set_summary(
        self,
        total_events: int,
        tgs_events: int,
        tgt_events: int,
        preauth_events: int,
        total_alerts: int,
        critical_count: int,
        high_count: int,
    ) -> None:
        self.data["summary"] = {
            "total_kerberos_events": total_events,
            "tgs_requests_4769": tgs_events,
            "tgt_requests_4768": tgt_events,
            "preauth_failures_4771": preauth_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical_count,
            "high_alerts": high_count,
            "risk_level": (
                "CRITICAL" if critical_count > 0
                else "HIGH" if high_count > 0
                else "LOW"
            ),
        }

    def add_alerts(self, alerts: List[Alert]) -> None:
        for a in alerts:
            self.data["alerts"].append(a.to_dict())

    def set_source_ip_analysis(self, analysis: Dict[str, Any]) -> None:
        self.data["source_ip_analysis"] = analysis

    def set_service_risk(self, risk: Dict[str, Dict[str, Any]]) -> None:
        self.data["service_account_risk"] = risk

    def set_ad_audit(
        self,
        spn_accounts: List[Dict[str, Any]],
        no_preauth: List[Dict[str, Any]],
        weak_crypto: List[Dict[str, Any]],
    ) -> None:
        # Clean up internal keys before serialization
        clean_weak = []
        for acct in weak_crypto:
            clean = {k: v for k, v in acct.items() if not k.startswith("_")}
            clean["weak_flags"] = acct.get("_enc_flags", [])
            clean_weak.append(clean)

        self.data["ad_audit"] = {
            "spn_accounts_kerberoastable": len(spn_accounts),
            "spn_account_details": spn_accounts,
            "no_preauth_accounts_asrep": len(no_preauth),
            "no_preauth_account_details": no_preauth,
            "weak_encryption_accounts": len(weak_crypto),
            "weak_encryption_details": clean_weak,
        }

    def set_wazuh_rules(self, rules_xml: str, rules_file: str) -> None:
        self.data["wazuh_rules"] = {
            "rules_file": rules_file,
            "rule_ids": [100550, 100551, 100555, 100556, 100557],
            "deployment_path": "/var/ossec/etc/rules/kerberos_attack_rules.xml",
        }

    def set_remediation(self) -> None:
        self.data["remediation"] = {
            "kerberoasting_mitigations": [
                "Convert service accounts to Group Managed Service Accounts (gMSA)",
                "Set msDS-SupportedEncryptionTypes to 0x18 (AES-only) on all SPN accounts",
                "Enforce 25+ character random passwords on service accounts",
                "Rotate service account passwords every 30 days",
                "Minimize service account privileges (least privilege)",
                "Deploy honeypot SPN accounts for early detection",
                "Monitor Event ID 4769 for RC4 encryption type requests",
            ],
            "asrep_roasting_mitigations": [
                "Enable Kerberos pre-authentication on ALL accounts",
                "Audit and clear DONT_REQUIRE_PREAUTH flag domain-wide",
                "Reset passwords for any account that had pre-auth disabled",
                "Monitor Event ID 4768 for PreAuthType=0 requests",
                "Implement fine-grained password policies for sensitive accounts",
            ],
            "general_hardening": [
                "Disable DES and RC4 encryption domain-wide via Group Policy",
                "Enable AES 256-bit encryption for Kerberos",
                "Configure Kerberos logging: Audit Kerberos Authentication Service + Ticket Operations",
                "Deploy Wazuh rules for real-time detection (rules 100550-100557)",
                "Implement tiered admin model to limit credential exposure",
                "Regular AD security assessments using this tool in audit mode",
            ],
        }

    def save(self, output_dir: Optional[str] = None) -> str:
        """Save report to JSON file and return the file path."""
        report_dir = Path(output_dir) if output_dir else REPORTS_DIR
        report_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"kerberos_detect_{timestamp}.json"
        filepath = report_dir / filename

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=2, default=str)

        return str(filepath)


# ---------------------------------------------------------------------------
# Alert Timeline Printer
# ---------------------------------------------------------------------------

def print_alert_timeline(alerts: List[Alert]) -> None:
    """Print alerts as a chronological timeline."""
    section("ALERT TIMELINE")

    if not alerts:
        good("No alerts generated. Environment appears clean.")
        return

    # Sort by severity weight (descending) then timestamp
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_alerts = sorted(
        alerts,
        key=lambda a: (sev_order.get(a.severity, 5), a.timestamp),
    )

    for i, alert in enumerate(sorted_alerts, 1):
        color = severity_color(alert.severity)
        print(
            f"  {color}[{alert.severity}]{Style.RESET_ALL}  "
            f"{Fore.WHITE}#{i}{Style.RESET_ALL}  "
            f"{alert.attack_type}"
        )
        print(f"    {alert.description}")
        if alert.source_ip:
            print(f"    Source IP:  {alert.source_ip}")
        if alert.target_account:
            print(f"    Target:     {alert.target_account}")
        if alert.mitre_id:
            print(f"    MITRE:      {alert.mitre_id}  |  Finding: {alert.finding_id}")
        if alert.evidence:
            for ev in alert.evidence[:3]:
                print(f"    Evidence:   {ev}")
        if alert.recommendation:
            lines = alert.recommendation.strip().split("\n")
            print(f"    Remediation:")
            for line in lines[:4]:
                print(f"      {line.strip()}")
        print()

    # Stats
    crit = sum(1 for a in alerts if a.severity == "CRITICAL")
    high = sum(1 for a in alerts if a.severity == "HIGH")
    med = sum(1 for a in alerts if a.severity == "MEDIUM")

    print(
        f"  Total: {len(alerts)} alerts  |  "
        f"{Fore.RED}CRITICAL: {crit}{Style.RESET_ALL}  |  "
        f"{Fore.LIGHTRED_EX}HIGH: {high}{Style.RESET_ALL}  |  "
        f"{Fore.YELLOW}MEDIUM: {med}{Style.RESET_ALL}"
    )


# ---------------------------------------------------------------------------
# Remediation Summary
# ---------------------------------------------------------------------------

def print_remediation() -> None:
    """Print remediation recommendations."""
    section("REMEDIATION RECOMMENDATIONS")

    print(f"  {Fore.RED}--- Kerberoasting (T1558.003 / CRIT-CBE-10) ---{Style.RESET_ALL}")
    print()
    recs = [
        "Convert service accounts to gMSA (Group Managed Service Accounts)",
        "Set msDS-SupportedEncryptionTypes = 0x18 (AES-only) on all SPN accounts",
        "Enforce 25+ character random passwords on all service accounts",
        "Rotate service account passwords every 30 days",
        "Minimize service account privileges and group memberships",
        "Deploy honeypot SPN accounts for early warning",
    ]
    for i, r in enumerate(recs, 1):
        print(f"    {i}. {r}")

    print()
    print(f"  {Fore.RED}--- AS-REP Roasting (T1558.004 / CRIT-AWB-09) ---{Style.RESET_ALL}")
    print()
    recs2 = [
        "Enable Kerberos pre-authentication on ALL user accounts",
        "Audit DONT_REQUIRE_PREAUTH flag domain-wide (clear it everywhere)",
        "Reset passwords for any account that had pre-auth disabled",
        "Implement fine-grained password policies for sensitive accounts",
    ]
    for i, r in enumerate(recs2, 1):
        print(f"    {i}. {r}")

    print()
    print(f"  {Fore.CYAN}--- General Kerberos Hardening ---{Style.RESET_ALL}")
    print()
    recs3 = [
        "Disable DES and RC4 encryption domain-wide via Group Policy",
        "Enable AES 256-bit encryption for all Kerberos operations",
        "Audit logging: enable Kerberos Authentication Service + Ticket Operations",
        "Deploy Wazuh rules 100550-100557 for real-time detection",
        "Implement tiered admin model to limit credential exposure",
        "Schedule regular AD Kerberos audits using --audit-only mode",
    ]
    for i, r in enumerate(recs3, 1):
        print(f"    {i}. {r}")
    print()


# ---------------------------------------------------------------------------
# CLI / Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="haka_kerberos_detector",
        description=(
            "HAKA AI - Kerberos Attack Detector\n"
            "Detects Kerberoasting (T1558.003) and AS-REP Roasting (T1558.004)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --evtx Security.evtx\n"
            "  %(prog)s --evtx Security.evtx --ldap-server 192.168.122.210 "
            "--ldap-user 'HAKA\\administrator' --ldap-pass 'Password123!'\n"
            "  %(prog)s --audit-only --ldap-server 192.168.122.210 "
            "--ldap-user 'HAKA\\administrator' --ldap-pass 'Password123!'\n"
            "  %(prog)s --evtx logs.csv --burst-count 5 --burst-window 30\n"
        ),
    )

    # Input sources
    inp = p.add_argument_group("Input Sources")
    inp.add_argument(
        "--evtx", metavar="FILE",
        help="Path to Windows Security EVTX file (or CSV export)",
    )
    inp.add_argument(
        "--csv", metavar="FILE",
        help="Path to CSV export of security events (alias for --evtx with CSV)",
    )
    inp.add_argument(
        "--audit-only", action="store_true",
        help="Skip log analysis; only perform AD audit via LDAP",
    )

    # LDAP / AD
    ldap_grp = p.add_argument_group("Active Directory (LDAP)")
    ldap_grp.add_argument("--ldap-server", metavar="HOST", help="LDAP server address")
    ldap_grp.add_argument("--ldap-user", metavar="USER", help="LDAP bind username (DOMAIN\\\\user or DN)")
    ldap_grp.add_argument("--ldap-pass", metavar="PASS", help="LDAP bind password")
    ldap_grp.add_argument("--ldap-ssl", action="store_true", help="Use LDAPS (port 636)")
    ldap_grp.add_argument("--base-dn", metavar="DN", default="", help="LDAP base DN (auto-detected if omitted)")

    # Detection thresholds
    thresh = p.add_argument_group("Detection Thresholds")
    thresh.add_argument(
        "--burst-count", type=int, default=DEFAULT_BURST_COUNT,
        help=f"Min RC4 TGS requests for burst alert (default: {DEFAULT_BURST_COUNT})",
    )
    thresh.add_argument(
        "--burst-window", type=int, default=DEFAULT_BURST_WINDOW,
        help=f"Burst time window in seconds (default: {DEFAULT_BURST_WINDOW})",
    )
    thresh.add_argument(
        "--enum-count", type=int, default=DEFAULT_ENUM_COUNT,
        help=f"Min unique users for enumeration alert (default: {DEFAULT_ENUM_COUNT})",
    )
    thresh.add_argument(
        "--enum-window", type=int, default=DEFAULT_ENUM_WINDOW,
        help=f"Enumeration time window in seconds (default: {DEFAULT_ENUM_WINDOW})",
    )

    # Output
    out = p.add_argument_group("Output")
    out.add_argument(
        "--output-dir", metavar="DIR",
        help=f"Report output directory (default: {REPORTS_DIR})",
    )
    out.add_argument(
        "--wazuh-rules", metavar="FILE",
        help="Also write Wazuh rules XML to this file",
    )
    out.add_argument(
        "--json-only", action="store_true",
        help="Suppress console output; only write JSON report",
    )
    out.add_argument(
        "--no-banner", action="store_true",
        help="Suppress the banner",
    )

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Validate arguments
    if not args.evtx and not args.csv and not args.audit_only:
        parser.error(
            "Provide --evtx <file>, --csv <file>, or --audit-only.\n"
            "Run with --help for usage examples."
        )

    if args.audit_only and not args.ldap_server:
        parser.error("--audit-only requires --ldap-server, --ldap-user, --ldap-pass")

    if not args.no_banner:
        banner()

    report = ReportBuilder()
    all_alerts: List[Alert] = []

    # ----------------------------------------------------------------
    # Phase 1: Log Analysis
    # ----------------------------------------------------------------

    analyzer = KerberosAnalyzer(
        burst_count=args.burst_count,
        burst_window=args.burst_window,
        enum_count=args.enum_count,
        enum_window=args.enum_window,
    )

    if not args.audit_only:
        log_file = args.evtx or args.csv
        if not log_file:
            parser.error("Provide --evtx or --csv for log analysis")

        section("PHASE 1: LOG ANALYSIS")
        info(f"Input file: {log_file}")

        events = KerberosLogParser.parse(log_file)

        if not events:
            warn("No Kerberos events found in the log file.")
            if not args.ldap_server:
                warn("No events to analyze and no LDAP server specified. Exiting.")
                # Still generate a minimal report
                report.set_summary(0, 0, 0, 0, 0, 0, 0)
                report.set_remediation()
                filepath = report.save(args.output_dir)
                info(f"Report saved: {filepath}")
                return
        else:
            analyzer.ingest(events)

            # Run detections
            analyzer.detect_kerberoasting()
            analyzer.detect_asrep_roasting()

            # Source IP analysis
            ip_analysis = analyzer.analyze_source_ips()
            report.set_source_ip_analysis(ip_analysis)

            # Risk summary
            analyzer.print_risk_summary()
            report.set_service_risk(analyzer.service_account_risk)

            all_alerts.extend(analyzer.alerts)

    # ----------------------------------------------------------------
    # Phase 2: Active Directory Audit (if LDAP credentials provided)
    # ----------------------------------------------------------------

    ad_auditor = None
    if args.ldap_server:
        section("PHASE 2: ACTIVE DIRECTORY AUDIT")

        if not LDAP_AVAILABLE:
            warn("ldap3 library not installed. Skipping AD audit.")
            warn("Install with: pip install ldap3")
        elif not args.ldap_user or not args.ldap_pass:
            warn("LDAP credentials not provided. Skipping AD audit.")
            warn("Use --ldap-user and --ldap-pass")
        else:
            ad_auditor = ADKerberosAuditor(
                server=args.ldap_server,
                username=args.ldap_user,
                password=args.ldap_pass,
                use_ssl=args.ldap_ssl,
                base_dn=args.base_dn,
            )

            if ad_auditor.connect():
                spn_accounts = ad_auditor.find_spn_accounts()
                no_preauth = ad_auditor.find_no_preauth_accounts()
                weak_crypto = ad_auditor.find_weak_encryption_accounts()

                report.set_ad_audit(spn_accounts, no_preauth, weak_crypto)
                all_alerts.extend(ad_auditor.alerts)

                ad_auditor.disconnect()
            else:
                warn("Could not connect to AD. Skipping audit phase.")

    # ----------------------------------------------------------------
    # Phase 3: Wazuh Rule Generation
    # ----------------------------------------------------------------

    section("PHASE 3: WAZUH RULE GENERATION")

    wazuh_xml = WazuhRuleGenerator.generate(
        burst_count=args.burst_count,
        burst_window=args.burst_window,
    )

    wazuh_file = ""
    if args.wazuh_rules:
        wazuh_file = args.wazuh_rules
        try:
            Path(wazuh_file).parent.mkdir(parents=True, exist_ok=True)
            with open(wazuh_file, "w", encoding="utf-8") as fh:
                fh.write(wazuh_xml)
            good(f"Wazuh rules written to: {wazuh_file}")
        except Exception as exc:
            warn(f"Failed to write Wazuh rules: {exc}")
    else:
        # Default location
        wazuh_dir = REPORTS_DIR
        wazuh_dir.mkdir(parents=True, exist_ok=True)
        wazuh_file = str(wazuh_dir / "kerberos_wazuh_rules.xml")
        try:
            with open(wazuh_file, "w", encoding="utf-8") as fh:
                fh.write(wazuh_xml)
            good(f"Wazuh rules written to: {wazuh_file}")
        except Exception as exc:
            warn(f"Failed to write Wazuh rules: {exc}")

    info("Generated Wazuh rules:")
    info("  100550 - Kerberoasting: RC4 TGS request (Level 12)")
    info("  100551 - Kerberoasting: Mass RC4 TGS burst (Level 14)")
    info("  100555 - AS-REP Roasting: No pre-auth TGT (Level 12)")
    info("  100556 - AS-REP Roasting: Enumeration burst (Level 14)")
    info("  100557 - Kerberos pre-auth failure spray (Level 10)")
    info(f"  Deploy to: /var/ossec/etc/rules/kerberos_attack_rules.xml")

    report.set_wazuh_rules(wazuh_xml, wazuh_file)

    # ----------------------------------------------------------------
    # Phase 4: Alert Timeline & Report
    # ----------------------------------------------------------------

    print_alert_timeline(all_alerts)
    print_remediation()

    # Build summary
    total_events = len(analyzer.tgs_events) + len(analyzer.tgt_events) + len(analyzer.preauth_events)
    crit_count = sum(1 for a in all_alerts if a.severity == "CRITICAL")
    high_count = sum(1 for a in all_alerts if a.severity == "HIGH")

    report.set_summary(
        total_events=total_events,
        tgs_events=len(analyzer.tgs_events),
        tgt_events=len(analyzer.tgt_events),
        preauth_events=len(analyzer.preauth_events),
        total_alerts=len(all_alerts),
        critical_count=crit_count,
        high_count=high_count,
    )
    report.add_alerts(all_alerts)
    report.set_remediation()

    filepath = report.save(args.output_dir)

    # ----------------------------------------------------------------
    # Final Summary
    # ----------------------------------------------------------------

    section("SCAN COMPLETE")

    risk = "CRITICAL" if crit_count > 0 else "HIGH" if high_count > 0 else "LOW"
    risk_color = severity_color(risk)

    print(f"  Overall Risk Level:  {risk_color}{risk}{Style.RESET_ALL}")
    print(f"  Total Events Parsed: {total_events}")
    print(f"  Total Alerts:        {len(all_alerts)}")
    print(
        f"    {Fore.RED}CRITICAL: {crit_count}{Style.RESET_ALL}  |  "
        f"{Fore.LIGHTRED_EX}HIGH: {high_count}{Style.RESET_ALL}  |  "
        f"{Fore.YELLOW}MEDIUM: {sum(1 for a in all_alerts if a.severity == 'MEDIUM')}{Style.RESET_ALL}"
    )
    print()
    good(f"JSON report saved: {filepath}")
    good(f"Wazuh rules saved: {wazuh_file}")
    print()

    if crit_count > 0:
        critical(
            "CRITICAL findings detected. Immediate action required — "
            "review the alert timeline and remediation recommendations above."
        )
    elif high_count > 0:
        warn(
            "HIGH-severity findings detected. Review recommendations and "
            "prioritize remediation."
        )
    else:
        good("No critical Kerberos attack indicators found. Environment appears hardened.")


if __name__ == "__main__":
    main()
