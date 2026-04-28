#!/usr/bin/env python3
"""
HAKA AI - Password Spray Detector (Tool 4: B2 - Password Spray T1110.003)

Analyzes Windows Event Logs (EVTX / CSV) to detect password spraying attacks:
  - Event 4625 (Failed logon), 4624 (Successful logon), 4648 (Explicit cred)
  - Spray pattern recognition: same source -> many users in a time window
  - OWA / IIS-specific spray detection (LogonType 8, 3+NTLM, auth.owa POSTs)
  - Timeline visualization, suspicion scoring, Wazuh rule generation

Findings: CRIT-CBE-01, CRIT-CBE-12, CRIT-AWB-01, CRIT-BOA-05

Author:  HAKA AI Framework
Version: 1.0.0
"""

import argparse
import csv
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

try:
    import pandas as pd
except ImportError:
    sys.exit(
        "[!] pandas is required.  Install it:\n"
        "    pip install pandas"
    )

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    sys.exit(
        "[!] colorama is required.  Install it:\n"
        "    pip install colorama"
    )

# Optional: python-evtx for native EVTX parsing
try:
    import Evtx.Evtx as evtx
    import Evtx.Views as evtx_views
    HAS_EVTX = True
except ImportError:
    HAS_EVTX = False

# Optional: lxml for EVTX XML parsing
try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    try:
        import xml.etree.ElementTree as etree  # type: ignore[no-redef]
        HAS_LXML = False
    except ImportError:
        HAS_LXML = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
REPORTS_DIR = Path("/home/kironix/HAKA-AI/reports")

# Windows Security Event IDs of interest
EVENT_FAILED_LOGON = 4625
EVENT_SUCCESS_LOGON = 4624
EVENT_EXPLICIT_CRED = 4648

# Default thresholds
DEFAULT_THRESHOLD = 5        # minimum distinct users from one source
DEFAULT_WINDOW = 300         # seconds (5 minutes)
DEFAULT_SINGLE_USER_THRESHOLD = 10  # failed logins for MEDIUM alert on single user
DEFAULT_INTERVAL_TOLERANCE = 0.25   # 25% variance for automated-tool detection

# Logon type mapping (Windows)
LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

# Risk weights for scoring
RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# Windows Event Log XML namespaces
EVTX_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

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


def _header(text: str) -> str:
    return f"\n  {Fore.CYAN}{Style.BRIGHT}{text}{Style.RESET_ALL}"


def _subheader(text: str) -> str:
    return f"  {Fore.WHITE}{Style.BRIGHT}{text}{Style.RESET_ALL}"


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
        f"  {Fore.WHITE}Password Spray Detector v{VERSION} "
        f"| B2 - Password Spray (T1110.003){Style.RESET_ALL}\n"
    )


# ---------------------------------------------------------------------------
# EVTX parsing
# ---------------------------------------------------------------------------

def _extract_evtx_field(xml_node, field_name: str, ns: dict) -> Optional[str]:
    """Extract a named Data field from an EVTX XML event record."""
    # Try EventData/Data[@Name='field']
    xpath = f".//e:EventData/e:Data[@Name='{field_name}']"
    node = xml_node.find(xpath, ns)
    if node is not None and node.text:
        return node.text.strip()
    # Fallback: try without namespace (some exports strip it)
    xpath_no_ns = f".//EventData/Data[@Name='{field_name}']"
    node = xml_node.find(xpath_no_ns)
    if node is not None and node.text:
        return node.text.strip()
    return None


def parse_evtx_file(filepath: str) -> pd.DataFrame:
    """Parse a Windows EVTX file into a DataFrame of logon events."""
    if not HAS_EVTX:
        print(
            f"  {Fore.YELLOW}[!] python-evtx not installed. "
            f"Falling back to CSV mode.{Style.RESET_ALL}"
        )
        raise ImportError("python-evtx not available")

    records = []
    event_ids_of_interest = {EVENT_FAILED_LOGON, EVENT_SUCCESS_LOGON, EVENT_EXPLICIT_CRED}

    print(f"  {Fore.WHITE}[*] Parsing EVTX file: {filepath}{Style.RESET_ALL}")

    with evtx.Evtx(filepath) as log:
        record_count = 0
        matched_count = 0
        for record in log.records():
            record_count += 1
            try:
                xml_str = record.xml()
                root = etree.fromstring(xml_str.encode("utf-8") if isinstance(xml_str, str) else xml_str)

                # Extract EventID
                event_id_node = root.find(".//e:System/e:EventID", EVTX_NS)
                if event_id_node is None:
                    event_id_node = root.find(".//System/EventID")
                if event_id_node is None or event_id_node.text is None:
                    continue

                event_id = int(event_id_node.text)
                if event_id not in event_ids_of_interest:
                    continue

                matched_count += 1

                # Extract timestamp
                time_node = root.find(".//e:System/e:TimeCreated", EVTX_NS)
                if time_node is None:
                    time_node = root.find(".//System/TimeCreated")
                timestamp_str = None
                if time_node is not None:
                    timestamp_str = time_node.get("SystemTime")

                # Extract relevant fields
                target_user = _extract_evtx_field(root, "TargetUserName", EVTX_NS) or ""
                target_domain = _extract_evtx_field(root, "TargetDomainName", EVTX_NS) or ""
                source_ip = _extract_evtx_field(root, "IpAddress", EVTX_NS) or ""
                source_port = _extract_evtx_field(root, "IpPort", EVTX_NS) or ""
                logon_type_str = _extract_evtx_field(root, "LogonType", EVTX_NS) or ""
                status = _extract_evtx_field(root, "Status", EVTX_NS) or ""
                sub_status = _extract_evtx_field(root, "SubStatus", EVTX_NS) or ""
                failure_reason = _extract_evtx_field(root, "FailureReason", EVTX_NS) or ""
                workstation = _extract_evtx_field(root, "WorkstationName", EVTX_NS) or ""
                auth_package = _extract_evtx_field(root, "AuthenticationPackageName", EVTX_NS) or ""
                lm_package = _extract_evtx_field(root, "LmPackageName", EVTX_NS) or ""
                process_name = _extract_evtx_field(root, "ProcessName", EVTX_NS) or ""

                # Parse logon type
                logon_type = 0
                if logon_type_str.isdigit():
                    logon_type = int(logon_type_str)

                # Parse timestamp
                timestamp = None
                if timestamp_str:
                    for fmt in (
                        "%Y-%m-%dT%H:%M:%S.%fZ",
                        "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S.%f",
                        "%Y-%m-%d %H:%M:%S",
                    ):
                        try:
                            timestamp = datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
                            break
                        except ValueError:
                            continue

                # Normalize source IP: strip "-" and "::1" / "127.0.0.1" as local
                if source_ip in ("-", "::1", "127.0.0.1", ""):
                    source_ip = "LOCAL"

                # Skip machine accounts (end with $) unless they're interesting
                if target_user.endswith("$"):
                    continue

                records.append({
                    "timestamp": timestamp,
                    "event_id": event_id,
                    "target_user": target_user.lower(),
                    "target_domain": target_domain.upper(),
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "logon_type": logon_type,
                    "logon_type_name": LOGON_TYPES.get(logon_type, f"Unknown({logon_type})"),
                    "status": status,
                    "sub_status": sub_status,
                    "failure_reason": failure_reason,
                    "workstation": workstation,
                    "auth_package": auth_package,
                    "lm_package": lm_package,
                    "process_name": process_name,
                })

            except Exception:
                continue

    print(
        f"  {Fore.WHITE}[*] Parsed {record_count} total records, "
        f"{matched_count} logon events, {len(records)} after filtering{Style.RESET_ALL}"
    )

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    return df


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

# Expected CSV columns (flexible matching)
CSV_COLUMN_MAP = {
    "timestamp": ["timestamp", "time", "datetime", "timecreated", "date", "eventtime", "system_time"],
    "event_id": ["event_id", "eventid", "id", "event"],
    "target_user": ["target_user", "targetusername", "username", "user", "account", "targetuser", "target_username"],
    "target_domain": ["target_domain", "targetdomainname", "domain", "targetdomain"],
    "source_ip": ["source_ip", "ipaddress", "ip", "src_ip", "sourceip", "source_address", "client_ip"],
    "source_port": ["source_port", "ipport", "port", "src_port", "sourceport"],
    "logon_type": ["logon_type", "logontype", "type"],
    "status": ["status", "status_code"],
    "sub_status": ["sub_status", "substatus"],
    "failure_reason": ["failure_reason", "failurereason", "reason"],
    "workstation": ["workstation", "workstationname", "hostname", "computer"],
    "auth_package": ["auth_package", "authenticationpackagename", "authpackage", "authentication"],
    "lm_package": ["lm_package", "lmpackagename"],
    "process_name": ["process_name", "processname", "process"],
}


def _map_csv_columns(header: list[str]) -> dict[str, str]:
    """Map CSV header columns to our canonical field names."""
    header_lower = [h.strip().lower().replace(" ", "_") for h in header]
    mapping = {}
    for canonical, aliases in CSV_COLUMN_MAP.items():
        for alias in aliases:
            if alias in header_lower:
                idx = header_lower.index(alias)
                mapping[canonical] = header[idx].strip()
                break
    return mapping


def parse_csv_file(filepath: str) -> pd.DataFrame:
    """Parse a CSV file of logon events into a DataFrame."""
    print(f"  {Fore.WHITE}[*] Parsing CSV file: {filepath}{Style.RESET_ALL}")

    # Detect delimiter
    with open(filepath, "r", encoding="utf-8-sig", errors="replace") as fh:
        sample = fh.read(4096)
    sniffer = csv.Sniffer()
    try:
        dialect = sniffer.sniff(sample)
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ","

    df_raw = pd.read_csv(filepath, delimiter=delimiter, encoding="utf-8-sig",
                         on_bad_lines="skip", dtype=str)
    df_raw.columns = df_raw.columns.str.strip()

    col_map = _map_csv_columns(list(df_raw.columns))

    if "event_id" not in col_map and "target_user" not in col_map:
        print(
            f"  {Fore.RED}[!] CSV does not contain recognizable columns. "
            f"Expected at least 'EventID' or 'TargetUserName'.{Style.RESET_ALL}"
        )
        print(f"  {Fore.YELLOW}    Found columns: {list(df_raw.columns)}{Style.RESET_ALL}")
        return pd.DataFrame()

    records = []
    event_ids_of_interest = {str(EVENT_FAILED_LOGON), str(EVENT_SUCCESS_LOGON), str(EVENT_EXPLICIT_CRED)}

    for _, row in df_raw.iterrows():
        # Event ID filter
        event_id_str = str(row.get(col_map.get("event_id", ""), "")).strip()
        if event_id_str and event_id_str not in event_ids_of_interest:
            continue

        event_id = int(event_id_str) if event_id_str.isdigit() else 0

        # Timestamp
        ts_str = str(row.get(col_map.get("timestamp", ""), "")).strip()
        timestamp = _parse_timestamp(ts_str)

        # Fields
        target_user = str(row.get(col_map.get("target_user", ""), "")).strip().lower()
        target_domain = str(row.get(col_map.get("target_domain", ""), "")).strip().upper()
        source_ip = str(row.get(col_map.get("source_ip", ""), "")).strip()
        source_port = str(row.get(col_map.get("source_port", ""), "")).strip()
        logon_type_str = str(row.get(col_map.get("logon_type", ""), "0")).strip()
        logon_type = int(logon_type_str) if logon_type_str.isdigit() else 0
        status = str(row.get(col_map.get("status", ""), "")).strip()
        sub_status = str(row.get(col_map.get("sub_status", ""), "")).strip()
        failure_reason = str(row.get(col_map.get("failure_reason", ""), "")).strip()
        workstation = str(row.get(col_map.get("workstation", ""), "")).strip()
        auth_package = str(row.get(col_map.get("auth_package", ""), "")).strip()
        lm_package = str(row.get(col_map.get("lm_package", ""), "")).strip()
        process_name = str(row.get(col_map.get("process_name", ""), "")).strip()

        # Normalize
        if source_ip in ("-", "::1", "127.0.0.1", "", "nan", "None"):
            source_ip = "LOCAL"
        if target_user in ("nan", "none", "-", ""):
            continue
        if target_user.endswith("$"):
            continue

        records.append({
            "timestamp": timestamp,
            "event_id": event_id,
            "target_user": target_user,
            "target_domain": target_domain if target_domain not in ("NAN", "NONE", "") else "",
            "source_ip": source_ip,
            "source_port": source_port,
            "logon_type": logon_type,
            "logon_type_name": LOGON_TYPES.get(logon_type, f"Unknown({logon_type})"),
            "status": status,
            "sub_status": sub_status,
            "failure_reason": failure_reason,
            "workstation": workstation,
            "auth_package": auth_package,
            "lm_package": lm_package,
            "process_name": process_name,
        })

    print(
        f"  {Fore.WHITE}[*] Loaded {len(df_raw)} rows, "
        f"{len(records)} logon events after filtering{Style.RESET_ALL}"
    )

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    return df


def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Try multiple timestamp formats and return a datetime or None."""
    if not ts_str or ts_str in ("nan", "None", "NaT", ""):
        return None
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # Last resort: pandas
    try:
        dt = pd.to_datetime(ts_str, utc=True)
        return dt.to_pydatetime()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# IIS log parsing (for OWA detection)
# ---------------------------------------------------------------------------

def parse_iis_log(filepath: str) -> pd.DataFrame:
    """Parse IIS W3C log for OWA authentication patterns."""
    print(f"  {Fore.WHITE}[*] Parsing IIS log: {filepath}{Style.RESET_ALL}")

    records = []
    headers = None

    with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("#Fields:"):
                headers = line.replace("#Fields:", "").strip().split()
                continue
            if line.startswith("#") or not line:
                continue
            if headers is None:
                continue

            fields = line.split()
            if len(fields) != len(headers):
                continue

            row = dict(zip(headers, fields))

            # Only interested in OWA auth endpoints
            cs_uri = row.get("cs-uri-stem", "")
            cs_method = row.get("cs-method", "")
            if not any(pattern in cs_uri.lower() for pattern in (
                "/owa/auth", "/owa/auth.owa", "/ecp/", "/autodiscover",
                "/mapi/", "/ews/", "/oab/", "/rpc/",
            )):
                continue

            date_str = row.get("date", "")
            time_str = row.get("time", "")
            timestamp = _parse_timestamp(f"{date_str} {time_str}") if date_str and time_str else None

            source_ip = row.get("c-ip", "")
            status_code = row.get("sc-status", "")
            cs_username = row.get("cs-username", "-")
            user_agent = row.get("cs(User-Agent)", "")

            is_failed = status_code in ("401", "403")

            records.append({
                "timestamp": timestamp,
                "event_id": EVENT_FAILED_LOGON if is_failed else EVENT_SUCCESS_LOGON,
                "target_user": cs_username.lower() if cs_username != "-" else "",
                "target_domain": "",
                "source_ip": source_ip,
                "source_port": "",
                "logon_type": 8,  # NetworkCleartext for OWA
                "logon_type_name": "NetworkCleartext",
                "status": status_code,
                "sub_status": "",
                "failure_reason": f"HTTP {status_code}",
                "workstation": "",
                "auth_package": "OWA/IIS",
                "lm_package": "",
                "process_name": "",
                "uri": cs_uri,
                "method": cs_method,
                "user_agent": user_agent,
            })

    print(
        f"  {Fore.WHITE}[*] Found {len(records)} OWA/Exchange auth "
        f"requests in IIS log{Style.RESET_ALL}"
    )

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df.sort_values("timestamp", inplace=True, ignore_index=True)
    return df


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class SprayDetector:
    """Core detection engine for password spray analysis."""

    def __init__(
        self,
        df: pd.DataFrame,
        threshold: int = DEFAULT_THRESHOLD,
        window: int = DEFAULT_WINDOW,
        single_user_threshold: int = DEFAULT_SINGLE_USER_THRESHOLD,
    ):
        self.df = df
        self.threshold = threshold
        self.window = window
        self.window_td = timedelta(seconds=window)
        self.single_user_threshold = single_user_threshold
        self.alerts: list[dict[str, Any]] = []
        self.compromised_accounts: list[dict[str, Any]] = []
        self.attacker_ips: dict[str, dict[str, Any]] = {}
        self.spray_sessions: list[dict[str, Any]] = []

    def run_all_detections(self) -> None:
        """Execute the full detection pipeline."""
        if self.df.empty:
            print(f"  {Fore.YELLOW}[!] No events to analyze.{Style.RESET_ALL}")
            return

        print(_header("Running Detection Engines"))
        print(f"  {'=' * 60}")

        self._detect_spray_by_source()
        self._detect_success_after_spray()
        self._detect_single_user_brute_force()
        self._detect_automated_tool_timing()
        self._detect_owa_spray()
        self._detect_ntlm_relay_patterns()
        self._build_attacker_profiles()

    # ----- Detection: spray from same source IP -----

    def _detect_spray_by_source(self) -> None:
        """Detect same source IP trying multiple usernames within a time window."""
        print(f"\n  {Fore.WHITE}[*] Analyzing spray patterns by source IP...{Style.RESET_ALL}")

        failed = self.df[self.df["event_id"] == EVENT_FAILED_LOGON].copy()
        if failed.empty:
            print(f"  {Fore.GREEN}    No failed logon events found.{Style.RESET_ALL}")
            return

        # Drop events without timestamps or source IPs
        failed = failed.dropna(subset=["timestamp"])
        failed = failed[failed["source_ip"] != "LOCAL"]
        if failed.empty:
            return

        # Group by source IP
        grouped = failed.groupby("source_ip")

        for source_ip, group in grouped:
            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].tolist()
            users = group["target_user"].tolist()

            # Sliding window analysis
            i = 0
            while i < len(timestamps):
                window_end = timestamps[i] + self.window_td
                j = i
                window_users = set()
                window_events = []

                while j < len(timestamps) and timestamps[j] <= window_end:
                    window_users.add(users[j])
                    window_events.append({
                        "timestamp": timestamps[j].isoformat() if timestamps[j] else "",
                        "user": users[j],
                    })
                    j += 1

                if len(window_users) >= self.threshold:
                    session = {
                        "source_ip": source_ip,
                        "start_time": timestamps[i].isoformat() if timestamps[i] else "",
                        "end_time": timestamps[j - 1].isoformat() if timestamps[j - 1] else "",
                        "unique_users": len(window_users),
                        "total_attempts": j - i,
                        "users_targeted": sorted(window_users),
                        "duration_seconds": (timestamps[j - 1] - timestamps[i]).total_seconds() if timestamps[j - 1] and timestamps[i] else 0,
                    }
                    self.spray_sessions.append(session)

                    self.alerts.append({
                        "severity": "HIGH",
                        "detection": "SPRAY_PATTERN",
                        "message": (
                            f"Password spray detected: {source_ip} targeted "
                            f"{len(window_users)} unique users with {j - i} "
                            f"attempts in {session['duration_seconds']:.0f}s"
                        ),
                        "source_ip": source_ip,
                        "unique_users": len(window_users),
                        "total_attempts": j - i,
                        "time_window": f"{timestamps[i]} -> {timestamps[j - 1]}",
                        "users": sorted(window_users),
                    })

                    # Skip past this window to avoid duplicate alerts
                    i = j
                else:
                    i += 1

        spray_count = len(self.spray_sessions)
        if spray_count:
            print(
                f"  {Fore.RED}    Found {spray_count} spray "
                f"session(s)!{Style.RESET_ALL}"
            )
        else:
            print(f"  {Fore.GREEN}    No spray patterns detected.{Style.RESET_ALL}")

    # ----- Detection: success after spray (compromised account) -----

    def _detect_success_after_spray(self) -> None:
        """Detect a successful logon from a spray source IP -- compromised account."""
        print(f"\n  {Fore.WHITE}[*] Checking for successful logons after spray...{Style.RESET_ALL}")

        if not self.spray_sessions:
            return

        success = self.df[self.df["event_id"] == EVENT_SUCCESS_LOGON].copy()
        if success.empty:
            return

        success = success.dropna(subset=["timestamp"])
        spray_ips = {s["source_ip"] for s in self.spray_sessions}

        for _, row in success.iterrows():
            if row["source_ip"] in spray_ips:
                # Check if success came after a spray session from this IP
                for session in self.spray_sessions:
                    if session["source_ip"] != row["source_ip"]:
                        continue

                    session_end = datetime.fromisoformat(session["end_time"]) if session["end_time"] else None
                    if session_end and row["timestamp"] and row["timestamp"] >= session_end:
                        compromised = {
                            "username": row["target_user"],
                            "domain": row.get("target_domain", ""),
                            "source_ip": row["source_ip"],
                            "logon_time": row["timestamp"].isoformat() if row["timestamp"] else "",
                            "logon_type": row.get("logon_type", 0),
                            "logon_type_name": row.get("logon_type_name", ""),
                            "spray_session_end": session["end_time"],
                            "time_after_spray_seconds": (
                                (row["timestamp"] - session_end).total_seconds()
                                if row["timestamp"] and session_end else 0
                            ),
                        }

                        # Avoid duplicates
                        dup_key = (compromised["username"], compromised["source_ip"])
                        if not any(
                            (c["username"], c["source_ip"]) == dup_key
                            for c in self.compromised_accounts
                        ):
                            self.compromised_accounts.append(compromised)
                            self.alerts.append({
                                "severity": "CRITICAL",
                                "detection": "SPRAY_SUCCESS",
                                "message": (
                                    f"COMPROMISED ACCOUNT: '{row['target_user']}' -- "
                                    f"successful logon from spray source {row['source_ip']} "
                                    f"at {compromised['logon_time']} "
                                    f"({compromised['time_after_spray_seconds']:.0f}s after spray)"
                                ),
                                "username": row["target_user"],
                                "source_ip": row["source_ip"],
                                "logon_time": compromised["logon_time"],
                            })
                        break

        if self.compromised_accounts:
            print(
                f"  {Fore.RED}{Style.BRIGHT}    CRITICAL: {len(self.compromised_accounts)} "
                f"potentially compromised account(s)!{Style.RESET_ALL}"
            )
        else:
            print(f"  {Fore.GREEN}    No post-spray successes detected.{Style.RESET_ALL}")

    # ----- Detection: brute force on single user -----

    def _detect_single_user_brute_force(self) -> None:
        """Detect multiple failed logins for a single user (traditional brute force)."""
        print(f"\n  {Fore.WHITE}[*] Checking single-user brute force...{Style.RESET_ALL}")

        failed = self.df[self.df["event_id"] == EVENT_FAILED_LOGON].copy()
        if failed.empty:
            return

        user_counts = failed.groupby("target_user").size()
        flagged = user_counts[user_counts >= self.single_user_threshold]

        for user, count in flagged.items():
            user_events = failed[failed["target_user"] == user]
            source_ips = user_events["source_ip"].unique().tolist()

            self.alerts.append({
                "severity": "MEDIUM",
                "detection": "BRUTE_FORCE_SINGLE_USER",
                "message": (
                    f"Multiple failed logins for user '{user}': "
                    f"{count} failures from {len(source_ips)} source(s)"
                ),
                "username": str(user),
                "failure_count": int(count),
                "source_ips": source_ips,
            })

        if flagged.empty:
            print(f"  {Fore.GREEN}    No single-user brute force detected.{Style.RESET_ALL}")
        else:
            print(
                f"  {Fore.YELLOW}    {len(flagged)} user(s) with "
                f">={self.single_user_threshold} failed logins.{Style.RESET_ALL}"
            )

    # ----- Detection: automated tool timing patterns -----

    def _detect_automated_tool_timing(self) -> None:
        """Detect regular intervals between attempts indicating automated tools."""
        print(f"\n  {Fore.WHITE}[*] Analyzing timing patterns for tool signatures...{Style.RESET_ALL}")

        failed = self.df[self.df["event_id"] == EVENT_FAILED_LOGON].copy()
        if failed.empty:
            return

        failed = failed.dropna(subset=["timestamp"])
        failed = failed[failed["source_ip"] != "LOCAL"]

        grouped = failed.groupby("source_ip")
        automated_sources = []

        for source_ip, group in grouped:
            if len(group) < 5:
                continue

            group = group.sort_values("timestamp")
            timestamps = group["timestamp"].tolist()

            # Calculate intervals between consecutive attempts
            intervals = []
            for k in range(1, len(timestamps)):
                delta = (timestamps[k] - timestamps[k - 1]).total_seconds()
                if 0 < delta < 600:  # ignore gaps > 10 min
                    intervals.append(delta)

            if len(intervals) < 4:
                continue

            # Check for regularity: low coefficient of variation
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                continue

            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            cv = std_dev / mean_interval  # coefficient of variation

            if cv <= DEFAULT_INTERVAL_TOLERANCE:
                automated_sources.append({
                    "source_ip": source_ip,
                    "mean_interval": round(mean_interval, 2),
                    "std_dev": round(std_dev, 2),
                    "cv": round(cv, 4),
                    "attempt_count": len(group),
                })

                self.alerts.append({
                    "severity": "HIGH",
                    "detection": "AUTOMATED_TOOL",
                    "message": (
                        f"Automated tool signature from {source_ip}: "
                        f"mean interval {mean_interval:.1f}s "
                        f"(std_dev={std_dev:.2f}, CV={cv:.3f}) "
                        f"over {len(group)} attempts"
                    ),
                    "source_ip": source_ip,
                    "mean_interval": round(mean_interval, 2),
                    "coefficient_of_variation": round(cv, 4),
                })

        if automated_sources:
            print(
                f"  {Fore.RED}    {len(automated_sources)} source(s) show "
                f"automated tool timing!{Style.RESET_ALL}"
            )
        else:
            print(f"  {Fore.GREEN}    No automated timing patterns found.{Style.RESET_ALL}")

    # ----- Detection: OWA-specific spray -----

    def _detect_owa_spray(self) -> None:
        """Detect OWA/IIS-specific spray patterns (LogonType 8 = NetworkCleartext)."""
        print(f"\n  {Fore.WHITE}[*] Checking OWA/Exchange-specific patterns...{Style.RESET_ALL}")

        # LogonType 8 = NetworkCleartext (OWA basic auth, cleartext over HTTPS)
        owa_events = self.df[self.df["logon_type"] == 8].copy()

        if not owa_events.empty:
            failed_owa = owa_events[owa_events["event_id"] == EVENT_FAILED_LOGON]
            if not failed_owa.empty:
                source_counts = failed_owa.groupby("source_ip")["target_user"].nunique()
                spray_sources = source_counts[source_counts >= self.threshold]

                for source_ip, user_count in spray_sources.items():
                    total_attempts = len(failed_owa[failed_owa["source_ip"] == source_ip])
                    self.alerts.append({
                        "severity": "HIGH",
                        "detection": "OWA_SPRAY",
                        "message": (
                            f"OWA spray (LogonType 8/NetworkCleartext): "
                            f"{source_ip} targeted {user_count} users "
                            f"({total_attempts} total attempts) -- "
                            f"credentials sent in cleartext over network"
                        ),
                        "source_ip": str(source_ip),
                        "unique_users": int(user_count),
                        "total_attempts": int(total_attempts),
                        "logon_type": 8,
                    })

                if not spray_sources.empty:
                    print(
                        f"  {Fore.RED}    {len(spray_sources)} OWA spray "
                        f"source(s) detected!{Style.RESET_ALL}"
                    )
                    return

        print(f"  {Fore.GREEN}    No OWA-specific spray patterns.{Style.RESET_ALL}")

    # ----- Detection: NTLM relay patterns -----

    def _detect_ntlm_relay_patterns(self) -> None:
        """Detect LogonType 3 + NTLM which may indicate relay attacks."""
        print(f"\n  {Fore.WHITE}[*] Checking for NTLM relay indicators...{Style.RESET_ALL}")

        ntlm_net = self.df[
            (self.df["logon_type"] == 3) &
            (self.df["auth_package"].str.upper().isin(["NTLM", "NTLMSSP"]))
        ].copy()

        if ntlm_net.empty:
            print(f"  {Fore.GREEN}    No NTLM network logon events.{Style.RESET_ALL}")
            return

        failed_ntlm = ntlm_net[ntlm_net["event_id"] == EVENT_FAILED_LOGON]
        if failed_ntlm.empty:
            return

        source_counts = failed_ntlm.groupby("source_ip")["target_user"].nunique()
        relay_suspects = source_counts[source_counts >= 3]

        for source_ip, user_count in relay_suspects.items():
            self.alerts.append({
                "severity": "MEDIUM",
                "detection": "NTLM_RELAY_INDICATOR",
                "message": (
                    f"Potential NTLM relay: {source_ip} with "
                    f"{user_count} failed NTLM network logons (LogonType 3) -- "
                    f"investigate for relay/pass-the-hash"
                ),
                "source_ip": str(source_ip),
                "unique_users": int(user_count),
            })

        if not relay_suspects.empty:
            print(
                f"  {Fore.YELLOW}    {len(relay_suspects)} potential NTLM "
                f"relay source(s).{Style.RESET_ALL}"
            )
        else:
            print(f"  {Fore.GREEN}    No NTLM relay indicators.{Style.RESET_ALL}")

    # ----- Build attacker profiles with suspicion scores -----

    def _build_attacker_profiles(self) -> None:
        """Build suspicion scores for all source IPs."""
        print(f"\n  {Fore.WHITE}[*] Building attacker profiles...{Style.RESET_ALL}")

        failed = self.df[self.df["event_id"] == EVENT_FAILED_LOGON]
        success = self.df[self.df["event_id"] == EVENT_SUCCESS_LOGON]

        all_ips = set(failed["source_ip"].unique()) | set(success["source_ip"].unique())
        all_ips.discard("LOCAL")

        for ip in all_ips:
            ip_failed = failed[failed["source_ip"] == ip]
            ip_success = success[success["source_ip"] == ip]

            total_failures = len(ip_failed)
            total_successes = len(ip_success)
            unique_users_failed = ip_failed["target_user"].nunique()
            unique_users_success = ip_success["target_user"].nunique()

            # Suspicion score calculation (0-100)
            score = 0.0

            # Factor 1: Number of unique users targeted (spray breadth)
            if unique_users_failed >= self.threshold:
                score += min(30, unique_users_failed * 3)

            # Factor 2: Failure-to-success ratio
            if total_failures > 0:
                ratio = total_failures / max(total_successes, 1)
                score += min(20, ratio * 2)

            # Factor 3: Success after failures (compromise indicator)
            if total_failures > self.threshold and total_successes > 0:
                score += 25

            # Factor 4: Volume of attempts
            score += min(15, total_failures / 5)

            # Factor 5: Associated alerts
            ip_alerts = [a for a in self.alerts if a.get("source_ip") == ip]
            for alert in ip_alerts:
                score += RISK_WEIGHTS.get(alert["severity"], 0)

            score = min(100, round(score, 1))

            # Logon types observed
            logon_types_seen = ip_failed["logon_type"].unique().tolist()

            self.attacker_ips[ip] = {
                "source_ip": ip,
                "suspicion_score": score,
                "total_failures": int(total_failures),
                "total_successes": int(total_successes),
                "unique_users_failed": int(unique_users_failed),
                "unique_users_success": int(unique_users_success),
                "logon_types": [int(lt) for lt in logon_types_seen],
                "alert_count": len(ip_alerts),
            }

        print(
            f"  {Fore.WHITE}    Profiled {len(self.attacker_ips)} "
            f"source IP(s).{Style.RESET_ALL}"
        )


# ---------------------------------------------------------------------------
# Timeline Visualization (text-based)
# ---------------------------------------------------------------------------

def render_timeline(df: pd.DataFrame, alerts: list[dict], max_width: int = 70) -> str:
    """Generate a text-based timeline chart of logon events."""
    if df.empty:
        return "  (No events to display)"

    events_with_ts = df.dropna(subset=["timestamp"]).copy()
    if events_with_ts.empty:
        return "  (No timestamped events)"

    min_time = events_with_ts["timestamp"].min()
    max_time = events_with_ts["timestamp"].max()
    total_span = (max_time - min_time).total_seconds()

    if total_span <= 0:
        return "  (All events at the same timestamp)"

    # Bucket events into time slots
    num_buckets = min(max_width, max(10, int(total_span / 60)))  # ~1 bucket/min
    bucket_size = total_span / num_buckets

    failed_buckets = [0] * num_buckets
    success_buckets = [0] * num_buckets
    alert_times = set()

    for _, row in events_with_ts.iterrows():
        offset = (row["timestamp"] - min_time).total_seconds()
        bucket_idx = min(int(offset / bucket_size), num_buckets - 1)
        if row["event_id"] == EVENT_FAILED_LOGON:
            failed_buckets[bucket_idx] += 1
        elif row["event_id"] == EVENT_SUCCESS_LOGON:
            success_buckets[bucket_idx] += 1

    # Mark alert times
    for alert in alerts:
        tw = alert.get("time_window", "")
        if " -> " in tw:
            try:
                start_str = tw.split(" -> ")[0]
                start_dt = datetime.fromisoformat(start_str)
                offset = (start_dt - min_time).total_seconds()
                bucket_idx = min(int(offset / bucket_size), num_buckets - 1)
                alert_times.add(bucket_idx)
            except (ValueError, IndexError):
                pass

    max_val = max(max(failed_buckets), max(success_buckets), 1)
    chart_height = 12

    lines = []
    lines.append("")
    lines.append(f"  {Fore.CYAN}{Style.BRIGHT}Event Timeline{Style.RESET_ALL}")
    lines.append(f"  {'=' * (num_buckets + 10)}")
    lines.append(
        f"  Time range: {min_time.strftime('%Y-%m-%d %H:%M')} to "
        f"{max_time.strftime('%Y-%m-%d %H:%M')} "
        f"({total_span / 60:.0f} min)"
    )
    lines.append(f"  Bucket size: {bucket_size:.0f}s | Max events/bucket: {max_val}")
    lines.append("")

    # Render rows top-down
    for row_idx in range(chart_height, 0, -1):
        threshold_val = (row_idx / chart_height) * max_val
        row_chars = []
        for b in range(num_buckets):
            f_val = failed_buckets[b]
            s_val = success_buckets[b]
            if f_val >= threshold_val and s_val >= threshold_val:
                row_chars.append(f"{Fore.YELLOW}X{Style.RESET_ALL}")
            elif f_val >= threshold_val:
                if b in alert_times:
                    row_chars.append(f"{Fore.RED}{Style.BRIGHT}!{Style.RESET_ALL}")
                else:
                    row_chars.append(f"{Fore.RED}#{Style.RESET_ALL}")
            elif s_val >= threshold_val:
                row_chars.append(f"{Fore.GREEN}o{Style.RESET_ALL}")
            else:
                row_chars.append(" ")

        label = f"{threshold_val:>5.0f}"
        lines.append(f"  {label} |{''.join(row_chars)}|")

    # X-axis
    lines.append(f"  {'':>5} +{'-' * num_buckets}+")

    # Time labels
    start_label = min_time.strftime("%H:%M")
    end_label = max_time.strftime("%H:%M")
    padding = num_buckets - len(start_label) - len(end_label)
    if padding > 0:
        lines.append(f"  {'':>6}{start_label}{' ' * padding}{end_label}")
    else:
        lines.append(f"  {'':>6}{start_label}")

    # Legend
    lines.append("")
    lines.append(
        f"  Legend: {Fore.RED}#{Style.RESET_ALL}=Failed  "
        f"{Fore.GREEN}o{Style.RESET_ALL}=Success  "
        f"{Fore.YELLOW}X{Style.RESET_ALL}=Both  "
        f"{Fore.RED}{Style.BRIGHT}!{Style.RESET_ALL}=Spray alert"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Wazuh Rule Generation
# ---------------------------------------------------------------------------

def generate_wazuh_rules(
    detector: SprayDetector,
    threshold: int,
    window: int,
) -> str:
    """Generate Wazuh custom rules XML based on detected patterns."""
    rules = []

    rules.append('<!-- HAKA AI - Auto-generated Wazuh rules for Password Spray Detection -->')
    rules.append(f'<!-- Generated: {datetime.now(timezone.utc).isoformat()} -->')
    rules.append(f'<!-- Threshold: {threshold} users | Window: {window}s -->')
    rules.append(f'<!-- Based on analysis of {len(detector.df)} events -->')
    rules.append('')
    rules.append('<group name="haka_spray_detection,">')
    rules.append('')

    rule_id = 100500  # starting custom rule ID

    # Rule 1: Multiple failed logins from same source IP
    rules.append(f'  <!-- Rule: Password spray - multiple users from same source -->')
    rules.append(f'  <rule id="{rule_id}" level="10" frequency="{threshold}" timeframe="{window}">')
    rules.append(f'    <if_matched_sid>60122</if_matched_sid>  <!-- Windows: Logon failure -->')
    rules.append(f'    <same_source_ip />')
    rules.append(f'    <different_user />')
    rules.append(f'    <description>HAKA: Password spray detected - $(srcip) targeting multiple accounts (T1110.003)</description>')
    rules.append(f'    <mitre>')
    rules.append(f'      <id>T1110.003</id>')
    rules.append(f'    </mitre>')
    rules.append(f'    <group>authentication_failures,attack,credential_access,</group>')
    rules.append(f'  </rule>')
    rules.append('')
    rule_id += 1

    # Rule 2: Successful logon after spray
    rules.append(f'  <!-- Rule: Successful logon after spray (compromised account) -->')
    rules.append(f'  <rule id="{rule_id}" level="14">')
    rules.append(f'    <if_matched_sid>{rule_id - 1}</if_matched_sid>')
    rules.append(f'    <same_source_ip />')
    rules.append(f'    <id>4624</id>')
    rules.append(f'    <description>HAKA CRITICAL: Successful logon after password spray from $(srcip) - possible account compromise (T1110.003)</description>')
    rules.append(f'    <mitre>')
    rules.append(f'      <id>T1110.003</id>')
    rules.append(f'      <id>T1078</id>')
    rules.append(f'    </mitre>')
    rules.append(f'    <group>authentication_success,attack,credential_access,</group>')
    rules.append(f'  </rule>')
    rules.append('')
    rule_id += 1

    # Rule 3: OWA spray (LogonType 8)
    rules.append(f'  <!-- Rule: OWA/Exchange spray (NetworkCleartext) -->')
    rules.append(f'  <rule id="{rule_id}" level="12" frequency="{threshold}" timeframe="{window}">')
    rules.append(f'    <if_sid>60122</if_sid>')
    rules.append(f'    <field name="win.eventdata.logonType">^8$</field>')
    rules.append(f'    <same_source_ip />')
    rules.append(f'    <different_user />')
    rules.append(f'    <description>HAKA: OWA password spray (LogonType 8/NetworkCleartext) from $(srcip) (T1110.003)</description>')
    rules.append(f'    <mitre>')
    rules.append(f'      <id>T1110.003</id>')
    rules.append(f'      <id>T1078</id>')
    rules.append(f'    </mitre>')
    rules.append(f'    <group>authentication_failures,web,attack,</group>')
    rules.append(f'  </rule>')
    rules.append('')
    rule_id += 1

    # Rule 4: NTLM relay indicator
    rules.append(f'  <!-- Rule: NTLM relay indicator (LogonType 3 + NTLM failures) -->')
    rules.append(f'  <rule id="{rule_id}" level="10" frequency="3" timeframe="{window}">')
    rules.append(f'    <if_sid>60122</if_sid>')
    rules.append(f'    <field name="win.eventdata.logonType">^3$</field>')
    rules.append(f'    <field name="win.eventdata.authenticationPackageName">NTLM</field>')
    rules.append(f'    <same_source_ip />')
    rules.append(f'    <different_user />')
    rules.append(f'    <description>HAKA: Potential NTLM relay - multiple NTLM network auth failures from $(srcip)</description>')
    rules.append(f'    <mitre>')
    rules.append(f'      <id>T1557.001</id>')
    rules.append(f'    </mitre>')
    rules.append(f'    <group>authentication_failures,attack,lateral_movement,</group>')
    rules.append(f'  </rule>')
    rules.append('')
    rule_id += 1

    # Rule 5: Brute force on single user
    rules.append(f'  <!-- Rule: Brute force on single user -->')
    rules.append(f'  <rule id="{rule_id}" level="10" frequency="{detector.single_user_threshold}" timeframe="{window * 2}">')
    rules.append(f'    <if_matched_sid>60122</if_matched_sid>')
    rules.append(f'    <same_user />')
    rules.append(f'    <description>HAKA: Brute force detected - $(data.win.eventdata.targetUserName) with multiple failures (T1110.001)</description>')
    rules.append(f'    <mitre>')
    rules.append(f'      <id>T1110.001</id>')
    rules.append(f'    </mitre>')
    rules.append(f'    <group>authentication_failures,attack,credential_access,</group>')
    rules.append(f'  </rule>')
    rules.append('')
    rule_id += 1

    # Add IP-specific rules for known attacker IPs
    top_attackers = sorted(
        detector.attacker_ips.values(),
        key=lambda x: x["suspicion_score"],
        reverse=True,
    )[:10]

    if top_attackers and any(a["suspicion_score"] > 30 for a in top_attackers):
        rules.append(f'  <!-- IP-specific watchlist rules (from detected spray sources) -->')
        for attacker in top_attackers:
            if attacker["suspicion_score"] <= 30:
                continue
            ip = attacker["source_ip"]
            rules.append(f'  <rule id="{rule_id}" level="12">')
            rules.append(f'    <if_sid>60122,60103</if_sid>')
            rules.append(f'    <srcip>{ip}</srcip>')
            rules.append(f'    <description>HAKA: Known spray source {ip} (suspicion score: {attacker["suspicion_score"]}) - any auth activity</description>')
            rules.append(f'    <group>attack,credential_access,</group>')
            rules.append(f'  </rule>')
            rules.append('')
            rule_id += 1

    rules.append('</group>')

    return "\n".join(rules)


# ---------------------------------------------------------------------------
# Output and Reporting
# ---------------------------------------------------------------------------

def print_alerts(alerts: list[dict]) -> None:
    """Print all alerts sorted by severity."""
    if not alerts:
        print(f"\n  {Fore.GREEN}{Style.BRIGHT}No alerts generated.{Style.RESET_ALL}")
        return

    print(_header("Detection Alerts"))
    print(f"  {'=' * 60}")

    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, INFO
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_alerts = sorted(alerts, key=lambda a: severity_order.get(a["severity"], 5))

    severity_counts = Counter(a["severity"] for a in sorted_alerts)

    for alert in sorted_alerts:
        print(_tag(alert["severity"], alert["message"]))

    print(f"\n  {'-' * 60}")
    print(
        f"  Totals: "
        f"{Fore.RED}{Style.BRIGHT}{severity_counts.get('CRITICAL', 0)} Critical{Style.RESET_ALL}, "
        f"{Fore.RED}{severity_counts.get('HIGH', 0)} High{Style.RESET_ALL}, "
        f"{Fore.YELLOW}{severity_counts.get('MEDIUM', 0)} Medium{Style.RESET_ALL}, "
        f"{Fore.CYAN}{severity_counts.get('LOW', 0)} Low{Style.RESET_ALL}"
    )


def print_compromised_accounts(accounts: list[dict]) -> None:
    """Print compromised accounts table."""
    if not accounts:
        return

    print(_header("COMPROMISED ACCOUNTS"))
    print(f"  {'=' * 60}")
    print(
        f"  {Fore.RED}{Style.BRIGHT}The following accounts were successfully "
        f"authenticated from spray sources:{Style.RESET_ALL}\n"
    )

    header = f"  {'Username':<25} {'Source IP':<18} {'Logon Time':<22} {'Type':<15}"
    print(f"  {Style.BRIGHT}{header}{Style.RESET_ALL}")
    print(f"  {'-' * 80}")

    for acct in accounts:
        logon_time = acct.get("logon_time", "N/A")
        if len(logon_time) > 20:
            logon_time = logon_time[:19]
        print(
            f"  {Fore.RED}{acct['username']:<25}{Style.RESET_ALL} "
            f"{acct['source_ip']:<18} {logon_time:<22} "
            f"{acct.get('logon_type_name', 'N/A'):<15}"
        )

    print(f"\n  {Fore.RED}{Style.BRIGHT}ACTION REQUIRED: "
          f"Reset passwords and revoke sessions immediately!{Style.RESET_ALL}")


def print_attacker_ips(attacker_ips: dict[str, dict]) -> None:
    """Print attacker IPs ranked by suspicion score."""
    if not attacker_ips:
        return

    print(_header("Source IP Suspicion Ranking"))
    print(f"  {'=' * 60}")

    sorted_ips = sorted(
        attacker_ips.values(),
        key=lambda x: x["suspicion_score"],
        reverse=True,
    )

    header = (
        f"  {'IP Address':<18} {'Score':>6} {'Failures':>9} "
        f"{'Successes':>10} {'Users':>6} {'Alerts':>7}"
    )
    print(f"\n  {Style.BRIGHT}{header}{Style.RESET_ALL}")
    print(f"  {'-' * 70}")

    for entry in sorted_ips[:25]:  # top 25
        score = entry["suspicion_score"]
        if score >= 60:
            color = Fore.RED + Style.BRIGHT
        elif score >= 30:
            color = Fore.RED
        elif score >= 15:
            color = Fore.YELLOW
        else:
            color = Fore.WHITE

        print(
            f"  {color}{entry['source_ip']:<18}{Style.RESET_ALL} "
            f"{color}{score:>5.0f}{Style.RESET_ALL}  "
            f"{entry['total_failures']:>8}  "
            f"{entry['total_successes']:>9}  "
            f"{entry['unique_users_failed']:>5}  "
            f"{entry['alert_count']:>6}"
        )


def print_event_stats(df: pd.DataFrame) -> None:
    """Print summary statistics of the loaded events."""
    if df.empty:
        return

    print(_header("Event Statistics"))
    print(f"  {'=' * 60}")

    total = len(df)
    failed = len(df[df["event_id"] == EVENT_FAILED_LOGON])
    success = len(df[df["event_id"] == EVENT_SUCCESS_LOGON])
    explicit = len(df[df["event_id"] == EVENT_EXPLICIT_CRED])

    print(f"  Total logon events:      {total}")
    print(f"  Failed logons (4625):    {failed}")
    print(f"  Successful logons (4624):{success}")
    print(f"  Explicit cred (4648):    {explicit}")

    unique_users = df["target_user"].nunique()
    unique_ips = df[df["source_ip"] != "LOCAL"]["source_ip"].nunique()
    print(f"  Unique usernames:        {unique_users}")
    print(f"  Unique source IPs:       {unique_ips}")

    ts_valid = df.dropna(subset=["timestamp"])
    if not ts_valid.empty:
        min_time = ts_valid["timestamp"].min()
        max_time = ts_valid["timestamp"].max()
        span = (max_time - min_time).total_seconds()
        print(f"  Time range:              {min_time} to {max_time}")
        print(f"  Duration:                {span / 3600:.1f} hours ({span / 60:.0f} min)")

    # Logon type breakdown
    if "logon_type" in df.columns:
        lt_counts = df["logon_type"].value_counts()
        lt_strs = []
        for lt, count in lt_counts.items():
            name = LOGON_TYPES.get(int(lt), f"Type{lt}")
            lt_strs.append(f"{name}({lt})={count}")
        if lt_strs:
            print(f"  Logon types:             {', '.join(lt_strs[:8])}")


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def write_report(
    detector: SprayDetector,
    threshold: int,
    window: int,
    input_file: str,
    wazuh_rules: Optional[str],
    output_path: Path,
) -> Path:
    """Write JSON report and return the file path."""
    severity_counts = Counter(a["severity"] for a in detector.alerts)

    # Determine overall risk
    if severity_counts.get("CRITICAL", 0) > 0:
        overall_risk = "CRITICAL"
    elif severity_counts.get("HIGH", 0) > 0:
        overall_risk = "HIGH"
    elif severity_counts.get("MEDIUM", 0) > 0:
        overall_risk = "MEDIUM"
    elif severity_counts.get("LOW", 0) > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "CLEAN"

    sorted_attackers = sorted(
        detector.attacker_ips.values(),
        key=lambda x: x["suspicion_score"],
        reverse=True,
    )

    report = {
        "tool": "haka_spray_detector",
        "version": VERSION,
        "mitre_technique": "T1110.003 - Password Spraying",
        "findings_ref": ["CRIT-CBE-01", "CRIT-CBE-12", "CRIT-AWB-01", "CRIT-BOA-05"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": input_file,
        "configuration": {
            "threshold_users": threshold,
            "window_seconds": window,
            "single_user_threshold": detector.single_user_threshold,
        },
        "summary": {
            "overall_risk": overall_risk,
            "total_events_analyzed": len(detector.df),
            "total_alerts": len(detector.alerts),
            "critical_alerts": severity_counts.get("CRITICAL", 0),
            "high_alerts": severity_counts.get("HIGH", 0),
            "medium_alerts": severity_counts.get("MEDIUM", 0),
            "low_alerts": severity_counts.get("LOW", 0),
            "spray_sessions_detected": len(detector.spray_sessions),
            "compromised_accounts": len(detector.compromised_accounts),
            "unique_attacker_ips": len(detector.attacker_ips),
        },
        "alerts": detector.alerts,
        "spray_sessions": detector.spray_sessions,
        "compromised_accounts": detector.compromised_accounts,
        "attacker_ips_ranked": sorted_attackers,
    }

    if wazuh_rules:
        report["wazuh_rules"] = wazuh_rules

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

    return output_path


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="haka_spray_detector",
        description=(
            "HAKA AI - Password Spray Detector\n"
            "Analyze Windows Event Logs (EVTX/CSV) to detect password "
            "spraying attacks (T1110.003)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --evtx Security.evtx\n"
            "  %(prog)s --csv failed_logins.csv --threshold 5 --window 300\n"
            "  %(prog)s --evtx Security.evtx --generate-wazuh-rules\n"
            "  %(prog)s --csv logins.csv --iis-log iis_u_ex210101.log\n"
        ),
    )

    input_group = parser.add_argument_group("Input sources")
    input_group.add_argument(
        "--evtx",
        type=str,
        help="Path to Windows Security EVTX file",
    )
    input_group.add_argument(
        "--csv",
        type=str,
        help="Path to CSV file with logon events",
    )
    input_group.add_argument(
        "--iis-log",
        type=str,
        help="Path to IIS W3C log file (for OWA detection)",
    )

    threshold_group = parser.add_argument_group("Detection thresholds")
    threshold_group.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help=f"Minimum distinct users from one source to trigger spray alert (default: {DEFAULT_THRESHOLD})",
    )
    threshold_group.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW,
        help=f"Time window in seconds for spray detection (default: {DEFAULT_WINDOW})",
    )
    threshold_group.add_argument(
        "--single-user-threshold",
        type=int,
        default=DEFAULT_SINGLE_USER_THRESHOLD,
        help=f"Failed login count to flag single-user brute force (default: {DEFAULT_SINGLE_USER_THRESHOLD})",
    )

    output_group = parser.add_argument_group("Output options")
    output_group.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Path for JSON report (default: auto-generated in reports/)",
    )
    output_group.add_argument(
        "--generate-wazuh-rules",
        action="store_true",
        default=False,
        help="Generate Wazuh custom rules based on detected patterns",
    )
    output_group.add_argument(
        "--wazuh-rules-file",
        type=str,
        default=None,
        help="Save Wazuh rules to this file (default: print to stdout)",
    )
    output_group.add_argument(
        "--no-timeline",
        action="store_true",
        default=False,
        help="Skip timeline visualization",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress banner art",
    )
    output_group.add_argument(
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

    # Validate input
    if not args.evtx and not args.csv and not args.iis_log:
        print(
            f"  {Fore.RED}[!] No input file specified. "
            f"Use --evtx, --csv, or --iis-log.{Style.RESET_ALL}"
        )
        sys.exit(1)

    start_time = time.monotonic()
    input_file = args.evtx or args.csv or args.iis_log or ""

    print(
        f"  {Fore.WHITE}Configuration: threshold={args.threshold} users, "
        f"window={args.window}s, "
        f"single_user={args.single_user_threshold}{Style.RESET_ALL}\n"
    )

    # ----- Load events -----
    frames: list[pd.DataFrame] = []

    if args.evtx:
        filepath = args.evtx
        if not os.path.isfile(filepath):
            print(f"  {Fore.RED}[!] EVTX file not found: {filepath}{Style.RESET_ALL}")
            sys.exit(1)
        try:
            df_evtx = parse_evtx_file(filepath)
            if not df_evtx.empty:
                frames.append(df_evtx)
        except ImportError:
            print(
                f"  {Fore.YELLOW}[!] python-evtx not available. "
                f"Please provide a CSV export instead, or install:\n"
                f"    pip install python-evtx{Style.RESET_ALL}"
            )
            sys.exit(1)
        except Exception as exc:
            print(
                f"  {Fore.RED}[!] Error parsing EVTX: {exc}{Style.RESET_ALL}"
            )
            sys.exit(1)

    if args.csv:
        filepath = args.csv
        if not os.path.isfile(filepath):
            print(f"  {Fore.RED}[!] CSV file not found: {filepath}{Style.RESET_ALL}")
            sys.exit(1)
        try:
            df_csv = parse_csv_file(filepath)
            if not df_csv.empty:
                frames.append(df_csv)
        except Exception as exc:
            print(
                f"  {Fore.RED}[!] Error parsing CSV: {exc}{Style.RESET_ALL}"
            )
            sys.exit(1)

    if args.iis_log:
        filepath = args.iis_log
        if not os.path.isfile(filepath):
            print(f"  {Fore.RED}[!] IIS log file not found: {filepath}{Style.RESET_ALL}")
            sys.exit(1)
        try:
            df_iis = parse_iis_log(filepath)
            if not df_iis.empty:
                frames.append(df_iis)
        except Exception as exc:
            print(
                f"  {Fore.RED}[!] Error parsing IIS log: {exc}{Style.RESET_ALL}"
            )
            sys.exit(1)

    if not frames:
        print(f"\n  {Fore.RED}[!] No events loaded from input files.{Style.RESET_ALL}")
        sys.exit(1)

    # Merge all sources
    df = pd.concat(frames, ignore_index=True)
    df.sort_values("timestamp", inplace=True, ignore_index=True)

    # ----- Print event stats -----
    print_event_stats(df)

    # ----- Run detections -----
    detector = SprayDetector(
        df=df,
        threshold=args.threshold,
        window=args.window,
        single_user_threshold=args.single_user_threshold,
    )
    detector.run_all_detections()

    # ----- Timeline -----
    if not args.no_timeline:
        timeline = render_timeline(df, detector.alerts)
        print(timeline)

    # ----- Output results -----
    print_alerts(detector.alerts)
    print_compromised_accounts(detector.compromised_accounts)
    print_attacker_ips(detector.attacker_ips)

    # ----- Wazuh rules -----
    wazuh_rules = None
    if args.generate_wazuh_rules:
        print(_header("Wazuh Custom Rules"))
        print(f"  {'=' * 60}")

        wazuh_rules = generate_wazuh_rules(detector, args.threshold, args.window)

        if args.wazuh_rules_file:
            rules_path = Path(args.wazuh_rules_file)
            rules_path.parent.mkdir(parents=True, exist_ok=True)
            with open(rules_path, "w", encoding="utf-8") as fh:
                fh.write(wazuh_rules)
            print(
                f"\n  {Fore.GREEN}[+] Wazuh rules saved to: "
                f"{rules_path}{Style.RESET_ALL}"
            )
        else:
            print(f"\n{Fore.YELLOW}{wazuh_rules}{Style.RESET_ALL}")

        print(
            f"\n  {Fore.CYAN}[*] To deploy: copy rules to "
            f"/var/ossec/etc/rules/local_rules.xml "
            f"and restart Wazuh manager{Style.RESET_ALL}"
        )

    # ----- Elapsed time -----
    elapsed = round(time.monotonic() - start_time, 2)

    # ----- JSON report -----
    if args.output:
        report_path = Path(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = REPORTS_DIR / f"spray_detect_{ts}.json"

    report_file = write_report(
        detector=detector,
        threshold=args.threshold,
        window=args.window,
        input_file=input_file,
        wazuh_rules=wazuh_rules,
        output_path=report_path,
    )

    # ----- Final summary -----
    print(_header("Scan Complete"))
    print(f"  {'=' * 60}")
    print(f"  Analysis completed in {elapsed}s")
    print(f"  Events analyzed: {len(df)}")
    print(f"  Alerts generated: {len(detector.alerts)}")

    severity_counts = Counter(a["severity"] for a in detector.alerts)
    if severity_counts.get("CRITICAL", 0) > 0:
        print(
            f"\n  {Fore.RED}{Style.BRIGHT}*** CRITICAL findings require "
            f"immediate investigation ***{Style.RESET_ALL}"
        )

    print(
        f"\n  {Fore.GREEN}[+] Report saved to: "
        f"{report_file}{Style.RESET_ALL}\n"
    )


if __name__ == "__main__":
    main()
