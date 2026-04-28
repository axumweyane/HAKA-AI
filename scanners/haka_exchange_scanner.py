#!/usr/bin/env python3
"""
HAKA AI - Tool 3: Exchange & NTLM Scanner
==========================================
Section B1 - NTLM Relay (T1557.001) + B3 - ProxyShell (T1190)
Findings: CRIT-CBE-01, CRIT-CBE-10, CRIT-CBE-11, CRIT-AWB-01, CRIT-AWB-02, CRIT-AWB-08

Enumerates Microsoft Exchange endpoints, extracts version information,
decodes NTLM authentication metadata, detects ProxyShell exposure,
and identifies F5 BIG-IP cookie information leakage.

Usage:
    python haka_exchange_scanner.py --target 192.168.122.210
    python haka_exchange_scanner.py --target 192.168.122.210 --ntlm-decode
    python haka_exchange_scanner.py --target 192.168.122.210 --check-proxyshell

Author:  HAKA AI Framework
License: For authorized security assessments only.
"""

import argparse
import base64
import json
import os
import random
import re
import socket
import struct
import sys
import time
import urllib3
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests")

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    sys.exit("[!] Missing dependency: pip install colorama")

# ---------------------------------------------------------------------------
# Globals & constants
# ---------------------------------------------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
colorama_init(autoreset=True)

BANNER = rf"""
{Fore.RED}
  ██╗  ██╗ █████╗ ██╗  ██╗ █████╗      █████╗ ██╗
  ██║  ██║██╔══██╗██║ ██╔╝██╔══██╗    ██╔══██╗██║
  ███████║███████║█████╔╝ ███████║    ███████║██║
  ██╔══██║██╔══██║██╔═██╗ ██╔══██║    ██╔══██║██║
  ██║  ██║██║  ██║██║  ██╗██║  ██║    ██║  ██║██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝
{Style.RESET_ALL}
  {Fore.CYAN}Tool 3: Exchange & NTLM Scanner{Style.RESET_ALL}
  {Fore.WHITE}MITRE: T1557.001 (NTLM Relay) | T1190 (ProxyShell){Style.RESET_ALL}
  {Fore.WHITE}Findings: CRIT-CBE-01,10,11 | CRIT-AWB-01,02,08{Style.RESET_ALL}
"""

DEFAULT_TIMEOUT = 5

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)",
]

# NTLM Type 1 (Negotiate) message - standard negotiate flags
NTLM_TYPE1_B64 = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="

# Exchange endpoints to probe
EXCHANGE_ENDPOINTS = [
    ("/owa", "Outlook Web Access"),
    ("/ecp", "Exchange Control Panel"),
    ("/ews/exchange.asmx", "Exchange Web Services"),
    ("/autodiscover/autodiscover.xml", "Autodiscover"),
    ("/mapi/nspi", "MAPI/NSPI"),
    ("/oab", "Offline Address Book"),
    ("/powershell", "Exchange PowerShell"),
    ("/rpc/rpcproxy.dll", "RPC over HTTP"),
]

# Endpoints that commonly accept NTLM authentication
NTLM_ENDPOINTS = [
    "/ews/exchange.asmx",
    "/autodiscover/autodiscover.xml",
    "/rpc/rpcproxy.dll",
    "/mapi/nspi",
    "/oab",
    "/ecp",
]

# NTLM AV_PAIR type IDs
AV_PAIR_TYPES = {
    1: "MsvAvNbComputerName",
    2: "MsvAvNbDomainName",
    3: "MsvAvDnsComputerName",
    4: "MsvAvDnsDomainName",
    5: "MsvAvDnsTreeName",
    6: "MsvAvFlags",
    7: "MsvAvTimestamp",
    8: "MsvAvSingleHost",
    9: "MsvAvTargetName",
    10: "MsvAvChannelBindings",
}

# ---------------------------------------------------------------------------
# Exchange build-number -> CU version mapping
# ---------------------------------------------------------------------------

EXCHANGE_VERSIONS = {
    # Exchange Server 2019 -------------------------------------------------
    "15.2.1544": ("Exchange 2019 CU14 Nov23SU", "2023-11"),
    "15.2.1258": ("Exchange 2019 CU13", "2023-05"),
    "15.2.1118": ("Exchange 2019 CU12", "2022-04"),
    "15.2.986":  ("Exchange 2019 CU11", "2021-10"),
    "15.2.922":  ("Exchange 2019 CU10", "2021-06"),
    "15.2.858":  ("Exchange 2019 CU9", "2021-03"),
    "15.2.792":  ("Exchange 2019 CU8", "2020-12"),
    "15.2.721":  ("Exchange 2019 CU7", "2020-09"),
    "15.2.659":  ("Exchange 2019 CU6", "2020-06"),
    "15.2.595":  ("Exchange 2019 CU5", "2020-03"),
    "15.2.529":  ("Exchange 2019 CU4", "2019-12"),
    "15.2.464":  ("Exchange 2019 CU3", "2019-09"),
    "15.2.397":  ("Exchange 2019 CU2", "2019-06"),
    "15.2.330":  ("Exchange 2019 CU1", "2019-02"),
    "15.2.221":  ("Exchange 2019 RTM", "2018-10"),
    # Exchange Server 2016 -------------------------------------------------
    "15.1.2507": ("Exchange 2016 CU23", "2022-04"),
    "15.1.2375": ("Exchange 2016 CU22", "2021-09"),
    "15.1.2308": ("Exchange 2016 CU21", "2021-06"),
    "15.1.2242": ("Exchange 2016 CU20", "2021-03"),
    "15.1.2176": ("Exchange 2016 CU19", "2020-12"),
    "15.1.2106": ("Exchange 2016 CU18", "2020-09"),
    "15.1.2044": ("Exchange 2016 CU17", "2020-06"),
    "15.1.1979": ("Exchange 2016 CU16", "2020-03"),
    "15.1.1913": ("Exchange 2016 CU15", "2019-12"),
    "15.1.1847": ("Exchange 2016 CU14", "2019-09"),
    "15.1.1779": ("Exchange 2016 CU13", "2019-06"),
    "15.1.1713": ("Exchange 2016 CU12", "2019-02"),
    "15.1.1591": ("Exchange 2016 CU11", "2018-10"),
    "15.1.1531": ("Exchange 2016 CU10", "2018-06"),
    "15.1.1466": ("Exchange 2016 CU9", "2018-03"),
    "15.1.1415": ("Exchange 2016 CU8", "2017-12"),
    "15.1.1261": ("Exchange 2016 CU7", "2017-09"),
    "15.1.1034": ("Exchange 2016 CU6", "2017-06"),
    "15.1.845":  ("Exchange 2016 CU5", "2017-03"),
    "15.1.669":  ("Exchange 2016 CU4", "2016-12"),
    "15.1.544":  ("Exchange 2016 CU3", "2016-09"),
    "15.1.466":  ("Exchange 2016 CU2", "2016-06"),
    "15.1.396":  ("Exchange 2016 CU1", "2016-03"),
    "15.1.225":  ("Exchange 2016 RTM", "2015-10"),
    # Exchange Server 2013 -------------------------------------------------
    "15.0.1497": ("Exchange 2013 CU23", "2019-06"),
    "15.0.1473": ("Exchange 2013 CU22", "2018-11"),
    "15.0.1395": ("Exchange 2013 CU21", "2018-06"),
    "15.0.1367": ("Exchange 2013 CU20", "2018-03"),
    "15.0.1365": ("Exchange 2013 CU19", "2017-12"),
    "15.0.1347": ("Exchange 2013 CU18", "2017-09"),
    "15.0.1320": ("Exchange 2013 CU17", "2017-06"),
    "15.0.1293": ("Exchange 2013 CU16", "2017-03"),
    "15.0.1263": ("Exchange 2013 CU15", "2016-12"),
    "15.0.1236": ("Exchange 2013 CU14", "2016-09"),
    "15.0.1210": ("Exchange 2013 CU13", "2016-06"),
    "15.0.1178": ("Exchange 2013 CU12", "2016-03"),
    "15.0.1156": ("Exchange 2013 CU11", "2015-12"),
    "15.0.1130": ("Exchange 2013 CU10", "2015-09"),
    "15.0.1104": ("Exchange 2013 CU9", "2015-06"),
    "15.0.1076": ("Exchange 2013 CU8", "2015-03"),
    "15.0.1044": ("Exchange 2013 CU7", "2014-12"),
    "15.0.995":  ("Exchange 2013 CU6", "2014-08"),
    "15.0.913":  ("Exchange 2013 CU5", "2014-05"),
    "15.0.847":  ("Exchange 2013 CU4 / SP1", "2014-02"),
    "15.0.775":  ("Exchange 2013 CU3", "2013-11"),
    "15.0.712":  ("Exchange 2013 CU2", "2013-07"),
    "15.0.620":  ("Exchange 2013 CU1", "2013-04"),
    "15.0.516":  ("Exchange 2013 RTM", "2012-12"),
}

# Latest known CU per major version (for staleness check)
LATEST_CU = {
    "15.2": ("CU14", 14),   # Exchange 2019
    "15.1": ("CU23", 23),   # Exchange 2016
    "15.0": ("CU23", 23),   # Exchange 2013
}

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def ts() -> str:
    """Compact timestamp for log lines."""
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str) -> None:
    print(f"  {Fore.CYAN}[{ts()}] [*]{Style.RESET_ALL} {msg}")


def good(msg: str) -> None:
    print(f"  {Fore.GREEN}[{ts()}] [+]{Style.RESET_ALL} {msg}")


def warn(msg: str) -> None:
    print(f"  {Fore.YELLOW}[{ts()}] [!]{Style.RESET_ALL} {msg}")


def bad(msg: str) -> None:
    print(f"  {Fore.RED}[{ts()}] [-]{Style.RESET_ALL} {msg}")


def crit(msg: str) -> None:
    print(f"  {Fore.RED}{Style.BRIGHT}[{ts()}] [CRITICAL]{Style.RESET_ALL} {msg}")


def section(title: str) -> None:
    width = 60
    print()
    print(f"  {Fore.MAGENTA}{'=' * width}")
    print(f"  {title.center(width)}")
    print(f"  {'=' * width}{Style.RESET_ALL}")
    print()


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def build_base_url(target: str, scheme: str = "https") -> str:
    """Normalise a target into a base URL."""
    target = target.strip().rstrip("/")
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"{scheme}://{target}"


# ---------------------------------------------------------------------------
# F5 BIG-IP cookie decoder
# ---------------------------------------------------------------------------

def decode_bigip_cookie(cookie_value: str) -> dict | None:
    """
    Decode a BIG-IP persistence cookie into an internal IP and port.

    Format: <encoded_ip>.<encoded_port>.0000
    encoded_ip  = little-endian 32-bit integer of the IPv4 address
    encoded_port = little-endian 16-bit integer of the port, byte-swapped
    """
    try:
        parts = cookie_value.split(".")
        if len(parts) < 3:
            return None

        ip_enc = int(parts[0])
        port_enc = int(parts[1])

        # Decode IP (little-endian 32-bit)
        octet1 = ip_enc & 0xFF
        octet2 = (ip_enc >> 8) & 0xFF
        octet3 = (ip_enc >> 16) & 0xFF
        octet4 = (ip_enc >> 24) & 0xFF
        ip_addr = f"{octet1}.{octet2}.{octet3}.{octet4}"

        # Decode port (two bytes swapped)
        port = ((port_enc & 0xFF) << 8) | ((port_enc >> 8) & 0xFF)

        return {"internal_ip": ip_addr, "internal_port": port}
    except (ValueError, IndexError, TypeError):
        return None


# ---------------------------------------------------------------------------
# NTLM Type 2 message parser
# ---------------------------------------------------------------------------

def parse_ntlm_type2(raw: bytes) -> dict:
    """
    Parse an NTLM Type 2 (Challenge) message and return extracted fields.

    NTLM Type 2 layout (offsets):
        0-7     : Signature  "NTLMSSP\x00"
        8-11    : Message type (2)
        12-13   : Target name length
        14-15   : Target name max length
        16-19   : Target name offset
        20-23   : Negotiate flags
        24-31   : Server challenge (8 bytes)
        32-39   : Reserved
        40-41   : Target info length
        42-43   : Target info max length
        44-47   : Target info offset
        48-55   : OS version (optional, if flag set)
    """
    result: dict = {
        "target_name": "",
        "negotiate_flags": 0,
        "av_pairs": {},
        "os_version": "",
    }

    if len(raw) < 32:
        return result

    sig = raw[0:8]
    if sig != b"NTLMSSP\x00":
        return result

    msg_type = struct.unpack_from("<I", raw, 8)[0]
    if msg_type != 2:
        return result

    # Target name
    tn_len = struct.unpack_from("<H", raw, 12)[0]
    tn_offset = struct.unpack_from("<I", raw, 16)[0]
    if tn_offset + tn_len <= len(raw):
        try:
            result["target_name"] = raw[tn_offset:tn_offset + tn_len].decode("utf-16-le")
        except UnicodeDecodeError:
            result["target_name"] = raw[tn_offset:tn_offset + tn_len].hex()

    # Flags
    result["negotiate_flags"] = struct.unpack_from("<I", raw, 20)[0]

    # OS version (if flag 0x02000000 NTLMSSP_NEGOTIATE_VERSION is set)
    if result["negotiate_flags"] & 0x02000000 and len(raw) >= 56:
        major = raw[48]
        minor = raw[49]
        build = struct.unpack_from("<H", raw, 50)[0]
        revision = raw[55]
        result["os_version"] = f"{major}.{minor}.{build} (NTLM revision {revision})"

    # Target info / AV_PAIRs
    if len(raw) >= 48:
        ti_len = struct.unpack_from("<H", raw, 40)[0]
        ti_offset = struct.unpack_from("<I", raw, 44)[0]

        if ti_offset + ti_len <= len(raw):
            _parse_av_pairs(raw, ti_offset, ti_len, result)

    return result


def _parse_av_pairs(raw: bytes, offset: int, length: int, result: dict) -> None:
    """Walk the AV_PAIR list inside an NTLM Type 2 message."""
    pos = offset
    end = offset + length

    while pos + 4 <= end:
        av_id = struct.unpack_from("<H", raw, pos)[0]
        av_len = struct.unpack_from("<H", raw, pos + 2)[0]
        pos += 4

        if av_id == 0:  # MsvAvEOL
            break

        if pos + av_len > end:
            break

        av_data = raw[pos:pos + av_len]
        av_name = AV_PAIR_TYPES.get(av_id, f"Unknown({av_id})")

        # String types are UTF-16-LE
        if av_id in (1, 2, 3, 4, 5, 9):
            try:
                result["av_pairs"][av_name] = av_data.decode("utf-16-le")
            except UnicodeDecodeError:
                result["av_pairs"][av_name] = av_data.hex()
        elif av_id == 7:
            # Timestamp: Windows FILETIME (100ns intervals since 1601-01-01)
            if av_len == 8:
                filetime = struct.unpack_from("<Q", av_data, 0)[0]
                # Convert to Unix epoch
                epoch_diff = 116444736000000000
                if filetime > epoch_diff:
                    unix_ts = (filetime - epoch_diff) / 10_000_000
                    try:
                        result["av_pairs"][av_name] = datetime.fromtimestamp(
                            unix_ts, tz=timezone.utc
                        ).isoformat()
                    except (OSError, OverflowError):
                        result["av_pairs"][av_name] = str(filetime)
                else:
                    result["av_pairs"][av_name] = str(filetime)
            else:
                result["av_pairs"][av_name] = av_data.hex()
        elif av_id == 6:
            # Flags (32-bit)
            if av_len >= 4:
                result["av_pairs"][av_name] = struct.unpack_from("<I", av_data, 0)[0]
            else:
                result["av_pairs"][av_name] = av_data.hex()
        else:
            result["av_pairs"][av_name] = av_data.hex()

        pos += av_len


# ---------------------------------------------------------------------------
# Exchange version resolver
# ---------------------------------------------------------------------------

def resolve_exchange_version(build_str: str) -> dict:
    """
    Given a build string like '15.2.1544.11', match the closest CU
    and determine how outdated it is.
    """
    result = {
        "build": build_str,
        "product": "Unknown",
        "release_date": "Unknown",
        "cu_behind": 0,
        "is_outdated": False,
    }

    # Normalise: strip trailing .x revision numbers, keep major.minor.build
    parts = build_str.split(".")
    if len(parts) < 3:
        return result

    # Try progressively shorter prefixes for a match
    prefix3 = f"{parts[0]}.{parts[1]}.{parts[2]}"
    major_minor = f"{parts[0]}.{parts[1]}"

    if prefix3 in EXCHANGE_VERSIONS:
        ver_name, rel_date = EXCHANGE_VERSIONS[prefix3]
        result["product"] = ver_name
        result["release_date"] = rel_date
    else:
        # Fuzzy: find the closest build number within the same major.minor
        best_key = None
        best_build = 0
        target_build = int(parts[2])
        for key in EXCHANGE_VERSIONS:
            kp = key.split(".")
            km = f"{kp[0]}.{kp[1]}"
            if km == major_minor:
                kb = int(kp[2])
                if kb <= target_build and kb > best_build:
                    best_build = kb
                    best_key = key
        if best_key:
            ver_name, rel_date = EXCHANGE_VERSIONS[best_key]
            result["product"] = f"{ver_name} (approx)"
            result["release_date"] = rel_date

    # CU staleness
    if major_minor in LATEST_CU:
        latest_name, latest_num = LATEST_CU[major_minor]
        # Extract the CU number from the matched product name
        cu_match = re.search(r"CU(\d+)", result["product"])
        if cu_match:
            detected_cu = int(cu_match.group(1))
            result["cu_behind"] = latest_num - detected_cu
            if result["cu_behind"] >= 2:
                result["is_outdated"] = True

    return result


# ---------------------------------------------------------------------------
# Core scanner class
# ---------------------------------------------------------------------------

class ExchangeScanner:
    """Comprehensive Exchange server scanner."""

    def __init__(
        self,
        target: str,
        timeout: int = DEFAULT_TIMEOUT,
        ntlm_decode: bool = False,
        check_proxyshell: bool = False,
    ):
        self.target = target
        self.timeout = timeout
        self.ntlm_decode = ntlm_decode
        self.check_proxyshell = check_proxyshell

        # Results accumulator
        self.results: dict = {
            "scan_metadata": {
                "target": target,
                "scan_start": datetime.now(timezone.utc).isoformat(),
                "scan_end": "",
                "scanner": "haka_exchange_scanner",
                "version": "1.0.0",
            },
            "endpoints": {},
            "exchange_version": {},
            "ntlm_info": {},
            "proxyshell": {},
            "bigip_cookies": [],
            "risk_findings": [],
            "risk_score": 0,
        }

        # Track determined base URL (https preferred)
        self._base_url: str | None = None
        self._session = requests.Session()
        self._session.verify = False

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, **kwargs) -> requests.Response | None:
        """Issue a GET request to <base>/<path>, return Response or None."""
        if self._base_url is None:
            return None
        url = f"{self._base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", random_ua())
        try:
            resp = self._session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=kwargs.pop("allow_redirects", True),
                **kwargs,
            )
            return resp
        except requests.exceptions.RequestException:
            return None

    def _post(self, path: str, **kwargs) -> requests.Response | None:
        if self._base_url is None:
            return None
        url = f"{self._base_url}{path}"
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", random_ua())
        try:
            resp = self._session.post(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=kwargs.pop("allow_redirects", False),
                **kwargs,
            )
            return resp
        except requests.exceptions.RequestException:
            return None

    # ------------------------------------------------------------------
    # Phase 0: Connectivity
    # ------------------------------------------------------------------

    def check_connectivity(self) -> bool:
        """Determine whether HTTPS or HTTP is reachable."""
        section("PHASE 0: Connectivity Check")

        for scheme in ("https", "http"):
            url = build_base_url(self.target, scheme)
            info(f"Trying {url} ...")
            try:
                resp = self._session.get(
                    url,
                    timeout=self.timeout,
                    headers={"User-Agent": random_ua()},
                    allow_redirects=True,
                )
                good(f"Connected via {scheme.upper()} (HTTP {resp.status_code})")
                self._base_url = url
                return True
            except requests.exceptions.SSLError:
                # SSL error but host is reachable on this port
                good(f"Host reachable on {scheme.upper()} (SSL error ignored)")
                self._base_url = url
                return True
            except requests.exceptions.ConnectionError:
                bad(f"Connection refused on {scheme.upper()}")
            except requests.exceptions.Timeout:
                bad(f"Timeout on {scheme.upper()}")
            except requests.exceptions.RequestException as exc:
                bad(f"Error on {scheme.upper()}: {exc}")

        bad("Target is unreachable on both HTTPS and HTTP")
        return False

    # ------------------------------------------------------------------
    # Phase 1: Endpoint enumeration
    # ------------------------------------------------------------------

    def enumerate_endpoints(self) -> None:
        section("PHASE 1: Exchange Endpoint Enumeration")

        accessible_count = 0

        for path, description in EXCHANGE_ENDPOINTS:
            resp = self._get(path, allow_redirects=False)
            if resp is None:
                bad(f"{path:40s} - Connection failed")
                self.results["endpoints"][path] = {
                    "description": description,
                    "status": "error",
                    "status_code": None,
                }
                continue

            code = resp.status_code
            entry: dict = {
                "description": description,
                "status_code": code,
                "headers": dict(resp.headers),
            }

            # 200, 301, 302, 401, 403 all indicate the endpoint exists
            if code in (200, 301, 302, 401, 403, 440):
                accessible_count += 1
                status_str = "accessible" if code == 200 else f"exists (HTTP {code})"
                entry["status"] = "found"
                good(f"{path:40s} - {Fore.GREEN}{status_str}{Style.RESET_ALL}")

                # Check for NTLM authentication support
                www_auth = resp.headers.get("WWW-Authenticate", "")
                if "NTLM" in www_auth or "Negotiate" in www_auth:
                    entry["ntlm_auth"] = True
                    warn(f"{'':40s}   NTLM/Negotiate auth advertised")
                else:
                    entry["ntlm_auth"] = False

            else:
                entry["status"] = "not_found"
                info(f"{path:40s} - HTTP {code}")

            # Check for BIG-IP cookies in every response
            self._check_bigip_cookies(resp, path)

            self.results["endpoints"][path] = entry

        # Risk: full stack exposed
        if accessible_count >= 5:
            self._add_finding(
                "CRITICAL",
                "CRIT-CBE-01",
                "Full Exchange endpoint stack exposed",
                f"{accessible_count}/{len(EXCHANGE_ENDPOINTS)} endpoints accessible",
            )

        # Risk: NTLM auth on endpoints
        ntlm_endpoints = [
            p for p, e in self.results["endpoints"].items() if e.get("ntlm_auth")
        ]
        if ntlm_endpoints:
            self._add_finding(
                "CRITICAL",
                "CRIT-CBE-10",
                "NTLM authentication enabled on Exchange endpoints",
                f"Endpoints: {', '.join(ntlm_endpoints)}",
            )

        # Risk: PowerShell endpoint exposed
        ps_entry = self.results["endpoints"].get("/powershell", {})
        if ps_entry.get("status") == "found":
            self._add_finding(
                "HIGH",
                "CRIT-AWB-08",
                "Exchange PowerShell endpoint exposed",
                "Remote PowerShell may allow authenticated command execution",
            )

    # ------------------------------------------------------------------
    # Phase 2: Version extraction
    # ------------------------------------------------------------------

    def extract_version(self) -> None:
        section("PHASE 2: Exchange Version Detection")

        build_candidates: list[str] = []

        # --- Method 1: OWA login page HTML ----
        info("Checking OWA login page for version strings ...")
        resp = self._get("/owa/auth/logon.aspx")
        if resp and resp.status_code == 200:
            text = resp.text

            # Common patterns in OWA HTML
            patterns = [
                r"/owa/(?:auth/)?(\d+\.\d+\.\d+(?:\.\d+)?)/",
                r"version[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+(?:\.\d+)?)",
                r"X-OWA-Version[\"']?\s*[:=]\s*[\"']?(\d+\.\d+\.\d+(?:\.\d+)?)",
            ]
            for pat in patterns:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    build_candidates.append(m.group(1))
                    good(f"Version from OWA HTML: {m.group(1)}")

        # --- Method 2: HTTP headers ----
        info("Checking HTTP response headers for version info ...")
        for path in ("/owa", "/ecp", "/ews/exchange.asmx"):
            resp = self._get(path, allow_redirects=False)
            if resp is None:
                continue

            for hdr_name in ("X-OWA-Version", "X-FEServer", "X-BEServer",
                             "X-DiagInfo", "X-CalculatedBETarget"):
                val = resp.headers.get(hdr_name, "")
                if val:
                    info(f"  {hdr_name}: {val}")
                    # Try to extract version pattern
                    m = re.search(r"(\d+\.\d+\.\d+(?:\.\d+)?)", val)
                    if m:
                        build_candidates.append(m.group(1))
                        good(f"Version from {hdr_name}: {m.group(1)}")

            # X-FEServer / X-BEServer may reveal server hostname
            for hdr_name in ("X-FEServer", "X-BEServer", "X-DiagInfo",
                             "X-CalculatedBETarget"):
                val = resp.headers.get(hdr_name, "")
                if val and not re.match(r"^\d", val):
                    info(f"  Internal hostname via {hdr_name}: {Fore.YELLOW}{val}")

        # Resolve the best version candidate
        if build_candidates:
            # Take the most detailed (longest) build string
            best = max(build_candidates, key=len)
            ver_info = resolve_exchange_version(best)
            self.results["exchange_version"] = ver_info
            good(f"Identified: {Fore.GREEN}{ver_info['product']}")
            info(f"Build: {ver_info['build']}  |  Released: {ver_info['release_date']}")
            if ver_info["is_outdated"]:
                crit(
                    f"Exchange is {ver_info['cu_behind']} CU(s) behind latest! "
                    f"Likely vulnerable to known exploits."
                )
                self._add_finding(
                    "CRITICAL",
                    "CRIT-CBE-11",
                    "Outdated Exchange version detected",
                    f"{ver_info['product']} is {ver_info['cu_behind']} CU(s) behind latest",
                )
        else:
            warn("Could not determine Exchange version from OWA or headers")
            self.results["exchange_version"] = {"build": "unknown", "product": "Unknown"}

    # ------------------------------------------------------------------
    # Phase 3: NTLM information extraction
    # ------------------------------------------------------------------

    def ntlm_extract(self) -> None:
        section("PHASE 3: NTLM Information Extraction")

        if not self.ntlm_decode:
            info("NTLM decode not requested (use --ntlm-decode to enable)")
            return

        ntlm_type1 = base64.b64decode(NTLM_TYPE1_B64)

        for endpoint in NTLM_ENDPOINTS:
            info(f"Sending NTLM Type 1 to {endpoint} ...")

            url = f"{self._base_url}{endpoint}"
            auth_header = f"NTLM {NTLM_TYPE1_B64}"

            try:
                resp = self._session.post(
                    url,
                    headers={
                        "User-Agent": random_ua(),
                        "Authorization": auth_header,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    data=b"",
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.exceptions.RequestException as exc:
                bad(f"  Connection error: {exc}")
                continue

            if resp.status_code != 401:
                info(f"  HTTP {resp.status_code} (expected 401 for NTLM challenge)")
                # Some endpoints return 401 on GET with NTLM, try GET as well
                try:
                    resp = self._session.get(
                        url,
                        headers={
                            "User-Agent": random_ua(),
                            "Authorization": auth_header,
                        },
                        timeout=self.timeout,
                        allow_redirects=False,
                    )
                except requests.exceptions.RequestException:
                    continue

            www_auth = resp.headers.get("WWW-Authenticate", "")
            if not www_auth:
                bad(f"  No WWW-Authenticate header in response")
                continue

            # Extract the NTLM Type 2 blob
            ntlm_match = re.search(r"NTLM\s+([A-Za-z0-9+/=]+)", www_auth)
            if not ntlm_match:
                info(f"  No NTLM Type 2 in WWW-Authenticate")
                continue

            type2_b64 = ntlm_match.group(1)
            try:
                type2_raw = base64.b64decode(type2_b64)
            except Exception:
                bad(f"  Failed to decode Type 2 base64")
                continue

            parsed = parse_ntlm_type2(type2_raw)

            if parsed["target_name"] or parsed["av_pairs"]:
                good(f"NTLM Type 2 decoded from {endpoint}:")
                print()

                if parsed["target_name"]:
                    print(f"    {Fore.WHITE}Target Name    : {Fore.YELLOW}{parsed['target_name']}")
                if parsed["os_version"]:
                    print(f"    {Fore.WHITE}OS Version     : {Fore.YELLOW}{parsed['os_version']}")
                print(f"    {Fore.WHITE}Flags          : {Fore.YELLOW}0x{parsed['negotiate_flags']:08x}")

                for av_name, av_val in parsed["av_pairs"].items():
                    label = av_name.replace("MsvAv", "").replace("Nb", "NB ").replace("Dns", "DNS ")
                    print(f"    {Fore.WHITE}{label:15s}: {Fore.YELLOW}{av_val}")

                print()

                # Store results (first successful decode wins)
                if not self.results["ntlm_info"]:
                    self.results["ntlm_info"] = {
                        "source_endpoint": endpoint,
                        "target_name": parsed["target_name"],
                        "os_version": parsed["os_version"],
                        "negotiate_flags": f"0x{parsed['negotiate_flags']:08x}",
                        "av_pairs": {k: str(v) for k, v in parsed["av_pairs"].items()},
                    }

                    # Summarise for the operator
                    domain = parsed["av_pairs"].get("MsvAvNbDomainName", "")
                    server = parsed["av_pairs"].get("MsvAvDnsComputerName", "")
                    dns_domain = parsed["av_pairs"].get("MsvAvDnsDomainName", "")
                    if domain:
                        good(f"AD Domain (NetBIOS): {Fore.GREEN}{domain}")
                    if dns_domain:
                        good(f"AD Domain (DNS)    : {Fore.GREEN}{dns_domain}")
                    if server:
                        good(f"Server FQDN        : {Fore.GREEN}{server}")

                # One successful decode is enough
                break
            else:
                warn(f"  Type 2 decoded but no useful fields extracted")

        if not self.results["ntlm_info"]:
            warn("NTLM Type 2 decode failed on all endpoints")
        else:
            self._add_finding(
                "CRITICAL",
                "CRIT-CBE-10",
                "NTLM authentication leaks internal AD information",
                f"Domain: {self.results['ntlm_info'].get('target_name', 'N/A')}",
            )

    # ------------------------------------------------------------------
    # Phase 4: ProxyShell detection
    # ------------------------------------------------------------------

    def check_proxyshell_exposure(self) -> None:
        section("PHASE 4: ProxyShell Exposure Check")

        if not self.check_proxyshell:
            info("ProxyShell check not requested (use --check-proxyshell to enable)")
            return

        proxyshell_results: dict = {
            "autodiscover_ssrf": False,
            "powershell_accessible": False,
            "xrps_cat_accepted": False,
        }

        # -- Test 1: Autodiscover SSRF pattern (CVE-2021-34473) ----------
        info("Testing autodiscover.json SSRF pattern (detection only) ...")
        # The SSRF pattern uses a specially crafted autodiscover URL
        # We test the URL pattern WITHOUT exploitation -- just checking
        # if the server responds differently to the crafted path.
        ssrf_path = "/autodiscover/autodiscover.json?@foo.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3f@foo.com"

        resp_ssrf = self._get(ssrf_path, allow_redirects=False)
        resp_normal = self._get("/autodiscover/autodiscover.json", allow_redirects=False)

        if resp_ssrf is not None:
            info(f"  SSRF pattern response: HTTP {resp_ssrf.status_code}")
            if resp_normal is not None:
                info(f"  Normal pattern response: HTTP {resp_normal.status_code}")

            # If SSRF path gives 200 or 302 while normal gives 401/403, it may be vulnerable
            if resp_ssrf.status_code in (200, 302) and (
                resp_normal is None or resp_normal.status_code in (401, 403, 404)
            ):
                proxyshell_results["autodiscover_ssrf"] = True
                crit(
                    "Autodiscover SSRF pattern accessible (potential CVE-2021-34473)"
                )
                self._add_finding(
                    "CRITICAL",
                    "CRIT-AWB-01",
                    "ProxyShell SSRF pattern accessible (CVE-2021-34473)",
                    f"autodiscover.json SSRF returned HTTP {resp_ssrf.status_code}",
                )
            elif resp_ssrf.status_code in (200, 302):
                warn("Autodiscover SSRF path returned success -- review manually")
                proxyshell_results["autodiscover_ssrf"] = "possible"
            else:
                good("Autodiscover SSRF pattern blocked or not exploitable")
        else:
            bad("  Could not reach autodiscover.json endpoint")

        # -- Test 2: PowerShell endpoint accessibility (CVE-2021-34523) ------
        info("Checking /powershell endpoint accessibility ...")
        ps_resp = self._get("/powershell", allow_redirects=False)
        if ps_resp is not None:
            info(f"  /powershell response: HTTP {ps_resp.status_code}")
            if ps_resp.status_code in (200, 302, 401):
                proxyshell_results["powershell_accessible"] = True
                warn("/powershell endpoint is accessible")
            else:
                good("/powershell endpoint appears blocked")
        else:
            good("/powershell endpoint unreachable")

        # -- Test 3: X-Rps-CAT header acceptance (CVE-2021-31207) ---------
        info("Testing X-Rps-CAT header acceptance ...")
        # We send a benign request with the header to see if the server processes it
        cat_header = base64.b64encode(
            b"V2luZG93c0lkZW50aXR5"  # dummy - just testing header acceptance
        ).decode()

        try:
            resp_cat = self._session.get(
                f"{self._base_url}/powershell",
                headers={
                    "User-Agent": random_ua(),
                    "X-Rps-CAT": cat_header,
                },
                timeout=self.timeout,
                allow_redirects=False,
            )
            info(f"  X-Rps-CAT response: HTTP {resp_cat.status_code}")

            # Compare with a request without the header
            resp_nocat = self._session.get(
                f"{self._base_url}/powershell",
                headers={"User-Agent": random_ua()},
                timeout=self.timeout,
                allow_redirects=False,
            )

            # If the server returns different codes, it may be processing the header
            if resp_cat.status_code != resp_nocat.status_code:
                proxyshell_results["xrps_cat_accepted"] = True
                crit("X-Rps-CAT header changes server behaviour (potential CVE-2021-31207)")
                self._add_finding(
                    "CRITICAL",
                    "CRIT-AWB-02",
                    "X-Rps-CAT header accepted by Exchange (CVE-2021-31207)",
                    f"With header: HTTP {resp_cat.status_code}, Without: HTTP {resp_nocat.status_code}",
                )
            else:
                good("X-Rps-CAT header does not appear to be processed differently")

        except requests.exceptions.RequestException:
            bad("  Could not test X-Rps-CAT header")

        self.results["proxyshell"] = proxyshell_results

        # Combined ProxyShell risk
        if proxyshell_results["autodiscover_ssrf"] is True and proxyshell_results["powershell_accessible"]:
            crit(
                "FULL PROXYSHELL CHAIN MAY BE POSSIBLE -- "
                "autodiscover SSRF + PowerShell accessible"
            )

    # ------------------------------------------------------------------
    # BIG-IP cookie checking (called per-response)
    # ------------------------------------------------------------------

    def _check_bigip_cookies(self, resp: requests.Response, source_path: str) -> None:
        """Inspect response cookies for BIG-IP persistence leakage."""
        for cookie in resp.cookies:
            if cookie.name.lower().startswith("bigipserver") or "bigip" in cookie.name.lower():
                decoded = decode_bigip_cookie(cookie.value)
                entry = {
                    "cookie_name": cookie.name,
                    "cookie_value": cookie.value,
                    "source_path": source_path,
                    "decoded": decoded,
                }
                self.results["bigip_cookies"].append(entry)

                if decoded:
                    warn(
                        f"F5 BIG-IP cookie found on {source_path}: "
                        f"{Fore.YELLOW}{cookie.name}={cookie.value}"
                    )
                    crit(
                        f"Decoded internal IP: {Fore.RED}{decoded['internal_ip']}:{decoded['internal_port']}"
                    )
                    self._add_finding(
                        "HIGH",
                        "CRIT-AWB-08",
                        "F5 BIG-IP cookie leaks internal IP address",
                        f"Internal: {decoded['internal_ip']}:{decoded['internal_port']} "
                        f"(from {source_path})",
                    )

        # Also check Set-Cookie header directly (some cookies don't get
        # parsed into the cookie jar due to path/domain restrictions)
        for hdr_val in resp.headers.get("Set-Cookie", "").split(","):
            if "bigip" in hdr_val.lower():
                m = re.search(r"(BIGipServer[^=]*)=([^;]+)", hdr_val, re.IGNORECASE)
                if m:
                    cname, cval = m.group(1), m.group(2)
                    # Avoid duplicates
                    already = any(
                        c["cookie_name"] == cname and c["cookie_value"] == cval
                        for c in self.results["bigip_cookies"]
                    )
                    if not already:
                        decoded = decode_bigip_cookie(cval)
                        self.results["bigip_cookies"].append({
                            "cookie_name": cname,
                            "cookie_value": cval,
                            "source_path": source_path,
                            "decoded": decoded,
                        })
                        if decoded:
                            warn(
                                f"F5 BIG-IP cookie (header) on {source_path}: "
                                f"{Fore.YELLOW}{cname}={cval}"
                            )
                            crit(
                                f"Decoded internal IP: "
                                f"{Fore.RED}{decoded['internal_ip']}:{decoded['internal_port']}"
                            )
                            self._add_finding(
                                "HIGH",
                                "CRIT-AWB-08",
                                "F5 BIG-IP cookie leaks internal IP address",
                                f"Internal: {decoded['internal_ip']}:{decoded['internal_port']} "
                                f"(from {source_path})",
                            )

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _add_finding(self, severity: str, finding_id: str, title: str, detail: str) -> None:
        """Append a de-duplicated risk finding."""
        # Deduplicate by finding_id + title
        for existing in self.results["risk_findings"]:
            if existing["id"] == finding_id and existing["title"] == title:
                return
        self.results["risk_findings"].append({
            "severity": severity,
            "id": finding_id,
            "title": title,
            "detail": detail,
        })

    def compute_risk_score(self) -> int:
        """
        Calculate an aggregate risk score (0-100).
        CRITICAL = 25 pts, HIGH = 15 pts, MEDIUM = 10 pts, LOW = 5 pts
        Capped at 100.
        """
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 10, "LOW": 5}
        total = sum(
            weights.get(f["severity"], 0) for f in self.results["risk_findings"]
        )
        return min(total, 100)

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        section("SCAN SUMMARY")

        score = self.compute_risk_score()
        self.results["risk_score"] = score

        if score >= 75:
            score_color = Fore.RED + Style.BRIGHT
        elif score >= 50:
            score_color = Fore.RED
        elif score >= 25:
            score_color = Fore.YELLOW
        else:
            score_color = Fore.GREEN

        print(f"  Target         : {Fore.WHITE}{self.target}")
        ver = self.results["exchange_version"].get("product", "Unknown")
        print(f"  Exchange       : {Fore.WHITE}{ver}")
        print(f"  Risk Score     : {score_color}{score}/100{Style.RESET_ALL}")
        print()

        if self.results["risk_findings"]:
            print(f"  {Fore.RED}{'Sev':10s} {'ID':15s} Title{Style.RESET_ALL}")
            print(f"  {'-' * 60}")
            for f in sorted(
                self.results["risk_findings"],
                key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    x["severity"], 4
                ),
            ):
                if f["severity"] == "CRITICAL":
                    clr = Fore.RED + Style.BRIGHT
                elif f["severity"] == "HIGH":
                    clr = Fore.RED
                elif f["severity"] == "MEDIUM":
                    clr = Fore.YELLOW
                else:
                    clr = Fore.WHITE
                print(f"  {clr}{f['severity']:10s}{Style.RESET_ALL} {f['id']:15s} {f['title']}")
                print(f"  {'':10s} {'':15s} {Fore.WHITE}{f['detail']}{Style.RESET_ALL}")
        else:
            good("No significant findings")

        print()

    def save_report(self) -> str:
        """Save JSON report to the reports directory. Return the file path."""
        self.results["scan_metadata"]["scan_end"] = datetime.now(timezone.utc).isoformat()

        reports_dir = Path("/home/kironix/HAKA-AI/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)

        safe_target = re.sub(r"[^a-zA-Z0-9._-]", "_", self.target)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exchange_scan_{safe_target}_{timestamp}.json"
        filepath = reports_dir / filename

        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(self.results, fh, indent=2, default=str)

        good(f"Report saved: {Fore.GREEN}{filepath}")
        return str(filepath)

    # ------------------------------------------------------------------
    # Main scan orchestration
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """Execute the full scan pipeline."""
        print(BANNER)

        if not self.check_connectivity():
            self.results["scan_metadata"]["scan_end"] = datetime.now(timezone.utc).isoformat()
            bad("Scan aborted: target unreachable")
            self.save_report()
            return self.results

        self.enumerate_endpoints()
        self.extract_version()
        self.ntlm_extract()
        self.check_proxyshell_exposure()
        self.print_summary()
        self.save_report()

        return self.results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HAKA AI - Exchange & NTLM Scanner (Tool 3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --target 192.168.122.210\n"
            "  %(prog)s --target mail.corp.local --ntlm-decode\n"
            "  %(prog)s --target 10.0.0.5 --check-proxyshell\n"
            "  %(prog)s --target exchange.lab --ntlm-decode --check-proxyshell\n"
        ),
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP address or hostname",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--ntlm-decode",
        action="store_true",
        default=False,
        help="Send NTLM Type 1 messages and decode Type 2 responses",
    )
    parser.add_argument(
        "--check-proxyshell",
        action="store_true",
        default=False,
        help="Test for ProxyShell (CVE-2021-34473/34523/31207) exposure",
    )
    parser.add_argument(
        "--scheme",
        choices=["https", "http"],
        default=None,
        help="Force HTTP or HTTPS (default: auto-detect, prefer HTTPS)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    target = args.target
    if args.scheme:
        target = build_base_url(target, args.scheme)

    scanner = ExchangeScanner(
        target=target,
        timeout=args.timeout,
        ntlm_decode=args.ntlm_decode,
        check_proxyshell=args.check_proxyshell,
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print()
        warn("Scan interrupted by operator")
        scanner.save_report()
        sys.exit(130)


if __name__ == "__main__":
    main()
