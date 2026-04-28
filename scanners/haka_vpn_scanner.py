#!/usr/bin/env python3
"""
HAKA AI - VPN Gateway Scanner (Tool 11: D3 - VPN Exploit T1133)

Fingerprints VPN vendors, extracts version info, maps to known CVEs,
checks for MFA indicators, and evaluates SSL certificates.

Supported vendors:
  Fortinet FortiGate, Pulse Secure, Cisco AnyConnect,
  Palo Alto GlobalProtect, OpenVPN Access Server, SonicWall

Findings reference: CRIT-ET-06

Author:  HAKA AI Framework
Version: 1.0.0
"""

import argparse
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit(
        "[!] requests is required.  Install it:\n"
        "    pip install requests"
    )

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    sys.exit(
        "[!] colorama is required.  Install it:\n"
        "    pip install colorama"
    )

# Suppress only the InsecureRequestWarning (we deliberately skip TLS verify)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
TOOL_ID = "Tool 11"
MITRE_ID = "T1133"
FINDING_REF = "CRIT-ET-06"
SECTION = "D3 - VPN Exploit"
TIMEOUT = 5
REPORTS_DIR = Path("/home/kironix/HAKA-AI/reports")

RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# ---------------------------------------------------------------------------
# CVE Database  (vendor -> list of {cve, versions_affected, severity, desc})
# ---------------------------------------------------------------------------

CVE_DATABASE: Dict[str, List[Dict[str, Any]]] = {
    "fortinet": [
        {
            "cve": "CVE-2023-27997",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "FortiOS heap-based buffer overflow in SSL-VPN pre-authentication",
            "affected_versions": [
                "6.0.0-6.0.16", "6.2.0-6.2.14", "6.4.0-6.4.12",
                "7.0.0-7.0.11", "7.2.0-7.2.4",
            ],
            "fixed_versions": ["6.0.17", "6.2.15", "6.4.13", "7.0.12", "7.2.5"],
        },
        {
            "cve": "CVE-2024-21762",
            "severity": "CRITICAL",
            "cvss": 9.6,
            "description": "FortiOS out-of-bound write in SSL-VPN daemon",
            "affected_versions": [
                "6.0.0-6.0.17", "6.2.0-6.2.15", "6.4.0-6.4.14",
                "7.0.0-7.0.13", "7.2.0-7.2.6", "7.4.0-7.4.2",
            ],
            "fixed_versions": ["6.2.16", "6.4.15", "7.0.14", "7.2.7", "7.4.3"],
        },
        {
            "cve": "CVE-2023-34992",
            "severity": "CRITICAL",
            "cvss": 9.7,
            "description": "FortiSIEM OS command injection via crafted API requests",
            "affected_versions": ["7.0.0", "6.7.0-6.7.5", "6.6.0-6.6.3"],
            "fixed_versions": ["7.0.1", "6.7.6", "6.6.4"],
        },
        {
            "cve": "CVE-2022-42475",
            "severity": "CRITICAL",
            "cvss": 9.3,
            "description": "FortiOS SSL-VPN heap buffer overflow (exploited in the wild)",
            "affected_versions": [
                "6.0.0-6.0.14", "6.2.0-6.2.12", "6.4.0-6.4.10",
                "7.0.0-7.0.8", "7.2.0-7.2.2",
            ],
            "fixed_versions": ["6.0.15", "6.2.13", "6.4.11", "7.0.9", "7.2.3"],
        },
        {
            "cve": "CVE-2024-47575",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "FortiManager missing authentication for critical function (FortiJump)",
            "affected_versions": ["7.0.0-7.0.12", "7.2.0-7.2.7", "7.4.0-7.4.4", "7.6.0"],
            "fixed_versions": ["7.0.13", "7.2.8", "7.4.5", "7.6.1"],
        },
    ],
    "pulse_secure": [
        {
            "cve": "CVE-2021-22893",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "Pulse Connect Secure authentication bypass (actively exploited)",
            "affected_versions": ["9.0R1-9.0R3.3", "9.1R1-9.1R10.1"],
            "fixed_versions": ["9.1R11.4"],
        },
        {
            "cve": "CVE-2019-11510",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "Pulse Secure arbitrary file read pre-authentication",
            "affected_versions": ["8.1R1-8.1R15.0", "8.2R1-8.2R12.0", "8.3R1-8.3R7.0", "9.0R1-9.0R3.3"],
            "fixed_versions": ["8.1R15.1", "8.2R12.1", "8.3R7.1", "9.0R3.4"],
        },
        {
            "cve": "CVE-2023-46805",
            "severity": "HIGH",
            "cvss": 8.2,
            "description": "Ivanti Connect Secure authentication bypass (chained with CVE-2024-21887)",
            "affected_versions": ["9.x", "22.x"],
            "fixed_versions": ["9.1R18.3", "22.4R2.2", "22.5R1.1"],
        },
        {
            "cve": "CVE-2024-21887",
            "severity": "CRITICAL",
            "cvss": 9.1,
            "description": "Ivanti Connect Secure command injection in web components",
            "affected_versions": ["9.x", "22.x"],
            "fixed_versions": ["9.1R18.3", "22.4R2.2", "22.5R1.1", "22.6R1.1"],
        },
    ],
    "cisco_anyconnect": [
        {
            "cve": "CVE-2023-20269",
            "severity": "HIGH",
            "cvss": 9.1,
            "description": "Cisco ASA/FTD unauthorized access and brute-force vulnerability",
            "affected_versions": ["ASA 9.8-9.18.x", "FTD 6.2.3-7.4.x"],
            "fixed_versions": ["ASA 9.16.4.57", "ASA 9.18.3.56", "FTD various"],
        },
        {
            "cve": "CVE-2020-3580",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "description": "Cisco ASA/FTD XSS in WebVPN login page",
            "affected_versions": ["ASA 9.6-9.16.x", "FTD 6.2.2-6.7.x"],
            "fixed_versions": ["ASA 9.8.4.40", "ASA 9.9.2.85", "ASA 9.16.2.3"],
        },
        {
            "cve": "CVE-2023-20095",
            "severity": "HIGH",
            "cvss": 8.6,
            "description": "Cisco ASA/FTD remote access VPN DoS vulnerability",
            "affected_versions": ["ASA 9.16.x-9.18.x", "FTD 7.0-7.4.x"],
            "fixed_versions": ["ASA 9.16.4.19", "ASA 9.18.2.8"],
        },
        {
            "cve": "CVE-2024-20359",
            "severity": "MEDIUM",
            "cvss": 6.0,
            "description": "Cisco ASA/FTD persistent local code execution (ArcaneDoor)",
            "affected_versions": ["ASA 9.x", "FTD 6.x-7.x"],
            "fixed_versions": ["ASA 9.16.4.57", "ASA 9.18.4.22", "FTD various"],
        },
    ],
    "palo_alto": [
        {
            "cve": "CVE-2024-3400",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "description": "PAN-OS GlobalProtect command injection (actively exploited zero-day)",
            "affected_versions": ["10.2.0-10.2.9-h1", "11.0.0-11.0.4-h1", "11.1.0-11.1.2-h3"],
            "fixed_versions": ["10.2.9-h1", "11.0.4-h1", "11.1.2-h3"],
        },
        {
            "cve": "CVE-2021-3064",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "PAN-OS GlobalProtect memory corruption and HTTP smuggling",
            "affected_versions": ["8.1.0-8.1.16"],
            "fixed_versions": ["8.1.17"],
        },
        {
            "cve": "CVE-2024-0012",
            "severity": "CRITICAL",
            "cvss": 9.3,
            "description": "PAN-OS management interface authentication bypass",
            "affected_versions": ["10.2.0-10.2.7-h12", "11.0.0-11.0.5-h2", "11.1.0-11.1.4-h7", "11.2.0-11.2.3-h2"],
            "fixed_versions": ["10.2.7-h13", "11.0.5-h3", "11.1.4-h8", "11.2.3-h3"],
        },
        {
            "cve": "CVE-2024-9474",
            "severity": "HIGH",
            "cvss": 7.2,
            "description": "PAN-OS privilege escalation in management interface (chained with CVE-2024-0012)",
            "affected_versions": ["10.1.0-10.1.14-h4", "10.2.0-10.2.12-h1", "11.0.0-11.0.6-h1", "11.1.0-11.1.5-h1", "11.2.0-11.2.4-h1"],
            "fixed_versions": ["10.1.14-h5", "10.2.12-h2", "11.0.6-h2", "11.1.5-h2", "11.2.4-h2"],
        },
    ],
    "openvpn": [
        {
            "cve": "CVE-2023-46849",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "OpenVPN division by zero crash in --fragment option",
            "affected_versions": ["2.6.0-2.6.6"],
            "fixed_versions": ["2.6.7"],
        },
        {
            "cve": "CVE-2023-46850",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "OpenVPN use-after-free in sending buffer leading to RCE",
            "affected_versions": ["2.6.0-2.6.6"],
            "fixed_versions": ["2.6.7"],
        },
        {
            "cve": "CVE-2022-0547",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "OpenVPN Access Server authentication bypass via plugins",
            "affected_versions": ["2.0.0-2.11.0"],
            "fixed_versions": ["2.11.1"],
        },
    ],
    "sonicwall": [
        {
            "cve": "CVE-2021-20016",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "SonicWall SMA SQL injection pre-authentication",
            "affected_versions": ["SMA 100 10.x"],
            "fixed_versions": ["10.2.0.5-d-29sv"],
        },
        {
            "cve": "CVE-2023-44221",
            "severity": "HIGH",
            "cvss": 7.2,
            "description": "SonicWall SMA OS command injection via SSL-VPN management",
            "affected_versions": ["SMA 100 10.2.1.9-57sv and earlier"],
            "fixed_versions": ["10.2.1.10-62sv"],
        },
        {
            "cve": "CVE-2024-40766",
            "severity": "CRITICAL",
            "cvss": 9.3,
            "description": "SonicWall SonicOS improper access control (exploited by Akira ransomware)",
            "affected_versions": ["SonicOS 5.x-7.0.1-5035"],
            "fixed_versions": ["5.9.2.14-13o", "6.5.4.15.116n", "7.0.1-5072"],
        },
    ],
}

# ---------------------------------------------------------------------------
# MFA indicator patterns
# ---------------------------------------------------------------------------

MFA_INDICATORS = [
    re.compile(r"(?i)(multi.?factor|mfa|two.?factor|2fa|2\-factor)"),
    re.compile(r"(?i)(one.?time|otp|token.?code|authenticator)"),
    re.compile(r"(?i)(duo|okta|rsa.?securid|yubikey|fido)"),
    re.compile(r"(?i)(push.?notification|sms.?verification|second.?factor)"),
    re.compile(r'(?i)(challenge|tokencode|passcode).*(?:input|field|name=)'),
    re.compile(r"(?i)(saml|radius|ldap.*totp)"),
]

# ---------------------------------------------------------------------------
# VPN Fingerprint Definitions
# ---------------------------------------------------------------------------

VPN_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
    "fortinet": {
        "display_name": "Fortinet FortiGate SSL-VPN",
        "paths": [
            "/remote/fgt_lang",
            "/remote/login",
            "/remote/logincheck",
            "/remote/info",
        ],
        "signatures": {
            "headers": [
                re.compile(r"(?i)FortiGate"),
                re.compile(r"(?i)SVPNCOOKIE"),
                re.compile(r"(?i)fgt_lang"),
            ],
            "body": [
                re.compile(r"(?i)FortiGate"),
                re.compile(r"(?i)fortinet"),
                re.compile(r"fgt_lang"),
                re.compile(r"(?i)sslvpn"),
                re.compile(r"/remote/login"),
            ],
        },
        "version_patterns": [
            re.compile(r"FortiOS[- ]?v?(\d+\.\d+\.\d+)", re.I),
            re.compile(r"FortiGate[- ]?v?(\d+\.\d+\.\d+)", re.I),
            re.compile(r"FGT[_-]?(\w+)[- ]v?(\d+\.\d+\.\d+)", re.I),
            re.compile(r"Server:\s*Forti[\w]*[/ ](\d+[\d.]+)", re.I),
        ],
    },
    "pulse_secure": {
        "display_name": "Pulse Secure / Ivanti Connect Secure",
        "paths": [
            "/dana-na/auth/url_default/welcome.cgi",
            "/dana-na/auth/url_0/welcome.cgi",
            "/dana/home/index.cgi",
            "/dana-na/css/ds.js",
        ],
        "signatures": {
            "headers": [
                re.compile(r"(?i)pulse.?secure"),
                re.compile(r"(?i)DSID"),
                re.compile(r"(?i)Ivanti"),
            ],
            "body": [
                re.compile(r"(?i)pulse.?secure"),
                re.compile(r"(?i)ivanti"),
                re.compile(r"(?i)dana-na"),
                re.compile(r"(?i)welcome\.cgi"),
                re.compile(r"(?i)ive_logo"),
            ],
        },
        "version_patterns": [
            re.compile(r"Pulse Secure[, ]*v?(\d+\.\d+[Rr]\d+[\.\d]*)", re.I),
            re.compile(r"Ivanti Connect Secure[, ]*v?(\d+\.\d+[\.\d]*)", re.I),
            re.compile(r"version[\"':\s]+v?(\d+\.\d+[Rr]?\d*[\.\d]*)", re.I),
        ],
    },
    "cisco_anyconnect": {
        "display_name": "Cisco ASA / AnyConnect SSL-VPN",
        "paths": [
            "/+CSCOE+/logon.html",
            "/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=win",
            "/CACHE/sdesktop/install/binaries/",
            "/+webvpn+/index.html",
        ],
        "signatures": {
            "headers": [
                re.compile(r"(?i)webvpn"),
                re.compile(r"(?i)cisco"),
                re.compile(r"(?i)cscoe"),
            ],
            "body": [
                re.compile(r"(?i)cisco"),
                re.compile(r"(?i)AnyConnect"),
                re.compile(r"(?i)CSCOE"),
                re.compile(r"(?i)webvpn"),
                re.compile(r"(?i)Adaptive Security Appliance"),
            ],
        },
        "version_patterns": [
            re.compile(r"Cisco ASA[_ ]?v?(\d+[\d.]+)", re.I),
            re.compile(r"AnyConnect[_ ]?v?(\d+[\d.]+)", re.I),
            re.compile(r"ASA[- ](\d+\.\d+[\(\)\d.]*)", re.I),
            re.compile(r"Version\s*(\d+\.\d+[\(\)\d.]*)", re.I),
        ],
    },
    "palo_alto": {
        "display_name": "Palo Alto GlobalProtect",
        "paths": [
            "/global-protect/login.esp",
            "/global-protect/portal/css/login.css",
            "/ssl-vpn/hipreportcheck.esp",
            "/global-protect/getsoftwarepage.esp",
        ],
        "signatures": {
            "headers": [
                re.compile(r"(?i)PanOS"),
                re.compile(r"(?i)Palo.?Alto"),
            ],
            "body": [
                re.compile(r"(?i)GlobalProtect"),
                re.compile(r"(?i)global-protect"),
                re.compile(r"(?i)Palo.?Alto"),
                re.compile(r"(?i)PanOS"),
                re.compile(r"(?i)login\.esp"),
            ],
        },
        "version_patterns": [
            re.compile(r"PAN-?OS[_ ]?v?(\d+\.\d+[\.\d\-h]*)", re.I),
            re.compile(r"GlobalProtect[_ ]Portal[_ ]?v?(\d+[\.\d]*)", re.I),
            re.compile(r"Palo Alto.*?(\d+\.\d+\.\d+)", re.I),
        ],
    },
    "openvpn": {
        "display_name": "OpenVPN Access Server",
        "paths": [
            "/admin",
            "/admin/",
            "/__session_start__/",
        ],
        "signatures": {
            "headers": [
                re.compile(r"(?i)openvpn"),
                re.compile(r"(?i)OpenVPN-AS"),
            ],
            "body": [
                re.compile(r"(?i)openvpn"),
                re.compile(r"(?i)OpenVPN.*Access Server"),
                re.compile(r"(?i)openvpn-gui"),
            ],
        },
        "version_patterns": [
            re.compile(r"OpenVPN Access Server[_ ]?v?(\d+[\.\d]+)", re.I),
            re.compile(r"openvpn-(\d+[\.\d]+)", re.I),
            re.compile(r"OpenVPN[_ ](\d+\.\d+[\.\d]*)", re.I),
        ],
        "udp_port": 1194,
    },
    "sonicwall": {
        "display_name": "SonicWall SSL-VPN / SMA",
        "paths": [
            "/cgi-bin/welcome",
            "/cgi-bin/main",
            "/cgi-bin/userLogin",
            "/auth.html",
        ],
        "signatures": {
            "headers": [
                re.compile(r"(?i)SonicWall"),
                re.compile(r"(?i)SonicOS"),
                re.compile(r"(?i)SMA"),
            ],
            "body": [
                re.compile(r"(?i)SonicWall"),
                re.compile(r"(?i)SonicOS"),
                re.compile(r"(?i)SMA"),
                re.compile(r"(?i)sonicwall\.com"),
            ],
        },
        "version_patterns": [
            re.compile(r"SonicOS[_ ]?v?(\d+[\.\d\-]+)", re.I),
            re.compile(r"SonicWall.*?v?(\d+\.\d+[\.\d]*)", re.I),
            re.compile(r"SMA\s?\d+.*?v?(\d+\.\d+[\.\d\-sv]*)", re.I),
        ],
    },
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


def _header(text: str) -> str:
    return f"\n  {Fore.WHITE}{Style.BRIGHT}{text}{Style.RESET_ALL}"


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
        f"  {Fore.WHITE}VPN Gateway Scanner v{VERSION} "
        f"| {SECTION} ({MITRE_ID}){Style.RESET_ALL}\n"
        f"  {Fore.WHITE}Findings: {FINDING_REF}{Style.RESET_ALL}\n"
    )


# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------

def _make_session() -> requests.Session:
    """Build a requests Session with retry logic and no TLS verification."""
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    })
    return session


# ---------------------------------------------------------------------------
# SSL Certificate Extraction
# ---------------------------------------------------------------------------

def extract_ssl_cert(host: str, port: int) -> Optional[Dict[str, Any]]:
    """Connect to host:port and extract SSL certificate details."""
    cert_info: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                cert_info["protocol"] = protocol
                cert_info["cipher"] = cipher[0] if cipher else "unknown"
                cert_info["cipher_bits"] = cipher[2] if cipher and len(cipher) > 2 else 0

                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    cert_info["subject_cn"] = subject.get("commonName", "N/A")
                    cert_info["issuer_cn"] = issuer.get("commonName", "N/A")
                    cert_info["issuer_org"] = issuer.get("organizationName", "N/A")
                    cert_info["serial_number"] = cert.get("serialNumber", "N/A")
                    cert_info["not_before"] = cert.get("notBefore", "N/A")
                    cert_info["not_after"] = cert.get("notAfter", "N/A")
                    cert_info["self_signed"] = (
                        subject.get("commonName") == issuer.get("commonName")
                        and subject.get("organizationName", "") == issuer.get("organizationName", "")
                    )
                    # Subject Alternative Names
                    san_list = []
                    for san_type, san_value in cert.get("subjectAltName", []):
                        san_list.append(f"{san_type}:{san_value}")
                    cert_info["san"] = san_list

                    # Check expiry
                    try:
                        not_after = datetime.strptime(
                            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                        )
                        cert_info["expired"] = not_after < datetime.utcnow()
                        cert_info["days_until_expiry"] = (
                            not_after - datetime.utcnow()
                        ).days
                    except (ValueError, KeyError):
                        cert_info["expired"] = None
                        cert_info["days_until_expiry"] = None
                else:
                    cert_info["note"] = "Peer certificate retrieved in binary form only"

    except (socket.timeout, socket.error, ssl.SSLError, OSError) as exc:
        cert_info["error"] = str(exc)

    return cert_info if cert_info else None


# ---------------------------------------------------------------------------
# OpenVPN UDP probe
# ---------------------------------------------------------------------------

def probe_openvpn_udp(host: str, port: int = 1194) -> Optional[Dict[str, Any]]:
    """Send an OpenVPN handshake probe on UDP to detect the service."""
    result: Dict[str, Any] = {"port": port, "protocol": "udp"}
    try:
        # OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 packet (minimal)
        # opcode=7 (P_CONTROL_HARD_RESET_CLIENT_V2), key_id=0
        # session_id = 8 random bytes, packet_id = 0, etc.
        opcode_keyid = (7 << 3) | 0  # 0x38
        session_id = b'\x00' * 8
        hmac_placeholder = b'\x00' * 20  # empty HMAC
        packet_id = b'\x00\x00\x00\x01'
        net_time = b'\x00\x00\x00\x00'
        payload = bytes([opcode_keyid]) + session_id + hmac_placeholder + packet_id + net_time

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(payload, (host, port))
        try:
            data, _ = sock.recvfrom(4096)
            if data:
                result["detected"] = True
                # Check for OpenVPN response (opcode in first byte)
                resp_opcode = (data[0] >> 3) if len(data) > 0 else None
                result["response_opcode"] = resp_opcode
                result["response_length"] = len(data)
                # P_CONTROL_HARD_RESET_SERVER_V2 = 8
                if resp_opcode == 8:
                    result["confirmed"] = True
                else:
                    result["confirmed"] = False
            else:
                result["detected"] = False
        except socket.timeout:
            # No response could mean filtered or not OpenVPN
            result["detected"] = False
            result["note"] = "No UDP response (filtered or not OpenVPN)"
        finally:
            sock.close()
    except (socket.error, OSError) as exc:
        result["detected"] = False
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Core VPN fingerprinting
# ---------------------------------------------------------------------------

def fingerprint_vpn(
    host: str,
    port: int,
    session: requests.Session,
) -> Dict[str, Any]:
    """
    Probe a target for all supported VPN vendors.
    Returns a dict with vendor detections, versions, CVEs, and risk findings.
    """
    result: Dict[str, Any] = {
        "target": host,
        "port": port,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "vendors_detected": [],
        "findings": [],
        "ssl_certificate": None,
        "login_accessible": False,
        "mfa_detected": False,
        "mfa_indicators": [],
        "versions_found": [],
        "cves_matched": [],
        "openvpn_udp": None,
        "raw_probes": {},
    }

    base_https = f"https://{host}:{port}"
    base_http = f"http://{host}:{port}"

    # Determine if HTTPS is available
    use_https = True
    try:
        session.head(base_https, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.SSLError:
        # SSL error but port is listening — still try HTTPS with verify=False
        pass
    except requests.exceptions.ConnectionError:
        use_https = False
    except requests.exceptions.RequestException:
        pass

    base_url = base_https if use_https else base_http

    # Extract SSL certificate
    if use_https:
        print(_tag("INFO", f"Extracting SSL certificate from {host}:{port}"))
        cert_info = extract_ssl_cert(host, port)
        result["ssl_certificate"] = cert_info
        if cert_info:
            cn = cert_info.get("subject_cn", "N/A")
            issuer = cert_info.get("issuer_cn", "N/A")
            print(_tag("INFO", f"Certificate CN: {cn} | Issuer: {issuer}"))
            if cert_info.get("self_signed"):
                result["findings"].append({
                    "id": "SELF_SIGNED_CERT",
                    "severity": "MEDIUM",
                    "title": "Self-signed SSL certificate detected",
                    "detail": f"CN={cn}, Issuer={issuer}",
                })
                print(_tag("MEDIUM", "Self-signed SSL certificate detected"))
            if cert_info.get("expired"):
                result["findings"].append({
                    "id": "EXPIRED_CERT",
                    "severity": "HIGH",
                    "title": "Expired SSL certificate",
                    "detail": f"Expired. Not After: {cert_info.get('not_after', 'N/A')}",
                })
                print(_tag("HIGH", "SSL certificate has EXPIRED"))
            days = cert_info.get("days_until_expiry")
            if days is not None and 0 < days < 30:
                result["findings"].append({
                    "id": "CERT_EXPIRING_SOON",
                    "severity": "LOW",
                    "title": "SSL certificate expiring soon",
                    "detail": f"Expires in {days} days",
                })
                print(_tag("LOW", f"Certificate expiring in {days} days"))

    # Probe each vendor
    all_response_text = ""
    all_response_headers = ""

    for vendor_key, vendor_def in VPN_FINGERPRINTS.items():
        vendor_name = vendor_def["display_name"]
        detected = False
        confidence = 0
        matched_paths: List[str] = []
        matched_sigs: List[str] = []

        print(_header(f"Probing for {vendor_name}..."))

        for path in vendor_def["paths"]:
            url = f"{base_url}{path}"
            try:
                resp = session.get(
                    url,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                )
                status = resp.status_code
                body = resp.text[:10000]  # limit body scan
                headers_str = str(resp.headers)

                # Store for later analysis
                probe_key = f"{vendor_key}:{path}"
                result["raw_probes"][probe_key] = {
                    "url": url,
                    "status_code": status,
                    "content_length": len(resp.text),
                    "headers": dict(resp.headers),
                }

                # A 200 or 401 or 302 on the VPN path is meaningful
                if status in (200, 301, 302, 303, 401, 403):
                    # Check header signatures
                    for sig in vendor_def["signatures"]["headers"]:
                        if sig.search(headers_str):
                            confidence += 3
                            matched_sigs.append(f"header:{sig.pattern}")

                    # Check body signatures
                    for sig in vendor_def["signatures"]["body"]:
                        if sig.search(body):
                            confidence += 2
                            matched_sigs.append(f"body:{sig.pattern}")

                    if status == 200:
                        confidence += 2
                        matched_paths.append(path)
                    elif status in (301, 302, 303):
                        confidence += 1
                        matched_paths.append(f"{path} (redirect)")
                    elif status == 401:
                        confidence += 1
                        matched_paths.append(f"{path} (auth required)")

                    # Accumulate text for version/MFA analysis
                    all_response_text += body + "\n"
                    all_response_headers += headers_str + "\n"

                    if confidence >= 3:
                        print(_tag("INFO", f"  {path} -> HTTP {status} (match confidence: {confidence})"))

            except requests.exceptions.Timeout:
                print(_tag("INFO", f"  {path} -> timeout"))
            except requests.exceptions.ConnectionError:
                pass
            except requests.exceptions.RequestException as exc:
                print(_tag("INFO", f"  {path} -> error: {exc}"))

        # OpenVPN UDP probe
        if vendor_key == "openvpn" and vendor_def.get("udp_port"):
            print(_tag("INFO", f"  Probing UDP/{vendor_def['udp_port']} for OpenVPN..."))
            udp_result = probe_openvpn_udp(host, vendor_def["udp_port"])
            result["openvpn_udp"] = udp_result
            if udp_result and udp_result.get("detected"):
                confidence += 5
                matched_sigs.append("udp:openvpn_handshake")
                if udp_result.get("confirmed"):
                    confidence += 5
                    print(_tag("HIGH", f"  OpenVPN confirmed on UDP/{vendor_def['udp_port']}"))

        # Decision: is this vendor detected?
        if confidence >= 4:
            detected = True
            detection_entry = {
                "vendor": vendor_key,
                "display_name": vendor_name,
                "confidence": confidence,
                "matched_paths": matched_paths,
                "matched_signatures": list(set(matched_sigs)),
            }

            # --- Version extraction ---
            versions: List[str] = []
            combined = all_response_text + all_response_headers
            for vp in vendor_def.get("version_patterns", []):
                matches = vp.findall(combined)
                for m in matches:
                    ver = m if isinstance(m, str) else m[-1]
                    if ver not in versions:
                        versions.append(ver)

            detection_entry["versions"] = versions
            if versions:
                for v in versions:
                    result["versions_found"].append({"vendor": vendor_key, "version": v})

            # --- CVE matching ---
            vendor_cves = CVE_DATABASE.get(vendor_key, [])
            matched_cves: List[Dict[str, Any]] = []

            if versions:
                for cve_entry in vendor_cves:
                    for v in versions:
                        for aff_range in cve_entry["affected_versions"]:
                            if _version_in_range(v, aff_range):
                                if cve_entry["cve"] not in [c["cve"] for c in matched_cves]:
                                    matched_cves.append(cve_entry)
                                    break
            else:
                # No version — flag all critical CVEs as potential
                for cve_entry in vendor_cves:
                    if cve_entry["severity"] == "CRITICAL":
                        potential = dict(cve_entry)
                        potential["status"] = "potential (version unknown)"
                        matched_cves.append(potential)

            detection_entry["cves"] = matched_cves
            for cve in matched_cves:
                if cve not in result["cves_matched"]:
                    result["cves_matched"].append(cve)

            result["vendors_detected"].append(detection_entry)

            sev = "HIGH" if confidence >= 6 else "MEDIUM"
            print(_tag(sev, f"DETECTED: {vendor_name} (confidence: {confidence})"))
            if versions:
                for v in versions:
                    print(_tag("INFO", f"  Version: {v}"))
            if matched_cves:
                for cve in matched_cves:
                    cve_sev = cve["severity"]
                    status = cve.get("status", "affected")
                    print(_tag(cve_sev, f"  {cve['cve']} (CVSS {cve['cvss']}) - {cve['description']} [{status}]"))
        else:
            if confidence > 0:
                print(_tag("INFO", f"  Low confidence ({confidence}) - not confirmed"))

    # --- Login accessibility check ---
    if result["vendors_detected"]:
        result["login_accessible"] = True
        result["findings"].append({
            "id": "VPN_LOGIN_PUBLIC",
            "severity": "HIGH",
            "title": "VPN login portal publicly accessible",
            "detail": (
                f"Detected vendor(s): "
                f"{', '.join(v['display_name'] for v in result['vendors_detected'])}"
            ),
        })
        print(_tag("HIGH", "VPN login portal is publicly accessible"))

    # --- MFA detection ---
    mfa_found = False
    mfa_details: List[str] = []
    for pattern in MFA_INDICATORS:
        matches = pattern.findall(all_response_text)
        if matches:
            mfa_found = True
            for m in matches[:3]:  # limit noise
                token = m if isinstance(m, str) else m[0]
                if token not in mfa_details:
                    mfa_details.append(token)

    result["mfa_detected"] = mfa_found
    result["mfa_indicators"] = mfa_details

    if result["vendors_detected"]:
        if mfa_found:
            print(_tag("INFO", f"MFA indicators found: {', '.join(mfa_details[:5])}"))
            result["findings"].append({
                "id": "MFA_DETECTED",
                "severity": "INFO",
                "title": "MFA indicators present on login page",
                "detail": f"Indicators: {', '.join(mfa_details[:5])}",
            })
        else:
            print(_tag("HIGH", "No MFA indicators detected on VPN login page"))
            result["findings"].append({
                "id": "NO_MFA",
                "severity": "HIGH",
                "title": "No MFA indicators detected on VPN login page",
                "detail": "Login page lacks visible multi-factor authentication prompts",
            })

    # --- CVE-based critical findings ---
    for cve in result["cves_matched"]:
        sev = cve["severity"]
        status = cve.get("status", "affected")
        result["findings"].append({
            "id": cve["cve"],
            "severity": sev,
            "title": f"{cve['cve']} - {cve['description']}",
            "detail": f"CVSS: {cve['cvss']} | Status: {status}",
        })

    # --- Outdated version heuristic ---
    for vinfo in result["versions_found"]:
        vendor_cves = CVE_DATABASE.get(vinfo["vendor"], [])
        is_outdated = False
        for cve_entry in vendor_cves:
            if _version_in_range(vinfo["version"], ",".join(cve_entry["affected_versions"])):
                is_outdated = True
                break
        if is_outdated:
            result["findings"].append({
                "id": "OUTDATED_VERSION",
                "severity": "MEDIUM",
                "title": f"Outdated VPN software version: {vinfo['version']}",
                "detail": f"Vendor: {vinfo['vendor']} - version has known vulnerabilities",
            })
            print(_tag("MEDIUM", f"Outdated version detected: {vinfo['vendor']} {vinfo['version']}"))

    return result


# ---------------------------------------------------------------------------
# Version range matching helper
# ---------------------------------------------------------------------------

def _parse_version_tuple(ver: str) -> Tuple[int, ...]:
    """Extract numeric components from a version string like '7.2.4' or '9.1R11.4'."""
    # Normalize: replace R/r/h/- with dots, strip non-numeric suffixes
    normalized = re.sub(r'[Rrh\-]', '.', ver)
    parts = re.findall(r'\d+', normalized)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_in_range(version: str, range_spec: str) -> bool:
    """
    Check if a version falls within a range specification.
    Supports formats:
      - "6.0.0-6.0.16"  (explicit range)
      - "9.x"           (major version wildcard)
      - "SMA 100 10.x"  (product prefix with wildcard)
      - Single version   (exact match)
    """
    ver_tuple = _parse_version_tuple(version)

    for rng in range_spec.split(","):
        rng = rng.strip()
        # Remove product name prefixes (e.g., "ASA ", "FTD ", "SMA 100 ")
        rng_cleaned = re.sub(r'^[A-Za-z]+\s*\d*\s*', '', rng).strip()
        if not rng_cleaned:
            rng_cleaned = rng

        # Wildcard: "9.x", "22.x"
        wc_match = re.match(r'^(\d+)\.x$', rng_cleaned)
        if wc_match:
            major = int(wc_match.group(1))
            if ver_tuple and ver_tuple[0] == major:
                return True
            continue

        # Range: "6.0.0-6.0.16"
        range_match = re.match(r'^([\d.Rrh\-]+)\-([\d.Rrh\-]+)$', rng_cleaned)
        if range_match:
            low = _parse_version_tuple(range_match.group(1))
            high = _parse_version_tuple(range_match.group(2))
            if low <= ver_tuple <= high:
                return True
            continue

        # "and earlier" style
        if "and earlier" in rng_cleaned.lower():
            ceiling = re.findall(r'[\d.Rrh]+', rng_cleaned)
            if ceiling:
                high = _parse_version_tuple(ceiling[-1])
                if ver_tuple <= high:
                    return True
            continue

        # Single version or partial match
        spec_tuple = _parse_version_tuple(rng_cleaned)
        if spec_tuple and ver_tuple == spec_tuple:
            return True
        # Partial prefix match (e.g., version "7.0.10" matches spec "7.0")
        if spec_tuple and len(spec_tuple) < len(ver_tuple):
            if ver_tuple[:len(spec_tuple)] == spec_tuple:
                return True

    return False


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

def calculate_risk_score(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate aggregate risk score from findings."""
    total = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total += RISK_WEIGHTS.get(sev, 0)

    # Determine overall risk level
    if severity_counts["CRITICAL"] > 0:
        overall = "CRITICAL"
    elif severity_counts["HIGH"] >= 2:
        overall = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        overall = "HIGH"
    elif severity_counts["MEDIUM"] > 0:
        overall = "MEDIUM"
    elif severity_counts["LOW"] > 0:
        overall = "LOW"
    else:
        overall = "INFO"

    return {
        "total_score": total,
        "overall_risk": overall,
        "severity_counts": severity_counts,
        "max_possible": sum(RISK_WEIGHTS[s] * severity_counts[s] for s in severity_counts),
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build the final JSON report for all scanned targets."""
    report = {
        "tool": "HAKA AI VPN Gateway Scanner",
        "tool_id": TOOL_ID,
        "version": VERSION,
        "mitre_technique": MITRE_ID,
        "finding_reference": FINDING_REF,
        "section": SECTION,
        "scan_start": datetime.now(timezone.utc).isoformat(),
        "targets_scanned": len(results),
        "results": [],
        "executive_summary": {},
    }

    total_findings = 0
    all_vendors: List[str] = []
    all_cves: List[str] = []
    overall_critical = 0
    overall_high = 0

    for res in results:
        # Risk score per target
        risk = calculate_risk_score(res.get("findings", []))
        res["risk_score"] = risk
        total_findings += len(res.get("findings", []))

        for v in res.get("vendors_detected", []):
            if v["display_name"] not in all_vendors:
                all_vendors.append(v["display_name"])

        for c in res.get("cves_matched", []):
            if c["cve"] not in all_cves:
                all_cves.append(c["cve"])
                if c["severity"] == "CRITICAL":
                    overall_critical += 1
                elif c["severity"] == "HIGH":
                    overall_high += 1

        overall_critical += risk["severity_counts"].get("CRITICAL", 0)
        overall_high += risk["severity_counts"].get("HIGH", 0)

        # Strip raw probe data from final report to keep it clean
        clean_result = {k: v for k, v in res.items() if k != "raw_probes"}
        report["results"].append(clean_result)

    report["scan_end"] = datetime.now(timezone.utc).isoformat()
    report["executive_summary"] = {
        "total_targets": len(results),
        "total_findings": total_findings,
        "vpn_vendors_found": all_vendors,
        "unique_cves": all_cves,
        "critical_findings": overall_critical,
        "high_findings": overall_high,
        "recommendation": _build_recommendation(all_vendors, all_cves, overall_critical),
    }

    return report


def _build_recommendation(
    vendors: List[str], cves: List[str], critical_count: int
) -> str:
    """Generate a human-readable recommendation based on findings."""
    parts: List[str] = []

    if critical_count > 0:
        parts.append(
            f"URGENT: {critical_count} critical finding(s) detected. "
            "Immediate patching and incident response assessment recommended."
        )

    if cves:
        parts.append(
            f"CVEs identified: {', '.join(cves[:10])}. "
            "Verify patch status and apply vendor security updates."
        )

    if vendors:
        parts.append(
            "Restrict VPN login portal exposure via firewall ACLs or "
            "geo-IP restrictions. Enforce MFA on all VPN authentication."
        )
    else:
        parts.append("No VPN gateways positively identified on scanned targets.")

    return " ".join(parts)


def save_report(report: Dict[str, Any], targets: List[str]) -> Path:
    """Write JSON report to disk and return the file path."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_tag = targets[0].replace(".", "_") if len(targets) == 1 else f"{len(targets)}_targets"
    filename = f"vpn_scan_{target_tag}_{ts}.json"
    filepath = REPORTS_DIR / filename

    with open(filepath, "w") as fh:
        json.dump(report, fh, indent=2, default=str)

    return filepath


# ---------------------------------------------------------------------------
# Result summary display
# ---------------------------------------------------------------------------

def print_summary(report: Dict[str, Any]) -> None:
    """Print a formatted summary of the scan to stdout."""
    summary = report.get("executive_summary", {})

    print(f"\n{'=' * 72}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{'=' * 72}")

    print(f"  Targets scanned:   {summary.get('total_targets', 0)}")
    print(f"  Total findings:    {summary.get('total_findings', 0)}")

    vendors = summary.get("vpn_vendors_found", [])
    if vendors:
        print(f"  VPN vendors found: {', '.join(vendors)}")
    else:
        print(f"  VPN vendors found: {Fore.GREEN}None detected{Style.RESET_ALL}")

    cves = summary.get("unique_cves", [])
    if cves:
        print(f"  Unique CVEs:       {Fore.RED}{', '.join(cves)}{Style.RESET_ALL}")

    crit = summary.get("critical_findings", 0)
    high = summary.get("high_findings", 0)
    if crit > 0:
        print(
            f"\n  {Fore.RED}{Style.BRIGHT}[!] CRITICAL FINDINGS: {crit}{Style.RESET_ALL}"
        )
    if high > 0:
        print(
            f"  {Fore.RED}[!] HIGH FINDINGS: {high}{Style.RESET_ALL}"
        )

    for res in report.get("results", []):
        target = res.get("target", "?")
        risk = res.get("risk_score", {})
        overall = risk.get("overall_risk", "INFO")
        score = risk.get("total_score", 0)
        color = SEVERITY_COLORS.get(overall, "")

        print(f"\n  {Fore.WHITE}{Style.BRIGHT}Target: {target}:{res.get('port', 443)}{Style.RESET_ALL}")
        print(f"    Risk Level: {color}{overall}{Style.RESET_ALL} (score: {score})")

        severity_counts = risk.get("severity_counts", {})
        counts_str = " | ".join(
            f"{s}: {c}" for s, c in severity_counts.items() if c > 0
        )
        if counts_str:
            print(f"    Findings:   {counts_str}")

        for finding in res.get("findings", []):
            print(_tag(finding["severity"], f"{finding['title']}"))

    print(f"\n{'=' * 72}")
    rec = summary.get("recommendation", "")
    if rec:
        print(f"  {Fore.YELLOW}{Style.BRIGHT}Recommendation:{Style.RESET_ALL}")
        # Word wrap at ~68 chars
        words = rec.split()
        line = "    "
        for w in words:
            if len(line) + len(w) + 1 > 72:
                print(line)
                line = "    " + w
            else:
                line += " " + w if line.strip() else w
        if line.strip():
            print(line)
    print(f"{'=' * 72}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            f"HAKA AI VPN Gateway Scanner v{VERSION} "
            f"| {SECTION} ({MITRE_ID})"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python haka_vpn_scanner.py --target 192.168.1.1\n"
            "  python haka_vpn_scanner.py --target vpn.example.com --port 8443\n"
            "  python haka_vpn_scanner.py --targets vpn_ips.txt\n"
            "  python haka_vpn_scanner.py --target 10.0.0.1 --port 443 --no-udp\n"
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--target",
        help="Single target IP or hostname",
    )
    group.add_argument(
        "--targets",
        help="File containing one target per line (IP or hostname)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="TCP port to scan (default: 443)",
    )
    parser.add_argument(
        "--no-udp",
        action="store_true",
        help="Skip OpenVPN UDP probe",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=TIMEOUT,
        help=f"Request timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--output",
        help="Custom output file path for JSON report",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal console output",
    )
    return parser.parse_args()


def load_targets(filepath: str) -> List[str]:
    """Load targets from a file, one per line. Supports # comments."""
    targets: List[str] = []
    path = Path(filepath)
    if not path.is_file():
        sys.exit(f"[!] Target file not found: {filepath}")
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                # Support "host:port" or just "host"
                targets.append(line.split("#")[0].strip())
    if not targets:
        sys.exit(f"[!] No valid targets found in {filepath}")
    return targets


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    colorama_init(autoreset=False)
    args = parse_args()

    global TIMEOUT
    TIMEOUT = args.timeout

    if not args.quiet:
        banner()

    # Build target list
    targets: List[Tuple[str, int]] = []
    if args.target:
        host = args.target
        port = args.port
        # Support host:port notation
        if ":" in host and not host.startswith("["):
            parts = host.rsplit(":", 1)
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                pass
        targets.append((host, port))
    else:
        raw_targets = load_targets(args.targets)
        for t in raw_targets:
            host = t
            port = args.port
            if ":" in t and not t.startswith("["):
                parts = t.rsplit(":", 1)
                host = parts[0]
                try:
                    port = int(parts[1])
                except ValueError:
                    pass
            targets.append((host, port))

    print(f"  {Fore.WHITE}Targets: {len(targets)} | Timeout: {TIMEOUT}s{Style.RESET_ALL}\n")

    # Disable UDP if requested
    if args.no_udp:
        for vendor_key in VPN_FINGERPRINTS:
            if "udp_port" in VPN_FINGERPRINTS[vendor_key]:
                del VPN_FINGERPRINTS[vendor_key]["udp_port"]

    session = _make_session()
    results: List[Dict[str, Any]] = []

    for idx, (host, port) in enumerate(targets, 1):
        print(f"\n{'─' * 72}")
        print(
            f"  {Fore.CYAN}{Style.BRIGHT}[{idx}/{len(targets)}] "
            f"Scanning {host}:{port}{Style.RESET_ALL}"
        )
        print(f"{'─' * 72}")

        try:
            result = fingerprint_vpn(host, port, session)
            results.append(result)
        except KeyboardInterrupt:
            print(f"\n  {Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            break
        except Exception as exc:
            print(_tag("HIGH", f"Error scanning {host}:{port} - {exc}"))
            results.append({
                "target": host,
                "port": port,
                "error": str(exc),
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "vendors_detected": [],
                "findings": [{
                    "id": "SCAN_ERROR",
                    "severity": "INFO",
                    "title": f"Scan error: {exc}",
                    "detail": str(exc),
                }],
            })

    # Generate and save report
    report = generate_report(results)

    if args.output:
        report_path = Path(args.output)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
    else:
        report_path = save_report(report, [t[0] for t in targets])

    if not args.quiet:
        print_summary(report)

    print(
        f"  {Fore.GREEN}{Style.BRIGHT}Report saved: {report_path}{Style.RESET_ALL}\n"
    )


if __name__ == "__main__":
    main()
