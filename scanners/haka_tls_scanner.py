#!/usr/bin/env python3
"""
HAKA AI - Tool 8: TLS/SSL Analyzer
====================================
Maps to: Section E1 - TLS Downgrade (T1557)
Findings: CRIT-AWB-06, CRIT-ET-02

Comprehensive TLS/SSL security assessment tool that tests protocol versions,
cipher suites, certificate validity, and HTTP security headers. Produces
risk-scored findings with actionable remediation guidance.

Author : HAKA AI Framework
Version: 1.0.0
"""

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import struct
import sys
import textwrap
import time
import warnings
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    # Graceful fallback if colorama is missing
    class _Stub:
        def __getattr__(self, _):
            return ""
    Fore = Style = _Stub()

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
    from cryptography.x509.oid import ExtensionOID, NameOID
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = r"""
  _   _    _    _  __    _        _____ _     ____
 | | | |  / \  | |/ /   / \      |_   _| |   / ___|
 | |_| | / _ \ | ' /   / _ \       | | | |   \___ \
 |  _  |/ ___ \| . \  / ___ \      | | | |___ ___) |
 |_| |_/_/   \_\_|\_\/_/   \_\     |_| |_____|____/
          TLS/SSL Analyzer  v1.0  [Tool 8]
"""

REPORTS_DIR = Path("/home/kironix/HAKA-AI/reports")

# Risk levels with numeric weight for scoring
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

RISK_WEIGHT = {
    RISK_CRITICAL: 40,
    RISK_HIGH: 25,
    RISK_MEDIUM: 10,
    RISK_LOW: 3,
    RISK_INFO: 0,
}

# Protocol version testing configuration
# Each entry: (label, TLSVersion enum, expected_state, risk_if_enabled)
PROTOCOL_TESTS = []

if hasattr(ssl, "TLSVersion"):
    _TV = ssl.TLSVersion
    PROTOCOL_TESTS = [
        ("SSLv3",   _TV.SSLv3,   "disabled", RISK_CRITICAL),
        ("TLS 1.0", _TV.TLSv1,   "disabled", RISK_HIGH),
        ("TLS 1.1", _TV.TLSv1_1, "disabled", RISK_HIGH),
        ("TLS 1.2", _TV.TLSv1_2, "enabled",  RISK_INFO),
        ("TLS 1.3", _TV.TLSv1_3, "enabled",  RISK_INFO),
    ]

# Cipher categorisation patterns
WEAK_CIPHER_PATTERNS = {
    "NULL":   (re.compile(r"(?:^|-)NULL(?:-|$)|eNULL|aNULL", re.I), RISK_HIGH),
    "EXPORT": (re.compile(r"EXPORT", re.I),                         RISK_HIGH),
    "RC4":    (re.compile(r"RC4", re.I),                             RISK_HIGH),
    "DES":    (re.compile(r"(?:^|[^3])DES(?!-CBC3)", re.I),         RISK_HIGH),
    "3DES":   (re.compile(r"3DES|DES-CBC3", re.I),                  RISK_MEDIUM),
    "MD5":    (re.compile(r"MD5", re.I),                             RISK_HIGH),
}

# Strong forward-secrecy + AEAD patterns
STRONG_CIPHER_PATTERN = re.compile(
    r"^(TLS_AES|TLS_CHACHA|ECDHE.*GCM|ECDHE.*CHACHA|DHE.*GCM|DHE.*CHACHA)",
    re.I,
)

DEFAULT_TIMEOUT = 5  # seconds

# Comprehensive list of ciphers to test individually (OpenSSL names)
# Grouped by category for readability
CIPHER_LIST_FULL = [
    # --- TLS 1.3 (these are actually suiteB, tested via protocol, listed for completeness) ---
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    # --- ECDHE + AEAD (strong) ---
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    # --- ECDHE + CBC ---
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    # --- DHE + AEAD (strong) ---
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    # --- DHE + CBC ---
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA",
    # --- RSA key exchange (no FS) ---
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    # --- Weak / deprecated ---
    "ECDHE-RSA-DES-CBC3-SHA",
    "ECDHE-ECDSA-DES-CBC3-SHA",
    "DHE-RSA-DES-CBC3-SHA",
    "DES-CBC3-SHA",
    "DES-CBC-SHA",
    "DHE-RSA-DES-CBC-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "ECDHE-RSA-RC4-SHA",
    "ECDHE-ECDSA-RC4-SHA",
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
    "EXP-RC2-CBC-MD5",
    # --- NULL ---
    "NULL-SHA256",
    "NULL-SHA",
    "NULL-MD5",
    "ECDHE-RSA-NULL-SHA",
    "ECDHE-ECDSA-NULL-SHA",
]

# Reduced quick-scan list (most telling ciphers per category)
CIPHER_LIST_QUICK = [
    # TLS 1.3
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    # Strong ECDHE
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    # CBC
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    # RSA key exchange
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    # Weak
    "DES-CBC3-SHA",
    "DES-CBC-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "NULL-SHA",
    "NULL-MD5",
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _color_risk(level: str) -> str:
    """Return colorized risk label."""
    colors = {
        RISK_CRITICAL: Fore.RED + Style.BRIGHT,
        RISK_HIGH: Fore.RED,
        RISK_MEDIUM: Fore.YELLOW,
        RISK_LOW: Fore.CYAN,
        RISK_INFO: Fore.GREEN,
    }
    return f"{colors.get(level, '')}{level}{Style.RESET_ALL}"


def _ok(text: str) -> str:
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"


def _warn(text: str) -> str:
    return f"{Fore.YELLOW}{text}{Style.RESET_ALL}"


def _bad(text: str) -> str:
    return f"{Fore.RED}{text}{Style.RESET_ALL}"


def _dim(text: str) -> str:
    return f"{Style.DIM}{text}{Style.RESET_ALL}"


def _bold(text: str) -> str:
    return f"{Style.BRIGHT}{text}{Style.RESET_ALL}"


def _header(title: str, width: int = 72) -> str:
    pad = width - len(title) - 4
    return f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 2} {title} {'=' * max(pad, 2)}{Style.RESET_ALL}"


def _subheader(title: str, width: int = 72) -> str:
    pad = width - len(title) - 4
    return f"{Fore.CYAN}{'─' * 2} {title} {'─' * max(pad, 2)}{Style.RESET_ALL}"


def _table_row(cols: List[Tuple[str, int]], fill: str = " ") -> str:
    """Build a fixed-width row. cols = [(text, width), ...]"""
    parts = []
    for text, width in cols:
        # Strip ANSI for length calculation
        raw = re.sub(r"\x1b\[[0-9;]*m", "", str(text))
        padding = max(width - len(raw), 0)
        parts.append(f"{text}{fill * padding}")
    return "  ".join(parts)


def _timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# TLS Protocol version testing
# ---------------------------------------------------------------------------

class ProtocolTester:
    """Test which TLS/SSL protocol versions a target supports."""

    def __init__(self, host: str, port: int, timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout

    def test_version(self, label: str, tls_version: "ssl.TLSVersion") -> Dict[str, Any]:
        """Attempt a handshake forcing a specific TLS version. Returns result dict."""
        result: Dict[str, Any] = {
            "version": label,
            "supported": False,
            "cipher": None,
            "error": None,
        }
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Intentionally setting deprecated protocol versions to test them.
            # Suppress the resulting DeprecationWarnings.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version
            # Allow all ciphers so we don't mask support
            try:
                ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
            except ssl.SSLError:
                try:
                    ctx.set_ciphers("ALL:COMPLEMENTOFALL")
                except ssl.SSLError:
                    ctx.set_ciphers("ALL")
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    result["supported"] = True
                    result["cipher"] = tls.cipher()
        except ssl.SSLError as exc:
            result["error"] = str(exc)
        except OSError as exc:
            result["error"] = str(exc)
        return result

    def test_all(self) -> List[Dict[str, Any]]:
        results = []
        for label, ver, _expected, _risk in PROTOCOL_TESTS:
            res = self.test_version(label, ver)
            results.append(res)
        return results


# ---------------------------------------------------------------------------
# Cipher suite testing
# ---------------------------------------------------------------------------

class CipherTester:
    """Test individual cipher suite acceptance per protocol version."""

    def __init__(self, host: str, port: int, timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout

    @staticmethod
    def classify_cipher(name: str) -> Tuple[str, str]:
        """Return (category, risk_level) for a cipher name."""
        for cat, (pattern, risk) in WEAK_CIPHER_PATTERNS.items():
            if pattern.search(name):
                return cat, risk
        if STRONG_CIPHER_PATTERN.match(name):
            return "STRONG", RISK_INFO
        return "ACCEPTABLE", RISK_LOW

    def test_cipher(self, cipher_name: str, tls_version: Optional["ssl.TLSVersion"] = None) -> Dict[str, Any]:
        """Attempt handshake with a single cipher. Returns result dict."""
        result: Dict[str, Any] = {
            "cipher": cipher_name,
            "supported": False,
            "protocol": None,
            "bits": None,
            "category": None,
            "risk": None,
            "error": None,
        }
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            # TLS 1.3 ciphers cannot be set via set_ciphers in OpenSSL;
            # they are controlled separately. Detect TLS 1.3 cipher names.
            is_tls13_cipher = cipher_name.startswith("TLS_")

            if tls_version:
                ctx.minimum_version = tls_version
                ctx.maximum_version = tls_version
            elif is_tls13_cipher:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            else:
                # Pin to TLS 1.2 and below for non-TLS1.3 ciphers.
                # If we allow TLS 1.3, the server may upgrade and ignore
                # our set_ciphers() call, giving a false positive.
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2

            if not is_tls13_cipher:
                try:
                    ctx.set_ciphers(f"{cipher_name}:@SECLEVEL=0")
                except ssl.SSLError:
                    try:
                        ctx.set_ciphers(cipher_name)
                    except ssl.SSLError as exc:
                        result["error"] = f"cipher not available locally: {exc}"
                        return result
            # For TLS 1.3, Python/OpenSSL picks the cipher from the server's preference.
            # We cannot force a single TLS 1.3 cipher via set_ciphers but we can check
            # if the negotiated cipher matches.

            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    neg_cipher, neg_proto, neg_bits = tls.cipher()
                    if is_tls13_cipher:
                        # Accept only if negotiated cipher matches what we wanted
                        if neg_cipher == cipher_name:
                            result["supported"] = True
                        else:
                            result["supported"] = False
                            result["error"] = f"negotiated {neg_cipher} instead"
                            return result
                    else:
                        # Verify we actually got the cipher we asked for.
                        # Some servers may negotiate a different cipher from
                        # the single-cipher list if OpenSSL's internals allow it.
                        if neg_cipher != cipher_name:
                            result["supported"] = False
                            result["error"] = f"negotiated {neg_cipher} instead"
                            return result
                        result["supported"] = True
                    result["protocol"] = neg_proto
                    result["bits"] = neg_bits
                    cat, risk = self.classify_cipher(neg_cipher)
                    result["category"] = cat
                    result["risk"] = risk
        except ssl.SSLError as exc:
            result["error"] = str(exc)
        except OSError as exc:
            result["error"] = str(exc)
        return result

    def test_list(self, cipher_list: List[str]) -> List[Dict[str, Any]]:
        results = []
        for name in cipher_list:
            r = self.test_cipher(name)
            results.append(r)
        return results


# ---------------------------------------------------------------------------
# Certificate analysis
# ---------------------------------------------------------------------------

class CertAnalyzer:
    """Fetch and analyze the server certificate."""

    def __init__(self, host: str, port: int, timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout

    def fetch_cert_der(self) -> Optional[bytes]:
        """Retrieve the DER-encoded leaf certificate."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    der = tls.getpeercert(binary_form=True)
                    return der
        except Exception:
            return None

    def fetch_cert_chain_pem(self) -> Optional[List[bytes]]:
        """Retrieve the full certificate chain as list of PEM bytes (if possible)."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as tls:
                    chain = tls.get_verified_chain()
                    if chain:
                        return [c.public_bytes(serialization.Encoding.PEM) if hasattr(c, 'public_bytes') else c for c in chain]
        except AttributeError:
            pass  # get_verified_chain not available in older Python
        except Exception:
            pass
        return None

    def analyze(self) -> Dict[str, Any]:
        """Full certificate analysis. Returns a rich dict of findings."""
        info: Dict[str, Any] = {
            "available": False,
            "subject": None,
            "issuer": None,
            "serial": None,
            "sans": [],
            "not_before": None,
            "not_after": None,
            "days_until_expiry": None,
            "expired": None,
            "self_signed": None,
            "key_type": None,
            "key_bits": None,
            "signature_algorithm": None,
            "sha256_fingerprint": None,
            "findings": [],
        }

        der = self.fetch_cert_der()
        if not der:
            info["findings"].append({
                "title": "Certificate retrieval failed",
                "risk": RISK_HIGH,
                "detail": "Could not retrieve a certificate from the server.",
            })
            return info

        if not HAS_CRYPTOGRAPHY:
            info["available"] = True
            info["findings"].append({
                "title": "cryptography library not installed",
                "risk": RISK_INFO,
                "detail": "Install 'cryptography' for full certificate analysis.",
            })
            return info

        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:
            info["findings"].append({
                "title": "Certificate parse error",
                "risk": RISK_HIGH,
                "detail": str(exc),
            })
            return info

        info["available"] = True
        now = datetime.datetime.now(datetime.timezone.utc)

        # Subject
        info["subject"] = cert.subject.rfc4514_string()

        # Issuer
        info["issuer"] = cert.issuer.rfc4514_string()

        # Serial
        info["serial"] = format(cert.serial_number, "X")

        # Validity
        # Handle both aware and naive datetimes from cryptography
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        info["not_before"] = not_before.isoformat()
        info["not_after"] = not_after.isoformat()
        delta = not_after - now
        info["days_until_expiry"] = delta.days
        info["expired"] = delta.days < 0

        if info["expired"]:
            info["findings"].append({
                "title": "Certificate has EXPIRED",
                "risk": RISK_CRITICAL,
                "detail": f"Expired {abs(delta.days)} days ago on {not_after.date()}.",
            })
        elif delta.days <= 30:
            info["findings"].append({
                "title": "Certificate expiring soon",
                "risk": RISK_MEDIUM,
                "detail": f"Expires in {delta.days} days on {not_after.date()}.",
            })

        # SANs
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            ip_addrs = [str(ip) for ip in san_ext.value.get_values_for_type(x509.IPAddress)]
            info["sans"] = dns_names + ip_addrs
        except x509.ExtensionNotFound:
            info["sans"] = []

        # Self-signed check
        info["self_signed"] = cert.subject == cert.issuer
        if info["self_signed"]:
            info["findings"].append({
                "title": "Self-signed certificate",
                "risk": RISK_MEDIUM,
                "detail": "The certificate is self-signed and will not be trusted by clients without explicit exception.",
            })

        # Key analysis
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            info["key_type"] = "RSA"
            info["key_bits"] = pub.key_size
            if pub.key_size < 2048:
                info["findings"].append({
                    "title": f"Weak RSA key ({pub.key_size} bits)",
                    "risk": RISK_MEDIUM,
                    "detail": "RSA keys shorter than 2048 bits are considered weak. Upgrade to >= 2048 bits.",
                })
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            info["key_type"] = "ECDSA"
            info["key_bits"] = pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            info["key_type"] = "DSA"
            info["key_bits"] = pub.key_size
            info["findings"].append({
                "title": "DSA key usage",
                "risk": RISK_MEDIUM,
                "detail": "DSA keys are deprecated in modern TLS deployments.",
            })
        elif isinstance(pub, (ed25519.Ed25519PublicKey,)):
            info["key_type"] = "Ed25519"
            info["key_bits"] = 256
        elif isinstance(pub, (ed448.Ed448PublicKey,)):
            info["key_type"] = "Ed448"
            info["key_bits"] = 448
        else:
            info["key_type"] = type(pub).__name__
            info["key_bits"] = None

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, "_name") else str(cert.signature_algorithm_oid.dotted_string)
        info["signature_algorithm"] = sig_algo
        if "sha1" in sig_algo.lower() or "sha-1" in sig_algo.lower():
            info["findings"].append({
                "title": "SHA-1 signature algorithm",
                "risk": RISK_MEDIUM,
                "detail": f"Certificate uses {sig_algo}. SHA-1 is cryptographically weak.",
            })
        if "md5" in sig_algo.lower():
            info["findings"].append({
                "title": "MD5 signature algorithm",
                "risk": RISK_CRITICAL,
                "detail": f"Certificate uses {sig_algo}. MD5 is completely broken.",
            })

        # Fingerprint
        info["sha256_fingerprint"] = cert.fingerprint(hashes.SHA256()).hex(":")

        return info


# ---------------------------------------------------------------------------
# HTTP security header checks
# ---------------------------------------------------------------------------

class HeaderChecker:
    """Probe HTTP(S) response headers for security directives."""

    HEADERS_OF_INTEREST = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    def __init__(self, host: str, port: int, timeout: int = DEFAULT_TIMEOUT):
        self.host = host
        self.port = port
        self.timeout = timeout

    def check(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "reachable": False,
            "headers": {},
            "findings": [],
        }
        if not HAS_REQUESTS:
            result["findings"].append({
                "title": "requests library not available",
                "risk": RISK_INFO,
                "detail": "Install 'requests' for HTTP header analysis.",
            })
            return result

        url = f"https://{self.host}:{self.port}/"
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            result["reachable"] = True
            # Collect headers
            for h in self.HEADERS_OF_INTEREST:
                val = resp.headers.get(h)
                if val:
                    result["headers"][h] = val

            # --- HSTS ---
            hsts = resp.headers.get("Strict-Transport-Security")
            if not hsts:
                result["findings"].append({
                    "title": "Missing HSTS header",
                    "risk": RISK_MEDIUM,
                    "detail": "Strict-Transport-Security header is absent. Clients may connect over plain HTTP.",
                })
            else:
                # Parse max-age
                ma_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                if ma_match:
                    max_age = int(ma_match.group(1))
                    if max_age < 31536000:
                        result["findings"].append({
                            "title": f"HSTS max-age too short ({max_age}s)",
                            "risk": RISK_LOW,
                            "detail": "Recommended minimum is 31536000 (1 year).",
                        })
                if "includesubdomains" not in hsts.lower():
                    result["findings"].append({
                        "title": "HSTS missing includeSubDomains",
                        "risk": RISK_LOW,
                        "detail": "Subdomains are not covered by HSTS.",
                    })
                if "preload" not in hsts.lower():
                    result["findings"].append({
                        "title": "HSTS missing preload directive",
                        "risk": RISK_LOW,
                        "detail": "Without preload, browsers won't include this domain in their built-in HSTS list.",
                    })

            # --- X-Content-Type-Options ---
            if not resp.headers.get("X-Content-Type-Options"):
                result["findings"].append({
                    "title": "Missing X-Content-Type-Options",
                    "risk": RISK_LOW,
                    "detail": "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
                })

            # --- X-Frame-Options ---
            if not resp.headers.get("X-Frame-Options"):
                result["findings"].append({
                    "title": "Missing X-Frame-Options",
                    "risk": RISK_LOW,
                    "detail": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to mitigate clickjacking.",
                })

            # --- Content-Security-Policy ---
            if not resp.headers.get("Content-Security-Policy"):
                result["findings"].append({
                    "title": "Missing Content-Security-Policy",
                    "risk": RISK_LOW,
                    "detail": "CSP helps prevent XSS and data injection attacks.",
                })

        except requests.exceptions.SSLError as exc:
            result["findings"].append({
                "title": "HTTPS connection error",
                "risk": RISK_INFO,
                "detail": f"SSL error during header check: {exc}",
            })
        except requests.exceptions.ConnectionError as exc:
            result["findings"].append({
                "title": "Connection refused for header check",
                "risk": RISK_INFO,
                "detail": str(exc),
            })
        except requests.exceptions.Timeout:
            result["findings"].append({
                "title": "HTTP request timed out",
                "risk": RISK_INFO,
                "detail": f"Timed out after {self.timeout}s.",
            })
        except Exception as exc:
            result["findings"].append({
                "title": "Header check error",
                "risk": RISK_INFO,
                "detail": str(exc),
            })

        return result


# ---------------------------------------------------------------------------
# Risk scoring engine
# ---------------------------------------------------------------------------

class RiskScorer:
    """Aggregate all findings into a single risk score and grade."""

    GRADES = [
        (0,   "A+"),
        (5,   "A"),
        (15,  "B"),
        (30,  "C"),
        (60,  "D"),
        (100, "F"),
    ]

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def add(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)

    def add_many(self, findings: List[Dict[str, Any]]) -> None:
        self.findings.extend(findings)

    def score(self) -> int:
        total = 0
        for f in self.findings:
            total += RISK_WEIGHT.get(f.get("risk", RISK_INFO), 0)
        return total

    def grade(self) -> str:
        s = self.score()
        for threshold, letter in self.GRADES:
            if s <= threshold:
                return letter
        return "F"

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {
            RISK_CRITICAL: 0, RISK_HIGH: 0, RISK_MEDIUM: 0, RISK_LOW: 0, RISK_INFO: 0,
        }
        for f in self.findings:
            level = f.get("risk", RISK_INFO)
            counts[level] = counts.get(level, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_json_report(
    target: str,
    port: int,
    protocol_results: List[Dict],
    cipher_results: List[Dict],
    cert_info: Dict,
    header_info: Dict,
    scorer: RiskScorer,
) -> str:
    """Generate JSON report and write to reports directory. Returns file path."""
    report = {
        "tool": "HAKA TLS/SSL Analyzer",
        "tool_id": "tool-8",
        "version": "1.0.0",
        "mapping": {
            "mitre_technique": "T1557",
            "section": "E1 - TLS Downgrade",
            "findings_ref": ["CRIT-AWB-06", "CRIT-ET-02"],
        },
        "scan_time": _timestamp(),
        "target": target,
        "port": port,
        "risk_score": scorer.score(),
        "risk_grade": scorer.grade(),
        "finding_counts": scorer.summary(),
        "protocols": protocol_results,
        "ciphers": [c for c in cipher_results if c["supported"]],
        "ciphers_rejected": [c["cipher"] for c in cipher_results if not c["supported"] and c.get("error") and "not available locally" not in str(c.get("error", ""))],
        "certificate": cert_info,
        "http_headers": header_info,
        "all_findings": scorer.findings,
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
    filename = f"tls_scan_{safe_host}_{port}_{ts}.json"
    filepath = REPORTS_DIR / filename
    with open(filepath, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    return str(filepath)


# ---------------------------------------------------------------------------
# Console display
# ---------------------------------------------------------------------------

def display_banner():
    print(f"{Fore.CYAN}{Style.BRIGHT}{BANNER}{Style.RESET_ALL}")


def display_protocol_results(results: List[Dict], scorer: RiskScorer):
    print(_header("Protocol Support"))
    print()
    print(_table_row([
        (_bold("Protocol"), 12),
        (_bold("Status"), 14),
        (_bold("Risk"), 12),
        (_bold("Cipher Negotiated"), 40),
    ]))
    print("─" * 80)

    for res, (label, _ver, expected, risk_if_enabled) in zip(results, PROTOCOL_TESTS):
        supported = res["supported"]
        if supported:
            if expected == "disabled":
                status_str = _bad("ENABLED")
                risk_str = _color_risk(risk_if_enabled)
                scorer.add({
                    "title": f"{label} protocol enabled",
                    "risk": risk_if_enabled,
                    "detail": f"{label} is deprecated/insecure and should be disabled.",
                })
            else:
                status_str = _ok("ENABLED")
                risk_str = _color_risk(RISK_INFO)
            cipher_str = res["cipher"][0] if res["cipher"] else "N/A"
        else:
            if expected == "enabled":
                status_str = _warn("DISABLED")
                risk_str = _color_risk(RISK_LOW)
                scorer.add({
                    "title": f"{label} not supported",
                    "risk": RISK_LOW,
                    "detail": f"{label} is recommended but not supported by the server.",
                })
            else:
                status_str = _ok("DISABLED")
                risk_str = _color_risk(RISK_INFO)
            cipher_str = _dim("N/A")

        print(_table_row([
            (label, 12),
            (status_str, 14),
            (risk_str, 12),
            (cipher_str, 40),
        ]))
    print()


def display_cipher_results(results: List[Dict], scorer: RiskScorer):
    print(_header("Cipher Suite Analysis"))
    print()

    supported = [r for r in results if r["supported"]]
    rejected = [r for r in results if not r["supported"]]

    if not supported:
        print(f"  {_warn('No ciphers accepted from test list (server may use a restricted set).')}")
        print()
        return

    # Group by category
    by_cat: Dict[str, List[Dict]] = {}
    for c in supported:
        cat = c.get("category", "UNKNOWN")
        by_cat.setdefault(cat, []).append(c)

    # Print strong first, then acceptable, then weak categories
    order = ["STRONG", "ACCEPTABLE", "3DES", "RC4", "DES", "NULL", "EXPORT", "MD5", "UNKNOWN"]
    for cat in order:
        ciphers = by_cat.get(cat, [])
        if not ciphers:
            continue

        if cat == "STRONG":
            cat_color = _ok(f"[{cat}]")
        elif cat == "ACCEPTABLE":
            cat_color = _ok(f"[{cat}]")
        else:
            cat_color = _bad(f"[{cat}]")

        print(f"  {cat_color}")
        for c in ciphers:
            risk = c.get("risk", RISK_INFO)
            bits = c.get("bits", "?")
            proto = c.get("protocol", "?")
            name = c["cipher"]

            if risk in (RISK_HIGH, RISK_CRITICAL):
                name_str = _bad(name)
                # Add finding
                scorer.add({
                    "title": f"Weak cipher supported: {name}",
                    "risk": risk,
                    "detail": f"Category: {cat}. This cipher should be disabled.",
                })
            elif risk == RISK_MEDIUM:
                name_str = _warn(name)
                scorer.add({
                    "title": f"Deprecated cipher supported: {name}",
                    "risk": risk,
                    "detail": f"Category: {cat}. Consider disabling this cipher.",
                })
            else:
                name_str = _ok(name)

            print(f"    {name_str}  {_dim(f'({proto}, {bits} bits)')}")
        print()

    print(f"  {_bold('Summary')}: {_ok(str(len(supported)))} accepted, "
          f"{_dim(str(len(rejected)))} rejected out of {len(results)} tested")
    print()


def display_cert_info(info: Dict, scorer: RiskScorer):
    print(_header("Certificate Analysis"))
    print()

    if not info.get("available"):
        for f in info.get("findings", []):
            print(f"  {_color_risk(f['risk'])}: {f['title']}")
            scorer.add(f)
        print()
        return

    def _row(label: str, value: str, width: int = 22):
        print(f"  {_bold(label.ljust(width))}: {value}")

    _row("Subject", info.get("subject", "N/A"))
    _row("Issuer", info.get("issuer", "N/A"))
    _row("Serial", info.get("serial", "N/A"))

    sans = info.get("sans", [])
    if sans:
        _row("SANs", ", ".join(sans[:5]))
        if len(sans) > 5:
            print(f"  {''.ljust(22)}  ... and {len(sans) - 5} more")

    _row("Valid From", info.get("not_before", "N/A"))
    _row("Valid Until", info.get("not_after", "N/A"))

    days = info.get("days_until_expiry")
    if days is not None:
        if days < 0:
            _row("Expiry Status", _bad(f"EXPIRED ({abs(days)} days ago)"))
        elif days <= 30:
            _row("Expiry Status", _warn(f"{days} days remaining"))
        else:
            _row("Expiry Status", _ok(f"{days} days remaining"))

    self_signed = info.get("self_signed")
    if self_signed is True:
        _row("Self-Signed", _bad("YES"))
    elif self_signed is False:
        _row("Self-Signed", _ok("No"))

    key_type = info.get("key_type", "Unknown")
    key_bits = info.get("key_bits")
    if key_bits:
        if key_type == "RSA" and key_bits < 2048:
            _row("Public Key", _bad(f"{key_type} {key_bits} bits (WEAK)"))
        else:
            _row("Public Key", _ok(f"{key_type} {key_bits} bits"))
    else:
        _row("Public Key", f"{key_type}")

    sig = info.get("signature_algorithm", "Unknown")
    if "sha1" in sig.lower() or "md5" in sig.lower():
        _row("Signature Algorithm", _bad(sig))
    else:
        _row("Signature Algorithm", _ok(sig))

    fp = info.get("sha256_fingerprint")
    if fp:
        _row("SHA-256 Fingerprint", _dim(fp))

    # Register findings with scorer
    for f in info.get("findings", []):
        scorer.add(f)
        print(f"\n  {_color_risk(f['risk'])}: {f['title']}")
        print(f"    {_dim(f['detail'])}")

    print()


def display_header_results(info: Dict, scorer: RiskScorer):
    print(_header("HTTP Security Headers"))
    print()

    if not info.get("reachable") and not info.get("headers"):
        for f in info.get("findings", []):
            print(f"  {_color_risk(f['risk'])}: {f['title']}")
            scorer.add(f)
        print()
        return

    headers = info.get("headers", {})
    all_headers = HeaderChecker.HEADERS_OF_INTEREST

    for h in all_headers:
        val = headers.get(h)
        if val:
            # Truncate long values for display
            display_val = val if len(val) <= 60 else val[:57] + "..."
            print(f"  {_ok('[PRESENT]')} {_bold(h)}: {display_val}")
        else:
            print(f"  {_warn('[MISSING]')} {_bold(h)}")

    # Register findings
    for f in info.get("findings", []):
        scorer.add(f)

    if info.get("findings"):
        print()
        for f in info["findings"]:
            print(f"  {_color_risk(f['risk'])}: {f['title']}")
    print()


def display_risk_summary(scorer: RiskScorer):
    print(_header("Risk Assessment"))
    print()

    score = scorer.score()
    grade = scorer.grade()
    counts = scorer.summary()

    # Grade with color
    grade_colors = {
        "A+": Fore.GREEN + Style.BRIGHT,
        "A": Fore.GREEN,
        "B": Fore.CYAN,
        "C": Fore.YELLOW,
        "D": Fore.RED,
        "F": Fore.RED + Style.BRIGHT,
    }
    grade_col = grade_colors.get(grade, "")
    print(f"  Overall Grade: {grade_col}{grade}{Style.RESET_ALL}  (score: {score})")
    print()

    print(f"  {_bad(f'CRITICAL: {counts[RISK_CRITICAL]}')}  |  "
          f"{Fore.RED}HIGH: {counts[RISK_HIGH]}{Style.RESET_ALL}  |  "
          f"{_warn(f'MEDIUM: {counts[RISK_MEDIUM]}')}  |  "
          f"{Fore.CYAN}LOW: {counts[RISK_LOW]}{Style.RESET_ALL}  |  "
          f"{_ok(f'INFO: {counts[RISK_INFO]}')}")
    print()

    # List all non-INFO findings
    important = [f for f in scorer.findings if f["risk"] != RISK_INFO]
    if important:
        print(_subheader("Findings Requiring Attention"))
        print()
        for f in sorted(important, key=lambda x: RISK_WEIGHT.get(x["risk"], 0), reverse=True):
            print(f"  {_color_risk(f['risk']):>12}  {f['title']}")
            if f.get("detail"):
                wrapped = textwrap.fill(f["detail"], width=64, initial_indent="                ", subsequent_indent="                ")
                print(f"{_dim(wrapped)}")
    else:
        print(f"  {_ok('No significant findings. Configuration looks solid.')}")

    print()


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_scan(target: str, port: int, full_cipher_test: bool = False, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Execute the full scan pipeline and return the JSON report path."""
    scorer = RiskScorer()

    display_banner()
    print(f"  Target : {_bold(target)}")
    print(f"  Port   : {_bold(str(port))}")
    print(f"  Time   : {_dim(_timestamp())}")
    print(f"  Mode   : {'Full cipher enumeration' if full_cipher_test else 'Quick scan'}")
    print()

    # --- Phase 1: Connectivity check ---
    print(f"  {_dim('[*] Testing connectivity...')}")
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
        sock.close()
        print(f"  {_ok('[+] Port {}/{} is open.'.format(target, port))}")
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        print(f"  {_bad(f'[!] Cannot connect to {target}:{port} - {exc}')}")
        print(f"  {_bad('[!] Scan aborted.')}")
        sys.exit(1)
    print()

    # --- Phase 2: Protocol versions ---
    print(f"  {_dim('[*] Testing protocol versions...')}")
    proto_tester = ProtocolTester(target, port, timeout)
    proto_results = proto_tester.test_all()
    display_protocol_results(proto_results, scorer)

    # --- Phase 3: Cipher suites ---
    cipher_list = CIPHER_LIST_FULL if full_cipher_test else CIPHER_LIST_QUICK
    total = len(cipher_list)
    print(f"  {_dim(f'[*] Testing {total} cipher suites...')}")
    cipher_tester = CipherTester(target, port, timeout)

    cipher_results = []
    for idx, name in enumerate(cipher_list, 1):
        # Progress indicator (overwrite line)
        pct = int(idx / total * 100)
        sys.stdout.write(f"\r  {_dim(f'[*] Progress: {idx}/{total} ({pct}%)')}")
        sys.stdout.flush()
        r = cipher_tester.test_cipher(name)
        cipher_results.append(r)
    print()  # newline after progress
    display_cipher_results(cipher_results, scorer)

    # --- Phase 4: Certificate ---
    print(f"  {_dim('[*] Analyzing certificate...')}")
    cert_analyzer = CertAnalyzer(target, port, timeout)
    cert_info = cert_analyzer.analyze()
    display_cert_info(cert_info, scorer)

    # --- Phase 5: HTTP headers ---
    print(f"  {_dim('[*] Checking HTTP security headers...')}")
    header_checker = HeaderChecker(target, port, timeout)
    header_info = header_checker.check()
    display_header_results(header_info, scorer)

    # --- Phase 6: TLS 1.3 specific check ---
    tls13_supported = any(r["supported"] for r in proto_results if r["version"] == "TLS 1.3")
    if not tls13_supported:
        scorer.add({
            "title": "TLS 1.3 not supported",
            "risk": RISK_LOW,
            "detail": "TLS 1.3 provides improved security and performance. Consider enabling it.",
        })

    # --- Risk summary ---
    display_risk_summary(scorer)

    # --- JSON report ---
    report_path = generate_json_report(
        target, port, proto_results, cipher_results, cert_info, header_info, scorer,
    )
    print(f"  {_ok(f'[+] JSON report saved to: {report_path}')}")
    print()

    return report_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="haka_tls_scanner",
        description="HAKA AI - TLS/SSL Security Analyzer (Tool 8)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s --target 192.168.122.210
              %(prog)s --target example.com --port 8443
              %(prog)s --target 10.0.0.1 --port 443 --full-cipher-test
              %(prog)s --target 192.168.122.210 --ports 443,8443,993
              %(prog)s --target 192.168.122.210 --timeout 10

            Maps to: Section E1 - TLS Downgrade (T1557)
            Findings: CRIT-AWB-06, CRIT-ET-02
        """),
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target hostname or IP address",
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=443,
        help="Single port to scan (default: 443)",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Comma-separated list of ports to scan (e.g., 443,8443,993,995)",
    )
    parser.add_argument(
        "--full-cipher-test", "-f",
        action="store_true",
        default=False,
        help="Test the full cipher suite list (~50 ciphers) instead of the quick set (~18)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        default=False,
        help="Suppress console output, only write JSON report",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    target = args.target

    # Resolve hostname to verify it's reachable
    try:
        socket.getaddrinfo(target, None)
    except socket.gaierror as exc:
        print(f"{Fore.RED}[!] Cannot resolve hostname '{target}': {exc}{Style.RESET_ALL}")
        sys.exit(1)

    # Determine ports to scan
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(f"{Fore.RED}[!] Invalid port list: {args.ports}{Style.RESET_ALL}")
            sys.exit(1)
    else:
        ports = [args.port]

    # Validate ports
    for p in ports:
        if not (1 <= p <= 65535):
            print(f"{Fore.RED}[!] Invalid port number: {p}{Style.RESET_ALL}")
            sys.exit(1)

    report_paths = []
    for port in ports:
        if len(ports) > 1:
            print(f"\n{'#' * 80}")
            print(f"# Scanning port {port}")
            print(f"{'#' * 80}")

        path = run_scan(target, port, args.full_cipher_test, args.timeout)
        report_paths.append(path)

    if len(report_paths) > 1:
        print(_header("All Reports"))
        for rp in report_paths:
            print(f"  {_ok('[+]')} {rp}")
        print()

    print(f"{Fore.CYAN}{Style.BRIGHT}Scan complete.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
