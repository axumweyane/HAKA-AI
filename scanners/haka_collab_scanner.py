#!/usr/bin/env python3
"""
HAKA AI - Mattermost / Collaboration Platform Scanner
(Tool 10: F1 - Mattermost T1078/T1530)

Findings: CRIT-BOA-03, CRIT-BOA-04, CRIT-BOA-05, CRIT-BOA-06

Detects and audits collaboration platforms for security misconfigurations:
  Mattermost, Slack, Microsoft Teams, Rocket.Chat, Jira, Confluence

Author:  HAKA AI Framework
Version: 1.0.0
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

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

# Suppress SSL warnings for lab use
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
TIMEOUT = 10  # seconds for every network operation
REPORTS_DIR = Path("/home/kironix/HAKA-AI/reports")

MATTERMOST_DEFAULT_PORTS = [8065, 443, 80]
SLACK_WEBHOOK_PATTERN = re.compile(
    r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+",
    re.IGNORECASE,
)
TEAMS_WEBHOOK_PATTERN = re.compile(
    r"https://[a-z0-9-]+\.webhook\.office\.com/",
    re.IGNORECASE,
)

RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# ---------------------------------------------------------------------------
# Known Mattermost CVEs (curated list for version mapping)
# ---------------------------------------------------------------------------

MATTERMOST_CVES: list[dict[str, Any]] = [
    {"cve": "CVE-2024-1402", "fixed_in": "9.4.0", "severity": "HIGH",
     "description": "Server-Side Request Forgery via file preview"},
    {"cve": "CVE-2024-1949", "fixed_in": "9.4.2", "severity": "MEDIUM",
     "description": "Stored XSS in markdown rendering"},
    {"cve": "CVE-2024-2446", "fixed_in": "9.5.0", "severity": "HIGH",
     "description": "Authentication bypass via OAuth flow"},
    {"cve": "CVE-2024-24776", "fixed_in": "9.3.1", "severity": "CRITICAL",
     "description": "Remote code execution via file upload handler"},
    {"cve": "CVE-2024-29221", "fixed_in": "9.5.2", "severity": "HIGH",
     "description": "Privilege escalation through team invitation"},
    {"cve": "CVE-2023-48369", "fixed_in": "9.2.3", "severity": "HIGH",
     "description": "SSRF in integration attachments"},
    {"cve": "CVE-2023-47865", "fixed_in": "9.1.4", "severity": "MEDIUM",
     "description": "Information disclosure in channel API"},
    {"cve": "CVE-2023-45316", "fixed_in": "9.0.2", "severity": "HIGH",
     "description": "Blind SSRF via Open Graph metadata"},
    {"cve": "CVE-2023-40703", "fixed_in": "8.1.1", "severity": "HIGH",
     "description": "Improper access control in playbooks plugin"},
    {"cve": "CVE-2023-35075", "fixed_in": "7.10.5", "severity": "CRITICAL",
     "description": "SQL injection in search functionality"},
    {"cve": "CVE-2023-2797", "fixed_in": "7.9.6", "severity": "HIGH",
     "description": "Path traversal in file download endpoint"},
    {"cve": "CVE-2023-2515", "fixed_in": "7.9.5", "severity": "MEDIUM",
     "description": "CSRF in admin console actions"},
    {"cve": "CVE-2022-4045", "fixed_in": "7.4.0", "severity": "HIGH",
     "description": "Improper authorization in channel management"},
    {"cve": "CVE-2022-3257", "fixed_in": "7.3.0", "severity": "MEDIUM",
     "description": "Denial of service via crafted markdown"},
    {"cve": "CVE-2025-20051", "fixed_in": "10.2.1", "severity": "HIGH",
     "description": "SSRF via crafted invite link"},
    {"cve": "CVE-2025-24490", "fixed_in": "10.3.0", "severity": "CRITICAL",
     "description": "Authentication bypass in SAML SSO flow"},
    {"cve": "CVE-2025-25279", "fixed_in": "10.4.1", "severity": "HIGH",
     "description": "Stored XSS through custom emoji upload"},
]

# Third-party tracking / integration indicators
THIRD_PARTY_INDICATORS = {
    "stripe": {
        "patterns": [r"js\.stripe\.com", r"stripe\.com/v3"],
        "severity": "MEDIUM",
        "description": "Stripe.js payment integration detected -- unexpected for internal collaboration platform",
    },
    "google_analytics": {
        "patterns": [r"google-analytics\.com", r"googletagmanager\.com", r"gtag/js"],
        "severity": "LOW",
        "description": "Google Analytics tracking detected on collaboration platform",
    },
    "facebook_pixel": {
        "patterns": [r"connect\.facebook\.net", r"fbevents\.js"],
        "severity": "MEDIUM",
        "description": "Facebook tracking pixel detected -- data may be exfiltrated to Meta",
    },
    "hotjar": {
        "patterns": [r"static\.hotjar\.com", r"hotjar\.com/c/hotjar"],
        "severity": "MEDIUM",
        "description": "Hotjar session recording detected -- captures user interactions",
    },
    "mixpanel": {
        "patterns": [r"cdn\.mxpnl\.com", r"mixpanel\.com"],
        "severity": "LOW",
        "description": "Mixpanel analytics detected on collaboration platform",
    },
    "intercom": {
        "patterns": [r"widget\.intercom\.io", r"intercom\.com"],
        "severity": "LOW",
        "description": "Intercom widget detected -- third-party chat integration",
    },
    "segment": {
        "patterns": [r"cdn\.segment\.com", r"api\.segment\.io"],
        "severity": "LOW",
        "description": "Segment analytics detected -- telemetry data collection",
    },
    "sentry": {
        "patterns": [r"browser\.sentry-cdn\.com", r"sentry\.io"],
        "severity": "LOW",
        "description": "Sentry error tracking detected -- may leak stack traces externally",
    },
}

# Remediation recommendations mapped to finding categories
REMEDIATION_MAP: dict[str, str] = {
    "public_signup": (
        "Disable public email signup. Navigate to System Console > "
        "Authentication > Signup > Enable Open Server, set to false. "
        "Use invite-only or SSO authentication."
    ),
    "mfa_disabled": (
        "Enforce MFA for all users. System Console > Authentication > MFA > "
        "Enforce Multi-factor Authentication = true. Require TOTP-based MFA."
    ),
    "weak_password": (
        "Increase minimum password length to at least 12 characters. "
        "System Console > Authentication > Password > Minimum Password Length. "
        "Enable complexity requirements (uppercase, lowercase, number, symbol)."
    ),
    "api_unauthenticated": (
        "Restrict API access to authenticated users only. Review rate limiting "
        "settings and ensure tokens are rotated regularly. Disable unnecessary "
        "API endpoints via config."
    ),
    "outdated_version": (
        "Upgrade Mattermost to the latest stable release. Outdated versions "
        "may contain known CVEs. Follow the official upgrade guide at "
        "https://docs.mattermost.com/upgrade/upgrading-mattermost-server.html"
    ),
    "third_party_tracking": (
        "Remove or audit third-party JavaScript integrations. External trackers "
        "on an internal collaboration platform increase the attack surface and "
        "may exfiltrate sensitive metadata."
    ),
    "version_disclosure": (
        "Suppress version information in HTTP responses and API endpoints. "
        "Configure a reverse proxy to strip server headers."
    ),
    "slack_webhook_exposed": (
        "Rotate exposed Slack webhook URLs immediately. Store webhook URLs in "
        "environment variables, not in source code or public configurations."
    ),
    "data_retention": (
        "Configure data retention policies. System Console > Compliance > "
        "Data Retention Policy. Set message and file retention appropriate "
        "to your compliance requirements."
    ),
    "cve_vulnerable": (
        "Upgrade to the latest patched version to remediate known CVEs. "
        "Review the Mattermost security updates page for details."
    ),
    "rocketchat_exposed": (
        "Restrict Rocket.Chat registration and harden configuration. "
        "Disable public registration, enforce 2FA, and limit API access."
    ),
    "jira_exposed": (
        "Restrict Jira/Confluence access to authenticated users. Disable "
        "anonymous access in Global Permissions. Apply security advisories."
    ),
    "teams_webhook_exposed": (
        "Rotate Microsoft Teams webhook URLs. Restrict connector creation "
        "to authorized users via Teams admin center policies."
    ),
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
        f"  {Fore.WHITE}Collaboration Platform Scanner v{VERSION} "
        f"| F1 - Mattermost (T1078/T1530){Style.RESET_ALL}\n"
    )


def section_header(title: str) -> None:
    print(f"\n  {Fore.GREEN}{Style.BRIGHT}[*] {title}{Style.RESET_ALL}")
    print(f"  {'─' * 58}")


# ---------------------------------------------------------------------------
# HTTP session factory
# ---------------------------------------------------------------------------

def _build_session() -> requests.Session:
    """Build a requests session with retry logic and disabled SSL verification."""
    session = requests.Session()
    session.verify = False
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "HEAD", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "HAKA-AI/1.0 CollabScanner",
        "Accept": "application/json, text/html, */*",
    })
    return session


def _base_url(target: str, port: int, use_https: bool = True) -> str:
    """Construct base URL from target and port."""
    scheme = "https" if use_https else "http"
    if port in (443, 8443):
        scheme = "https"
    elif port == 80:
        scheme = "http"
    return f"{scheme}://{target}:{port}"


# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------

def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse dotted version string to a comparable tuple."""
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_lt(a: str, b: str) -> bool:
    """Return True if version a < version b."""
    return _parse_version(a) < _parse_version(b)


def _version_age_months(version_str: str) -> Optional[int]:
    """
    Estimate age in months based on known Mattermost release cadence.
    Returns None if version cannot be mapped.
    """
    # Approximate release dates for major versions
    release_dates: dict[str, str] = {
        "10.4": "2025-02-15", "10.3": "2024-12-15", "10.2": "2024-11-15",
        "10.1": "2024-10-15", "10.0": "2024-09-15",
        "9.11": "2024-08-16", "9.10": "2024-07-16", "9.9": "2024-06-16",
        "9.8": "2024-05-16", "9.7": "2024-04-16", "9.6": "2024-03-16",
        "9.5": "2024-02-16", "9.4": "2024-01-16", "9.3": "2023-12-16",
        "9.2": "2023-11-16", "9.1": "2023-10-16", "9.0": "2023-09-16",
        "8.1": "2023-08-16", "8.0": "2023-07-16",
        "7.10": "2023-04-16", "7.9": "2023-03-16", "7.8": "2023-02-16",
        "7.7": "2023-01-16", "7.4": "2022-10-16", "7.3": "2022-09-16",
    }
    # Extract major.minor
    match = re.match(r"(\d+\.\d+)", version_str)
    if not match:
        return None
    major_minor = match.group(1)
    if major_minor not in release_dates:
        return None
    release_date = datetime.strptime(release_dates[major_minor], "%Y-%m-%d")
    now = datetime.now()
    delta = now - release_date
    return max(0, int(delta.days / 30.44))


# ---------------------------------------------------------------------------
# Mattermost checks
# ---------------------------------------------------------------------------

def detect_mattermost(session: requests.Session, target: str,
                      port: int) -> dict[str, Any]:
    """Attempt to detect a Mattermost instance and gather configuration."""
    result: dict[str, Any] = {
        "detected": False,
        "base_url": None,
        "version": None,
        "client_config": {},
        "server_headers": {},
        "findings": [],
    }

    # Try HTTPS first, then HTTP
    schemes = ["https", "http"] if port not in (80,) else ["http"]
    if port == 80:
        schemes = ["http"]
    elif port == 443:
        schemes = ["https"]

    base = None
    for scheme in schemes:
        test_url = f"{scheme}://{target}:{port}"
        try:
            resp = session.get(test_url, timeout=TIMEOUT, allow_redirects=True)
            if resp.status_code < 500:
                base = test_url
                result["server_headers"] = dict(resp.headers)
                # Check if this looks like Mattermost
                body = resp.text.lower()
                if any(indicator in body for indicator in [
                    "mattermost", "mm_config", "root id=root",
                    "signup_user_complete",
                ]):
                    result["detected"] = True
                elif "mattermost" in resp.headers.get("X-Request-Id", "").lower():
                    result["detected"] = True
                elif "mattermost" in resp.headers.get("Server", "").lower():
                    result["detected"] = True
                # Check the login page
                if "/login" in resp.url or "/signup" in resp.url:
                    result["detected"] = True
                break
        except requests.exceptions.RequestException:
            continue

    if not base:
        result["findings"].append({
            "severity": "INFO",
            "message": f"No HTTP service found on {target}:{port}",
            "category": "detection",
        })
        return result

    result["base_url"] = base

    # Try the Mattermost API client config endpoint (unauthenticated)
    config_url = f"{base}/api/v4/config/client?format=old"
    try:
        resp = session.get(config_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            try:
                config = resp.json()
                result["client_config"] = config
                result["detected"] = True

                # Extract version
                version = config.get("Version", config.get("BuildNumber", ""))
                if version:
                    result["version"] = version
                    result["findings"].append({
                        "severity": "INFO",
                        "message": f"Mattermost version detected: {version}",
                        "category": "version_disclosure",
                        "remediation": "version_disclosure",
                    })
            except (json.JSONDecodeError, ValueError):
                pass
        elif resp.status_code == 401:
            result["findings"].append({
                "severity": "INFO",
                "message": "Client config endpoint requires authentication (good)",
                "category": "api_access",
            })
        elif resp.status_code == 404:
            # Might not be Mattermost
            pass
    except requests.exceptions.RequestException as exc:
        result["findings"].append({
            "severity": "INFO",
            "message": f"Could not reach config endpoint: {type(exc).__name__}",
            "category": "detection",
        })

    # Try version from API system ping
    ping_url = f"{base}/api/v4/system/ping"
    try:
        resp = session.get(ping_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            result["detected"] = True
            try:
                ping_data = resp.json()
                if "server_version" in ping_data:
                    result["version"] = ping_data["server_version"]
            except (json.JSONDecodeError, ValueError):
                pass
    except requests.exceptions.RequestException:
        pass

    # Check /api/v4/users endpoint (unauthenticated access = bad)
    users_url = f"{base}/api/v4/users"
    try:
        resp = session.get(users_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            result["findings"].append({
                "severity": "CRITICAL",
                "message": (
                    "CRIT-BOA-03: User enumeration possible -- /api/v4/users "
                    "accessible without authentication"
                ),
                "category": "api_unauthenticated",
                "remediation": "api_unauthenticated",
            })
        elif resp.status_code in (401, 403):
            result["findings"].append({
                "severity": "INFO",
                "message": "Users API endpoint requires authentication (expected)",
                "category": "api_access",
            })
    except requests.exceptions.RequestException:
        pass

    # Check /api/v4/teams endpoint
    teams_url = f"{base}/api/v4/teams"
    try:
        resp = session.get(teams_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            try:
                teams = resp.json()
                if isinstance(teams, list) and len(teams) > 0:
                    result["findings"].append({
                        "severity": "HIGH",
                        "message": (
                            "CRIT-BOA-04: Team listing exposed -- /api/v4/teams "
                            f"returns {len(teams)} team(s) without authentication"
                        ),
                        "category": "api_unauthenticated",
                        "remediation": "api_unauthenticated",
                    })
            except (json.JSONDecodeError, ValueError):
                pass
    except requests.exceptions.RequestException:
        pass

    # Check /api/v4/channels endpoint
    channels_url = f"{base}/api/v4/channels"
    try:
        resp = session.get(channels_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            result["findings"].append({
                "severity": "HIGH",
                "message": (
                    "Channel listing exposed -- /api/v4/channels accessible "
                    "without authentication"
                ),
                "category": "api_unauthenticated",
                "remediation": "api_unauthenticated",
            })
    except requests.exceptions.RequestException:
        pass

    if not result["detected"]:
        # Final heuristic: check page title or common Mattermost paths
        try:
            resp = session.get(f"{base}/login", timeout=TIMEOUT)
            if resp.status_code == 200 and "mattermost" in resp.text.lower():
                result["detected"] = True
        except requests.exceptions.RequestException:
            pass

    if not result["detected"]:
        result["findings"].append({
            "severity": "INFO",
            "message": f"Service on {target}:{port} does not appear to be Mattermost",
            "category": "detection",
        })

    return result


def check_mattermost_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze the Mattermost client configuration for security issues."""
    findings: list[dict[str, Any]] = []

    if not config:
        return findings

    # CRIT-BOA-05: Public signup enabled
    enable_signup = config.get("EnableSignUpWithEmail", "")
    if str(enable_signup).lower() == "true":
        findings.append({
            "severity": "CRITICAL",
            "message": (
                "CRIT-BOA-05: Public email signup is ENABLED -- anyone "
                "can register an account on this Mattermost instance"
            ),
            "category": "public_signup",
            "remediation": "public_signup",
        })
    elif str(enable_signup).lower() == "false":
        findings.append({
            "severity": "INFO",
            "message": "Public email signup is disabled (good)",
            "category": "public_signup",
        })

    enable_open_server = config.get("EnableOpenServer", "")
    if str(enable_open_server).lower() == "true":
        findings.append({
            "severity": "HIGH",
            "message": (
                "Open Server mode is ENABLED -- users can join without "
                "an invitation link"
            ),
            "category": "public_signup",
            "remediation": "public_signup",
        })

    # CRIT-BOA-06: MFA not enforced
    enforce_mfa = config.get("EnforceMultifactorAuthentication", "")
    enable_mfa = config.get("EnableMultifactorAuthentication", "")
    if str(enforce_mfa).lower() != "true":
        if str(enable_mfa).lower() == "true":
            findings.append({
                "severity": "HIGH",
                "message": (
                    "CRIT-BOA-06: MFA is available but NOT enforced -- "
                    "users may opt out of multi-factor authentication"
                ),
                "category": "mfa_disabled",
                "remediation": "mfa_disabled",
            })
        else:
            findings.append({
                "severity": "CRITICAL",
                "message": (
                    "CRIT-BOA-06: MFA is completely DISABLED -- no multi-factor "
                    "authentication protection available"
                ),
                "category": "mfa_disabled",
                "remediation": "mfa_disabled",
            })
    else:
        findings.append({
            "severity": "INFO",
            "message": "MFA is enforced for all users (good)",
            "category": "mfa_disabled",
        })

    # Password length check
    min_length = config.get("PasswordMinimumLength", "")
    if min_length:
        try:
            min_len = int(min_length)
            if min_len < 8:
                findings.append({
                    "severity": "CRITICAL",
                    "message": (
                        f"Minimum password length is {min_len} characters -- "
                        "dangerously weak, should be at least 12"
                    ),
                    "category": "weak_password",
                    "remediation": "weak_password",
                })
            elif min_len < 12:
                findings.append({
                    "severity": "HIGH",
                    "message": (
                        f"Minimum password length is {min_len} characters -- "
                        "below recommended minimum of 12"
                    ),
                    "category": "weak_password",
                    "remediation": "weak_password",
                })
            else:
                findings.append({
                    "severity": "INFO",
                    "message": f"Minimum password length: {min_len} characters (acceptable)",
                    "category": "weak_password",
                })
        except ValueError:
            pass

    # Password complexity
    for check_key, label in [
        ("PasswordRequireLowercase", "lowercase"),
        ("PasswordRequireUppercase", "uppercase"),
        ("PasswordRequireNumber", "number"),
        ("PasswordRequireSymbol", "symbol"),
    ]:
        val = config.get(check_key, "")
        if str(val).lower() == "false":
            findings.append({
                "severity": "MEDIUM",
                "message": f"Password does not require {label} characters",
                "category": "weak_password",
                "remediation": "weak_password",
            })

    # Rate limiting
    enable_rate_limit = config.get("EnableRateLimiter", "")
    if str(enable_rate_limit).lower() == "false":
        findings.append({
            "severity": "MEDIUM",
            "message": (
                "Rate limiting is DISABLED -- brute force attacks are not throttled"
            ),
            "category": "api_unauthenticated",
            "remediation": "api_unauthenticated",
        })

    # Email verification
    require_email_verify = config.get("RequireEmailVerification", "")
    if str(require_email_verify).lower() == "false":
        findings.append({
            "severity": "MEDIUM",
            "message": (
                "Email verification is not required -- accounts can be "
                "created with unverified email addresses"
            ),
            "category": "public_signup",
            "remediation": "public_signup",
        })

    # Data retention
    enable_data_retention = config.get("DataRetentionEnableMessageDeletion", "")
    if str(enable_data_retention).lower() == "false":
        findings.append({
            "severity": "LOW",
            "message": "Message data retention policy is not configured",
            "category": "data_retention",
            "remediation": "data_retention",
        })

    enable_file_retention = config.get("DataRetentionEnableFileDeletion", "")
    if str(enable_file_retention).lower() == "false":
        findings.append({
            "severity": "LOW",
            "message": "File data retention policy is not configured",
            "category": "data_retention",
            "remediation": "data_retention",
        })

    # Guest accounts
    enable_guest = config.get("EnableGuestAccounts", "")
    if str(enable_guest).lower() == "true":
        findings.append({
            "severity": "LOW",
            "message": "Guest accounts are enabled -- verify guest access is properly scoped",
            "category": "public_signup",
        })

    # Bot accounts
    enable_bot = config.get("EnableBotAccountCreation", "")
    if str(enable_bot).lower() == "true":
        findings.append({
            "severity": "LOW",
            "message": "Bot account creation is enabled -- ensure bot tokens are managed",
            "category": "api_unauthenticated",
        })

    return findings


def check_mattermost_version(version: str) -> list[dict[str, Any]]:
    """Check version against known CVEs and age thresholds."""
    findings: list[dict[str, Any]] = []

    if not version:
        findings.append({
            "severity": "MEDIUM",
            "message": "Could not determine Mattermost version for CVE mapping",
            "category": "version_disclosure",
        })
        return findings

    # Check against known CVEs
    vulnerable_cves: list[dict[str, Any]] = []
    for cve in MATTERMOST_CVES:
        if _version_lt(version, cve["fixed_in"]):
            vulnerable_cves.append(cve)

    if vulnerable_cves:
        critical_cves = [c for c in vulnerable_cves if c["severity"] == "CRITICAL"]
        high_cves = [c for c in vulnerable_cves if c["severity"] == "HIGH"]
        other_cves = [c for c in vulnerable_cves
                      if c["severity"] not in ("CRITICAL", "HIGH")]

        for cve in critical_cves:
            findings.append({
                "severity": "CRITICAL",
                "message": (
                    f"Vulnerable to {cve['cve']} (fixed in {cve['fixed_in']}): "
                    f"{cve['description']}"
                ),
                "category": "cve_vulnerable",
                "remediation": "cve_vulnerable",
            })

        for cve in high_cves:
            findings.append({
                "severity": "HIGH",
                "message": (
                    f"Vulnerable to {cve['cve']} (fixed in {cve['fixed_in']}): "
                    f"{cve['description']}"
                ),
                "category": "cve_vulnerable",
                "remediation": "cve_vulnerable",
            })

        for cve in other_cves:
            findings.append({
                "severity": cve["severity"],
                "message": (
                    f"Vulnerable to {cve['cve']} (fixed in {cve['fixed_in']}): "
                    f"{cve['description']}"
                ),
                "category": "cve_vulnerable",
                "remediation": "cve_vulnerable",
            })

        findings.append({
            "severity": "HIGH" if not critical_cves else "CRITICAL",
            "message": (
                f"Total known CVEs affecting version {version}: "
                f"{len(vulnerable_cves)} ({len(critical_cves)} Critical, "
                f"{len(high_cves)} High, {len(other_cves)} Other)"
            ),
            "category": "cve_vulnerable",
            "remediation": "outdated_version",
        })
    else:
        findings.append({
            "severity": "INFO",
            "message": f"Version {version} has no known CVEs in our database",
            "category": "cve_vulnerable",
        })

    # Check version age
    age_months = _version_age_months(version)
    if age_months is not None:
        if age_months > 12:
            findings.append({
                "severity": "CRITICAL",
                "message": (
                    f"Mattermost version {version} is approximately "
                    f"{age_months} months old (>12 months) -- CRITICAL risk"
                ),
                "category": "outdated_version",
                "remediation": "outdated_version",
            })
        elif age_months > 6:
            findings.append({
                "severity": "HIGH",
                "message": (
                    f"Mattermost version {version} is approximately "
                    f"{age_months} months old (>6 months) -- HIGH risk"
                ),
                "category": "outdated_version",
                "remediation": "outdated_version",
            })
        elif age_months > 3:
            findings.append({
                "severity": "MEDIUM",
                "message": (
                    f"Mattermost version {version} is approximately "
                    f"{age_months} months old"
                ),
                "category": "outdated_version",
                "remediation": "outdated_version",
            })
        else:
            findings.append({
                "severity": "INFO",
                "message": (
                    f"Mattermost version {version} is relatively current "
                    f"(~{age_months} months old)"
                ),
                "category": "outdated_version",
            })

    return findings


def check_third_party_integrations(session: requests.Session,
                                   base_url: str) -> list[dict[str, Any]]:
    """Detect third-party integrations from page source and CSP headers."""
    findings: list[dict[str, Any]] = []

    try:
        resp = session.get(base_url, timeout=TIMEOUT)
        page_source = resp.text
        headers = resp.headers

        # Check Content-Security-Policy header for external domains
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            findings.append({
                "severity": "INFO",
                "message": f"Content-Security-Policy header present ({len(csp)} chars)",
                "category": "third_party_tracking",
            })
            # Check for overly permissive CSP
            if "unsafe-inline" in csp:
                findings.append({
                    "severity": "MEDIUM",
                    "message": "CSP allows 'unsafe-inline' -- XSS risk increased",
                    "category": "third_party_tracking",
                })
            if "unsafe-eval" in csp:
                findings.append({
                    "severity": "MEDIUM",
                    "message": "CSP allows 'unsafe-eval' -- code injection risk",
                    "category": "third_party_tracking",
                })
            if "*" in csp.split():
                findings.append({
                    "severity": "HIGH",
                    "message": "CSP contains wildcard (*) source -- effectively no protection",
                    "category": "third_party_tracking",
                })
        else:
            findings.append({
                "severity": "MEDIUM",
                "message": "No Content-Security-Policy header -- XSS protection weakened",
                "category": "third_party_tracking",
            })

        # Scan page source and CSP for third-party indicators
        combined_text = page_source + " " + csp
        for name, indicator in THIRD_PARTY_INDICATORS.items():
            for pattern in indicator["patterns"]:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    findings.append({
                        "severity": indicator["severity"],
                        "message": f"Third-party: {indicator['description']}",
                        "category": "third_party_tracking",
                        "remediation": "third_party_tracking",
                    })
                    break  # Only report each indicator once

        # Check X-Frame-Options
        xfo = headers.get("X-Frame-Options", "")
        if not xfo:
            findings.append({
                "severity": "MEDIUM",
                "message": "Missing X-Frame-Options header -- clickjacking risk",
                "category": "third_party_tracking",
            })

        # Check Strict-Transport-Security
        hsts = headers.get("Strict-Transport-Security", "")
        if not hsts:
            findings.append({
                "severity": "MEDIUM",
                "message": "Missing Strict-Transport-Security header",
                "category": "third_party_tracking",
            })

    except requests.exceptions.RequestException as exc:
        findings.append({
            "severity": "INFO",
            "message": f"Could not fetch page source for integration analysis: {type(exc).__name__}",
            "category": "third_party_tracking",
        })

    return findings


# ---------------------------------------------------------------------------
# Collaboration platform detection (non-Mattermost)
# ---------------------------------------------------------------------------

def check_slack_webhooks(session: requests.Session,
                         target: str, port: int) -> list[dict[str, Any]]:
    """Check for exposed Slack webhook URLs in page source."""
    findings: list[dict[str, Any]] = []

    base = _base_url(target, port)
    common_paths = ["/", "/config", "/settings", "/.env", "/api/config"]

    for path in common_paths:
        try:
            resp = session.get(f"{base}{path}", timeout=TIMEOUT)
            if resp.status_code == 200:
                matches = SLACK_WEBHOOK_PATTERN.findall(resp.text)
                if matches:
                    for wh in set(matches):
                        # Mask the webhook token for safety
                        masked = wh[:50] + "..." if len(wh) > 50 else wh
                        findings.append({
                            "severity": "CRITICAL",
                            "message": (
                                f"Slack webhook URL exposed at {path}: {masked}"
                            ),
                            "category": "slack_webhook_exposed",
                            "remediation": "slack_webhook_exposed",
                        })
        except requests.exceptions.RequestException:
            continue

    # Check for Slack API presence
    slack_urls = [
        "https://slack.com/api/api.test",
    ]
    # Only if targeting slack.com-like hosts
    if "slack" in target.lower():
        for url in slack_urls:
            try:
                resp = session.get(url, timeout=TIMEOUT)
                if resp.status_code == 200:
                    findings.append({
                        "severity": "INFO",
                        "message": "Slack API endpoint reachable",
                        "category": "slack_webhook_exposed",
                    })
            except requests.exceptions.RequestException:
                pass

    if not findings:
        findings.append({
            "severity": "INFO",
            "message": "No Slack webhook URLs detected in scanned paths",
            "category": "slack_webhook_exposed",
        })

    return findings


def check_teams_endpoints(session: requests.Session,
                          target: str, port: int) -> list[dict[str, Any]]:
    """Check for Microsoft Teams endpoint exposure."""
    findings: list[dict[str, Any]] = []

    base = _base_url(target, port)

    # Check page source for Teams webhook patterns
    try:
        resp = session.get(base, timeout=TIMEOUT)
        if resp.status_code == 200:
            matches = TEAMS_WEBHOOK_PATTERN.findall(resp.text)
            if matches:
                for wh in set(matches):
                    masked = wh[:60] + "..." if len(wh) > 60 else wh
                    findings.append({
                        "severity": "CRITICAL",
                        "message": f"Microsoft Teams webhook URL exposed: {masked}",
                        "category": "teams_webhook_exposed",
                        "remediation": "teams_webhook_exposed",
                    })
    except requests.exceptions.RequestException:
        pass

    # Check for common Teams-related paths
    teams_paths = [
        "/teams",
        "/api/v1/teams",
        "/_api/teams",
    ]
    for path in teams_paths:
        try:
            resp = session.get(f"{base}{path}", timeout=TIMEOUT)
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(kw in body for kw in ["microsoft", "teams", "office365"]):
                    findings.append({
                        "severity": "MEDIUM",
                        "message": f"Microsoft Teams-related endpoint found: {path}",
                        "category": "teams_webhook_exposed",
                    })
        except requests.exceptions.RequestException:
            continue

    if not findings:
        findings.append({
            "severity": "INFO",
            "message": "No Microsoft Teams endpoints detected",
            "category": "teams_webhook_exposed",
        })

    return findings


def check_rocketchat(session: requests.Session,
                     target: str, port: int) -> list[dict[str, Any]]:
    """Detect and assess Rocket.Chat instances."""
    findings: list[dict[str, Any]] = []

    base = _base_url(target, port)
    detected = False

    # Rocket.Chat API info endpoint
    info_url = f"{base}/api/info"
    try:
        resp = session.get(info_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if "info" in data or "version" in data:
                    detected = True
                    version = data.get("info", {}).get("version",
                              data.get("version", "unknown"))
                    findings.append({
                        "severity": "MEDIUM",
                        "message": f"Rocket.Chat instance detected, version: {version}",
                        "category": "rocketchat_exposed",
                        "remediation": "rocketchat_exposed",
                    })
            except (json.JSONDecodeError, ValueError):
                pass
    except requests.exceptions.RequestException:
        pass

    # Alternative API v1 endpoint
    api_v1_url = f"{base}/api/v1/info"
    try:
        resp = session.get(api_v1_url, timeout=TIMEOUT)
        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get("success") or "info" in data:
                    detected = True
                    version = data.get("info", {}).get("version", "unknown")
                    findings.append({
                        "severity": "MEDIUM",
                        "message": (
                            f"Rocket.Chat API v1 accessible, version: {version}"
                        ),
                        "category": "rocketchat_exposed",
                        "remediation": "rocketchat_exposed",
                    })
            except (json.JSONDecodeError, ValueError):
                pass
    except requests.exceptions.RequestException:
        pass

    # Check registration status
    if detected:
        reg_url = f"{base}/api/v1/settings.public"
        try:
            resp = session.get(reg_url, timeout=TIMEOUT,
                               params={"query": '{"_id":"Accounts_RegistrationForm"}'})
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    settings = data.get("settings", [])
                    for s in settings:
                        if s.get("_id") == "Accounts_RegistrationForm":
                            val = s.get("value", "")
                            if val.lower() == "public":
                                findings.append({
                                    "severity": "HIGH",
                                    "message": (
                                        "Rocket.Chat public registration is ENABLED"
                                    ),
                                    "category": "rocketchat_exposed",
                                    "remediation": "rocketchat_exposed",
                                })
                except (json.JSONDecodeError, ValueError):
                    pass
        except requests.exceptions.RequestException:
            pass

    # Check Rocket.Chat from page source
    if not detected:
        try:
            resp = session.get(base, timeout=TIMEOUT)
            if resp.status_code == 200:
                if "rocketchat" in resp.text.lower() or "rocket.chat" in resp.text.lower():
                    detected = True
                    findings.append({
                        "severity": "MEDIUM",
                        "message": "Rocket.Chat instance detected from page source",
                        "category": "rocketchat_exposed",
                        "remediation": "rocketchat_exposed",
                    })
        except requests.exceptions.RequestException:
            pass

    if not detected:
        findings.append({
            "severity": "INFO",
            "message": "No Rocket.Chat instance detected",
            "category": "rocketchat_exposed",
        })

    return findings


def check_jira_confluence(session: requests.Session,
                          target: str, port: int) -> list[dict[str, Any]]:
    """Detect and assess Jira/Confluence instances."""
    findings: list[dict[str, Any]] = []

    base = _base_url(target, port)

    # Jira detection paths
    jira_paths = [
        ("/rest/api/2/serverInfo", "Jira REST API"),
        ("/secure/Dashboard.jspa", "Jira Dashboard"),
        ("/login.jsp", "Jira Login"),
        ("/status", "Jira Status"),
        ("/rest/api/latest/serverInfo", "Jira Latest API"),
    ]

    jira_detected = False
    for path, desc in jira_paths:
        try:
            resp = session.get(f"{base}{path}", timeout=TIMEOUT)
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(kw in body for kw in [
                    "jira", "atlassian", "serverinfo", "baseurl",
                ]):
                    jira_detected = True
                    # Try to extract version
                    try:
                        data = resp.json()
                        version = data.get("version", data.get("versionNumbers", ""))
                        findings.append({
                            "severity": "MEDIUM",
                            "message": (
                                f"Jira instance detected via {desc}, "
                                f"version: {version}"
                            ),
                            "category": "jira_exposed",
                            "remediation": "jira_exposed",
                        })
                    except (json.JSONDecodeError, ValueError):
                        findings.append({
                            "severity": "MEDIUM",
                            "message": f"Jira instance detected via {desc}",
                            "category": "jira_exposed",
                            "remediation": "jira_exposed",
                        })
                    break
        except requests.exceptions.RequestException:
            continue

    # Jira anonymous access check
    if jira_detected:
        anon_url = f"{base}/rest/api/2/search?jql=order+by+created+DESC&maxResults=1"
        try:
            resp = session.get(anon_url, timeout=TIMEOUT)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    total = data.get("total", 0)
                    if total > 0:
                        findings.append({
                            "severity": "HIGH",
                            "message": (
                                f"Jira anonymous access enabled -- {total} "
                                "issues accessible without authentication"
                            ),
                            "category": "jira_exposed",
                            "remediation": "jira_exposed",
                        })
                except (json.JSONDecodeError, ValueError):
                    pass
        except requests.exceptions.RequestException:
            pass

    # Confluence detection paths
    confluence_paths = [
        ("/rest/api/space", "Confluence Spaces API"),
        ("/wiki/rest/api/space", "Confluence Wiki Spaces API"),
        ("/wiki/", "Confluence Wiki"),
        ("/display/", "Confluence Display"),
    ]

    confluence_detected = False
    for path, desc in confluence_paths:
        try:
            resp = session.get(f"{base}{path}", timeout=TIMEOUT)
            if resp.status_code == 200:
                body = resp.text.lower()
                if any(kw in body for kw in [
                    "confluence", "atlassian", "space", "wiki",
                ]):
                    confluence_detected = True
                    findings.append({
                        "severity": "MEDIUM",
                        "message": f"Confluence instance detected via {desc}",
                        "category": "jira_exposed",
                        "remediation": "jira_exposed",
                    })
                    break
        except requests.exceptions.RequestException:
            continue

    # Confluence anonymous access check
    if confluence_detected:
        for spaces_path in ["/rest/api/space", "/wiki/rest/api/space"]:
            try:
                resp = session.get(f"{base}{spaces_path}", timeout=TIMEOUT)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        results = data.get("results", [])
                        if results:
                            space_names = [s.get("name", "?") for s in results[:5]]
                            findings.append({
                                "severity": "HIGH",
                                "message": (
                                    f"Confluence anonymous access -- {len(results)} "
                                    f"spaces visible: {', '.join(space_names)}"
                                ),
                                "category": "jira_exposed",
                                "remediation": "jira_exposed",
                            })
                    except (json.JSONDecodeError, ValueError):
                        pass
                    break
            except requests.exceptions.RequestException:
                continue

    if not jira_detected and not confluence_detected:
        findings.append({
            "severity": "INFO",
            "message": "No Jira or Confluence instances detected",
            "category": "jira_exposed",
        })

    return findings


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

def calculate_risk_score(findings: list[dict[str, Any]]) -> tuple[float, str]:
    """
    Calculate a 0-10 risk score from aggregated findings.

    CRITICAL findings push score >= 8.0.
    """
    total = 0.0
    severity_counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }

    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        total += RISK_WEIGHTS.get(sev, 0)

    # Normalize to 0-10 scale
    max_raw = 60.0  # rough ceiling for a fully misconfigured platform
    score = min(10.0, round((total / max_raw) * 10.0, 1))

    if severity_counts["CRITICAL"] > 0:
        score = max(score, 8.0)

    if score >= 8.0:
        label = "CRITICAL"
    elif score >= 6.0:
        label = "HIGH"
    elif score >= 4.0:
        label = "MEDIUM"
    elif score >= 2.0:
        label = "LOW"
    else:
        label = "SECURE"

    return score, label


# ---------------------------------------------------------------------------
# Main scan orchestrator
# ---------------------------------------------------------------------------

def scan_mattermost(session: requests.Session, target: str,
                    port: int) -> dict[str, Any]:
    """Full Mattermost security audit."""
    section_header("Mattermost Detection & Enumeration")

    result: dict[str, Any] = {
        "platform": "mattermost",
        "target": target,
        "port": port,
        "detected": False,
        "version": None,
        "checks": {},
        "findings": [],
    }

    # Phase 1: Detection
    detection = detect_mattermost(session, target, port)
    result["detected"] = detection["detected"]
    result["version"] = detection.get("version")
    result["checks"]["detection"] = {
        "base_url": detection.get("base_url"),
        "detected": detection["detected"],
        "version": detection.get("version"),
        "server_headers": detection.get("server_headers", {}),
    }
    result["findings"].extend(detection["findings"])

    for f in detection["findings"]:
        print(_tag(f["severity"], f["message"]))

    if not detection["detected"]:
        return result

    # Phase 2: Configuration analysis
    section_header("Configuration Analysis")

    config_findings = check_mattermost_config(detection.get("client_config", {}))
    result["checks"]["configuration"] = {
        "client_config_available": bool(detection.get("client_config")),
        "findings_count": len(config_findings),
    }
    result["findings"].extend(config_findings)

    for f in config_findings:
        print(_tag(f["severity"], f["message"]))

    # Phase 3: Version vulnerability mapping
    if detection.get("version"):
        section_header("Version Vulnerability Analysis")

        version_findings = check_mattermost_version(detection["version"])
        result["checks"]["version_analysis"] = {
            "version": detection["version"],
            "findings_count": len(version_findings),
        }
        result["findings"].extend(version_findings)

        for f in version_findings:
            print(_tag(f["severity"], f["message"]))

    # Phase 4: Third-party integration detection
    if detection.get("base_url"):
        section_header("Third-Party Integration Detection")

        integration_findings = check_third_party_integrations(
            session, detection["base_url"]
        )
        result["checks"]["third_party"] = {
            "findings_count": len(integration_findings),
        }
        result["findings"].extend(integration_findings)

        for f in integration_findings:
            print(_tag(f["severity"], f["message"]))

    return result


def scan_collaboration_platforms(session: requests.Session, target: str,
                                port: int,
                                platforms: list[str]) -> dict[str, Any]:
    """Scan for non-Mattermost collaboration platforms."""
    result: dict[str, Any] = {
        "target": target,
        "port": port,
        "platforms_checked": platforms,
        "checks": {},
        "findings": [],
    }

    if "slack" in platforms:
        section_header("Slack Webhook Detection")
        slack_findings = check_slack_webhooks(session, target, port)
        result["checks"]["slack"] = {"findings_count": len(slack_findings)}
        result["findings"].extend(slack_findings)
        for f in slack_findings:
            print(_tag(f["severity"], f["message"]))

    if "teams" in platforms:
        section_header("Microsoft Teams Endpoint Detection")
        teams_findings = check_teams_endpoints(session, target, port)
        result["checks"]["teams"] = {"findings_count": len(teams_findings)}
        result["findings"].extend(teams_findings)
        for f in teams_findings:
            print(_tag(f["severity"], f["message"]))

    if "rocketchat" in platforms:
        section_header("Rocket.Chat Detection")
        rocketchat_findings = check_rocketchat(session, target, port)
        result["checks"]["rocketchat"] = {"findings_count": len(rocketchat_findings)}
        result["findings"].extend(rocketchat_findings)
        for f in rocketchat_findings:
            print(_tag(f["severity"], f["message"]))

    if "jira" in platforms:
        section_header("Jira / Confluence Detection")
        jira_findings = check_jira_confluence(session, target, port)
        result["checks"]["jira_confluence"] = {"findings_count": len(jira_findings)}
        result["findings"].extend(jira_findings)
        for f in jira_findings:
            print(_tag(f["severity"], f["message"]))

    return result


def full_scan(session: requests.Session, target: str,
              port: int) -> dict[str, Any]:
    """Run all checks: Mattermost + all collaboration platforms."""
    result: dict[str, Any] = {
        "scan_type": "full",
        "target": target,
        "port": port,
        "mattermost": {},
        "collaboration": {},
        "findings": [],
    }

    # Mattermost scan
    mm_result = scan_mattermost(session, target, port)
    result["mattermost"] = mm_result
    result["findings"].extend(mm_result["findings"])

    # All other platforms
    all_platforms = ["slack", "teams", "rocketchat", "jira"]
    collab_result = scan_collaboration_platforms(
        session, target, port, all_platforms
    )
    result["collaboration"] = collab_result
    result["findings"].extend(collab_result["findings"])

    return result


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def build_remediation_list(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Build deduplicated remediation recommendations from findings."""
    seen_categories: set[str] = set()
    remediations: list[dict[str, str]] = []

    for f in findings:
        rem_key = f.get("remediation")
        if rem_key and rem_key not in seen_categories:
            seen_categories.add(rem_key)
            if rem_key in REMEDIATION_MAP:
                remediations.append({
                    "category": rem_key,
                    "severity": f["severity"],
                    "recommendation": REMEDIATION_MAP[rem_key],
                })

    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    remediations.sort(key=lambda r: severity_order.get(r["severity"], 5))

    return remediations


def write_report(scan_result: dict[str, Any], output_path: Path) -> Path:
    """Write JSON report and return the file path."""
    all_findings = scan_result.get("findings", [])
    score, label = calculate_risk_score(all_findings)

    severity_counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "tool": "haka_collab_scanner",
        "version": VERSION,
        "mitre_techniques": ["T1078 - Valid Accounts", "T1530 - Data from Cloud Storage"],
        "findings_ref": ["CRIT-BOA-03", "CRIT-BOA-04", "CRIT-BOA-05", "CRIT-BOA-06"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": scan_result.get("target", scan_result.get("mattermost", {}).get("target", "")),
        "scan_type": scan_result.get("scan_type", "targeted"),
        "risk_score": score,
        "risk_label": label,
        "summary": severity_counts,
        "findings": all_findings,
        "remediation": build_remediation_list(all_findings),
        "scan_details": {
            k: v for k, v in scan_result.items() if k != "findings"
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    return output_path


# ---------------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------------

def print_summary(findings: list[dict[str, Any]], elapsed: float) -> None:
    """Print a compact summary table after the scan."""
    score, label = calculate_risk_score(findings)

    severity_counts: dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for f in findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 66}")
    print(f"  SCAN SUMMARY")
    print(f"{'=' * 66}{Style.RESET_ALL}\n")

    # Risk score
    score_color = (
        Fore.RED + Style.BRIGHT if score >= 8.0
        else Fore.RED if score >= 6.0
        else Fore.YELLOW if score >= 4.0
        else Fore.GREEN
    )
    print(f"  {score_color}Risk Score: {score}/10 -- {label}{Style.RESET_ALL}\n")

    # Severity breakdown
    print(
        f"  Findings: "
        f"{Fore.RED}{Style.BRIGHT}{severity_counts['CRITICAL']} Critical{Style.RESET_ALL}, "
        f"{Fore.RED}{severity_counts['HIGH']} High{Style.RESET_ALL}, "
        f"{Fore.YELLOW}{severity_counts['MEDIUM']} Medium{Style.RESET_ALL}, "
        f"{Fore.CYAN}{severity_counts['LOW']} Low{Style.RESET_ALL}, "
        f"{Fore.BLUE}{severity_counts['INFO']} Info{Style.RESET_ALL}"
    )

    # Remediation count
    remediations = build_remediation_list(findings)
    if remediations:
        print(
            f"\n  {Fore.YELLOW}{Style.BRIGHT}Remediation Actions: "
            f"{len(remediations)}{Style.RESET_ALL}"
        )
        for i, rem in enumerate(remediations, 1):
            sev_color = SEVERITY_COLORS.get(rem["severity"], "")
            print(
                f"    {sev_color}{i}. [{rem['severity']}]{Style.RESET_ALL} "
                f"{rem['category'].replace('_', ' ').title()}"
            )

    print(f"\n  Scan completed in {elapsed:.2f}s\n")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="haka_collab_scanner",
        description=(
            "HAKA AI - Collaboration Platform Security Scanner\n"
            "Audit Mattermost, Slack, Teams, Rocket.Chat, Jira/Confluence "
            "for misconfigurations and vulnerabilities."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --target 192.168.122.50 --port 8065\n"
            "  %(prog)s --target 10.0.0.5 --type mattermost\n"
            "  %(prog)s --target 10.0.0.5 --type jira --port 8080\n"
            "  %(prog)s --target 10.0.0.5 --full-scan\n"
            "  %(prog)s --target 10.0.0.5 --full-scan -o /tmp/report.json\n"
        ),
    )
    parser.add_argument(
        "-t", "--target",
        type=str,
        required=True,
        help="Target IP address or hostname",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=None,
        help=(
            "Target port (default: 8065 for Mattermost, 443 for others). "
            "Auto-detected if omitted."
        ),
    )
    parser.add_argument(
        "--type",
        type=str,
        choices=["mattermost", "slack", "teams", "rocketchat", "jira"],
        default="mattermost",
        help="Platform type to scan (default: mattermost)",
    )
    parser.add_argument(
        "--full-scan",
        action="store_true",
        default=False,
        help="Run all checks against all supported platforms",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help=(
            "Path for JSON report output "
            "(default: /home/kironix/HAKA-AI/reports/collab_scan_<timestamp>.json)"
        ),
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress banner art",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {TIMEOUT})",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Port auto-detection
# ---------------------------------------------------------------------------

def detect_open_port(target: str, ports: list[int],
                     timeout: float = 3.0) -> Optional[int]:
    """Quick TCP connect scan to find first open port from the list."""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except (socket.timeout, OSError):
            continue
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    colorama_init(autoreset=False)
    args = parse_args()

    if not args.quiet:
        banner()

    global TIMEOUT
    TIMEOUT = args.timeout

    target = args.target.strip()

    # Determine port
    if args.port:
        port = args.port
    elif args.full_scan or args.type == "mattermost":
        print(f"  {Fore.WHITE}Auto-detecting open port on {target}...{Style.RESET_ALL}")
        port = detect_open_port(target, MATTERMOST_DEFAULT_PORTS)
        if port:
            print(f"  {Fore.GREEN}Found open port: {port}{Style.RESET_ALL}")
        else:
            port = 8065  # fallback
            print(
                f"  {Fore.YELLOW}No common port detected, "
                f"defaulting to {port}{Style.RESET_ALL}"
            )
    else:
        port = 443  # default for non-Mattermost

    scan_type = "full" if args.full_scan else args.type
    print(
        f"\n  {Fore.WHITE}Target: {target}:{port} | "
        f"Scan: {scan_type}{Style.RESET_ALL}\n"
    )

    session = _build_session()
    start_time = time.monotonic()
    scan_result: dict[str, Any] = {}

    try:
        if args.full_scan:
            scan_result = full_scan(session, target, port)
        elif args.type == "mattermost":
            mm = scan_mattermost(session, target, port)
            scan_result = {
                "scan_type": "mattermost",
                "target": target,
                "port": port,
                "mattermost": mm,
                "findings": mm["findings"],
            }
        elif args.type == "slack":
            collab = scan_collaboration_platforms(session, target, port, ["slack"])
            scan_result = {
                "scan_type": "slack",
                "target": target,
                "port": port,
                "collaboration": collab,
                "findings": collab["findings"],
            }
        elif args.type == "teams":
            collab = scan_collaboration_platforms(session, target, port, ["teams"])
            scan_result = {
                "scan_type": "teams",
                "target": target,
                "port": port,
                "collaboration": collab,
                "findings": collab["findings"],
            }
        elif args.type == "rocketchat":
            collab = scan_collaboration_platforms(
                session, target, port, ["rocketchat"]
            )
            scan_result = {
                "scan_type": "rocketchat",
                "target": target,
                "port": port,
                "collaboration": collab,
                "findings": collab["findings"],
            }
        elif args.type == "jira":
            collab = scan_collaboration_platforms(session, target, port, ["jira"])
            scan_result = {
                "scan_type": "jira",
                "target": target,
                "port": port,
                "collaboration": collab,
                "findings": collab["findings"],
            }

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        scan_result["findings"] = scan_result.get("findings", [])
    except Exception as exc:
        print(
            f"\n{Fore.RED}[!] Unexpected error: {exc}{Style.RESET_ALL}"
        )
        scan_result["findings"] = scan_result.get("findings", [])

    elapsed = time.monotonic() - start_time
    all_findings = scan_result.get("findings", [])

    # Print summary
    print_summary(all_findings, elapsed)

    # Write report
    if args.output:
        report_path = Path(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = REPORTS_DIR / f"collab_scan_{ts}.json"

    report_file = write_report(scan_result, report_path)
    print(
        f"  {Fore.GREEN}[+] Report saved to: "
        f"{report_file}{Style.RESET_ALL}\n"
    )


if __name__ == "__main__":
    main()
