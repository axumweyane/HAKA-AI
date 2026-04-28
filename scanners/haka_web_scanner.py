#!/usr/bin/env python3
"""
HAKA AI - Tool 6: Web Application Scanner
==========================================
Maps to: Section C1-C5 -- PHP RCE, WordPress, cPanel, File Extraction, User Enum
Findings: CRIT-ET-07, CRIT-ET-08, CRIT-DSH-01 through CRIT-DSH-07, CRIT-TB-01, CRIT-TB-02

Performs comprehensive web application security scanning including:
  - PHP security configuration analysis
  - WordPress vulnerability detection and enumeration
  - Sensitive file and backup discovery
  - Admin panel and control panel detection
  - Risk scoring and professional reporting

Usage:
  python haka_web_scanner.py --url https://TARGET
  python haka_web_scanner.py --url https://TARGET --wordpress-only
  python haka_web_scanner.py --url https://TARGET --full-scan --output report

Author : HAKA AI Framework
Version: 1.0.0
License: For authorized security testing only
"""

import argparse
import json
import os
import random
import re
import sys
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html import escape as html_escape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests")

try:
    from bs4 import BeautifulSoup
except ImportError:
    sys.exit("[!] Missing dependency: pip install beautifulsoup4")

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    sys.exit("[!] Missing dependency: pip install colorama")

# Suppress insecure request warnings for lab use
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
REPORTS_DIR = "/home/kironix/HAKA-AI/reports"
DEFAULT_TIMEOUT = 5
DEFAULT_WORKERS = 10

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
]

# Risk severity levels and their numeric weights
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_SCORES = {
    SEVERITY_CRITICAL: 10,
    SEVERITY_HIGH: 8,
    SEVERITY_MEDIUM: 5,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 1,
}

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: Fore.RED + Style.BRIGHT,
    SEVERITY_HIGH: Fore.RED,
    SEVERITY_MEDIUM: Fore.YELLOW,
    SEVERITY_LOW: Fore.CYAN,
    SEVERITY_INFO: Fore.BLUE,
}

# Sensitive file paths to check
SENSITIVE_FILES = [
    # Environment and config
    ("/.env", SEVERITY_CRITICAL, "CRIT-DSH-03", "Environment file with potential secrets"),
    ("/.env.production", SEVERITY_CRITICAL, "CRIT-DSH-03", "Production environment file"),
    ("/.env.local", SEVERITY_CRITICAL, "CRIT-DSH-03", "Local environment file"),
    ("/.env.backup", SEVERITY_CRITICAL, "CRIT-DSH-03", "Backup environment file"),
    # Git exposure
    ("/.git/HEAD", SEVERITY_CRITICAL, "CRIT-DSH-04", "Git HEAD exposed -- source code leak"),
    ("/.git/config", SEVERITY_CRITICAL, "CRIT-DSH-04", "Git config exposed -- may contain credentials"),
    # Log files
    ("/debug.log", SEVERITY_HIGH, "CRIT-DSH-05", "Debug log file accessible"),
    ("/error.log", SEVERITY_HIGH, "CRIT-DSH-05", "Error log file accessible"),
    ("/access.log", SEVERITY_MEDIUM, "CRIT-DSH-05", "Access log file accessible"),
    ("/error_log", SEVERITY_HIGH, "CRIT-DSH-05", "Error log file accessible"),
    # Apache status
    ("/server-status", SEVERITY_HIGH, "CRIT-DSH-06", "Apache server-status exposed"),
    ("/server-info", SEVERITY_HIGH, "CRIT-DSH-06", "Apache server-info exposed"),
    # Config backups
    ("/wp-config.php.bak", SEVERITY_CRITICAL, "CRIT-DSH-01", "WordPress config backup with DB credentials"),
    ("/wp-config.php.old", SEVERITY_CRITICAL, "CRIT-DSH-01", "WordPress config old backup"),
    ("/wp-config.php~", SEVERITY_CRITICAL, "CRIT-DSH-01", "WordPress config editor backup"),
    ("/wp-config.php.swp", SEVERITY_CRITICAL, "CRIT-DSH-01", "WordPress config vim swap file"),
    ("/wp-config.php.save", SEVERITY_CRITICAL, "CRIT-DSH-01", "WordPress config save file"),
    ("/wp-config.bak", SEVERITY_CRITICAL, "CRIT-DSH-01", "WordPress config backup"),
    ("/.htaccess", SEVERITY_MEDIUM, "CRIT-DSH-02", ".htaccess file accessible"),
    ("/web.config", SEVERITY_MEDIUM, "CRIT-DSH-02", "IIS web.config accessible"),
    # Common backups
    ("/backup.sql", SEVERITY_CRITICAL, "CRIT-DSH-07", "SQL database backup exposed"),
    ("/database.sql", SEVERITY_CRITICAL, "CRIT-DSH-07", "SQL database backup exposed"),
    ("/dump.sql", SEVERITY_CRITICAL, "CRIT-DSH-07", "SQL database dump exposed"),
    ("/db.sql", SEVERITY_CRITICAL, "CRIT-DSH-07", "SQL database backup exposed"),
    ("/backup.zip", SEVERITY_CRITICAL, "CRIT-DSH-07", "Backup archive exposed"),
    ("/backup.tar.gz", SEVERITY_CRITICAL, "CRIT-DSH-07", "Backup archive exposed"),
    ("/site.zip", SEVERITY_HIGH, "CRIT-DSH-07", "Site archive exposed"),
    ("/www.zip", SEVERITY_HIGH, "CRIT-DSH-07", "Site archive exposed"),
    ("/public_html.zip", SEVERITY_HIGH, "CRIT-DSH-07", "Site archive exposed"),
    ("/backup.bak", SEVERITY_HIGH, "CRIT-DSH-07", "Backup file exposed"),
]

# Admin panel paths
ADMIN_PANELS = [
    ("/admin", "Generic Admin Panel"),
    ("/admin/", "Generic Admin Panel"),
    ("/administrator", "Administrator Panel"),
    ("/administrator/", "Administrator Panel"),
    ("/manager", "Manager Panel"),
    ("/manager/html", "Tomcat Manager"),
    ("/dashboard", "Dashboard"),
    ("/login", "Login Page"),
    ("/wp-admin", "WordPress Admin"),
    ("/user/login", "User Login (Drupal-style)"),
    ("/admin/login", "Admin Login"),
    ("/cpanel", "cPanel Redirect"),
    ("/webmail", "Webmail"),
    ("/phpmyadmin", "phpMyAdmin"),
    ("/phpMyAdmin", "phpMyAdmin"),
    ("/pma", "phpMyAdmin (short)"),
    ("/adminer.php", "Adminer DB Manager"),
    ("/adminer", "Adminer DB Manager"),
]

# Control panel ports to probe
CONTROL_PANELS = [
    (2082, "http", "cPanel (HTTP)"),
    (2083, "https", "cPanel (HTTPS)"),
    (2086, "http", "WHM (HTTP)"),
    (2087, "https", "WHM (HTTPS)"),
    (10000, "https", "Webmin"),
    (8443, "https", "Plesk"),
    (8880, "http", "Plesk (HTTP)"),
]


# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------

class Finding:
    """Represents a single security finding."""

    def __init__(
        self,
        title: str,
        severity: str,
        finding_id: str,
        description: str,
        url: str = "",
        evidence: str = "",
        category: str = "",
        recommendation: str = "",
    ):
        self.title = title
        self.severity = severity
        self.finding_id = finding_id
        self.description = description
        self.url = url
        self.evidence = evidence[:2000]  # cap evidence length
        self.category = category
        self.recommendation = recommendation
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.score = SEVERITY_SCORES.get(severity, 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "finding_id": self.finding_id,
            "score": self.score,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "category": self.category,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }

    def console_line(self) -> str:
        color = SEVERITY_COLORS.get(self.severity, "")
        tag = f"[{self.severity}]"
        return f"  {color}{tag:12s}{Style.RESET_ALL} {self.finding_id:16s} {self.title}"


# ---------------------------------------------------------------------------
# HTTP Client wrapper
# ---------------------------------------------------------------------------

class HTTPClient:
    """Managed HTTP session with UA rotation, rate limiting, redirect tracking."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, delay: float = 0.0, max_retries: int = 2):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()

        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False
        self.request_count = 0

    def _pick_ua(self) -> str:
        return random.choice(USER_AGENTS)

    def get(self, url: str, allow_redirects: bool = True, **kwargs) -> Optional[requests.Response]:
        """GET request with UA rotation, delay, timeout."""
        if self.delay > 0:
            time.sleep(self.delay)
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self._pick_ua())
        try:
            self.request_count += 1
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=False,
                **kwargs,
            )
            return resp
        except requests.exceptions.RequestException:
            return None

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        if self.delay > 0:
            time.sleep(self.delay)
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self._pick_ua())
        try:
            self.request_count += 1
            return self.session.head(url, headers=headers, timeout=self.timeout, verify=False, **kwargs)
        except requests.exceptions.RequestException:
            return None

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        if self.delay > 0:
            time.sleep(self.delay)
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self._pick_ua())
        try:
            self.request_count += 1
            return self.session.options(url, headers=headers, timeout=self.timeout, verify=False, **kwargs)
        except requests.exceptions.RequestException:
            return None

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if self.delay > 0:
            time.sleep(self.delay)
        headers = kwargs.pop("headers", {})
        headers.setdefault("User-Agent", self._pick_ua())
        try:
            self.request_count += 1
            return self.session.request(
                method, url, headers=headers, timeout=self.timeout, verify=False, **kwargs
            )
        except requests.exceptions.RequestException:
            return None


# ---------------------------------------------------------------------------
# Scanner modules
# ---------------------------------------------------------------------------

class PHPSecurityScanner:
    """C1: PHP security configuration checks."""

    CATEGORY = "PHP Security"

    def __init__(self, base_url: str, client: HTTPClient):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        self._check_phpinfo()
        self._check_http_methods()
        return self.findings

    def _check_phpinfo(self):
        """Check for accessible phpinfo pages."""
        phpinfo_paths = ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php", "/i.php"]
        for path in phpinfo_paths:
            url = self.base_url + path
            resp = self.client.get(url)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text
            if "phpinfo()" not in body and "PHP Version" not in body:
                continue

            self.findings.append(Finding(
                title=f"phpinfo() accessible at {path}",
                severity=SEVERITY_CRITICAL,
                finding_id="CRIT-ET-07",
                description="phpinfo() is publicly accessible, leaking full server configuration.",
                url=url,
                evidence=f"HTTP {resp.status_code} -- page contains PHP configuration details",
                category=self.CATEGORY,
                recommendation="Remove or restrict access to phpinfo files immediately.",
            ))
            # Parse phpinfo output for dangerous settings
            self._parse_phpinfo(body, url)
            break  # one is enough

    def _parse_phpinfo(self, body: str, url: str):
        """Extract dangerous PHP settings from phpinfo output."""
        soup = BeautifulSoup(body, "html.parser")
        rows = soup.find_all("tr")
        config_values: Dict[str, str] = {}
        for row in rows:
            cells = row.find_all("td")
            if len(cells) >= 2:
                key = cells[0].get_text(strip=True)
                val = cells[1].get_text(strip=True)
                config_values[key] = val

        # Check disable_functions
        disable_funcs = config_values.get("disable_functions", "")
        if not disable_funcs or disable_funcs.lower() in ("no value", "none", ""):
            self.findings.append(Finding(
                title="PHP disable_functions is empty",
                severity=SEVERITY_CRITICAL,
                finding_id="CRIT-ET-08",
                description="No PHP functions are disabled. Dangerous functions like exec, system, passthru are available for RCE.",
                url=url,
                evidence=f"disable_functions = {disable_funcs or '(empty)'}",
                category=self.CATEGORY,
                recommendation="Set disable_functions in php.ini to block exec, system, passthru, shell_exec, popen, proc_open.",
            ))
        else:
            dangerous = ["exec", "system", "passthru", "shell_exec", "popen", "proc_open", "eval"]
            missing = [fn for fn in dangerous if fn not in disable_funcs]
            if missing:
                self.findings.append(Finding(
                    title="Dangerous PHP functions not disabled",
                    severity=SEVERITY_HIGH,
                    finding_id="CRIT-ET-08",
                    description=f"The following dangerous functions are still enabled: {', '.join(missing)}",
                    url=url,
                    evidence=f"disable_functions = {disable_funcs[:300]}",
                    category=self.CATEGORY,
                    recommendation=f"Add to disable_functions: {', '.join(missing)}",
                ))

        # Check open_basedir
        open_basedir = config_values.get("open_basedir", "")
        if not open_basedir or open_basedir.lower() in ("no value", "none"):
            self.findings.append(Finding(
                title="PHP open_basedir not set",
                severity=SEVERITY_HIGH,
                finding_id="CRIT-ET-08",
                description="open_basedir is not configured. PHP scripts can access files anywhere on the filesystem.",
                url=url,
                evidence=f"open_basedir = {open_basedir or '(not set)'}",
                category=self.CATEGORY,
                recommendation="Set open_basedir to restrict file access to web root and tmp.",
            ))

        # Check allow_url_include
        allow_url_include = config_values.get("allow_url_include", "")
        if allow_url_include.lower() in ("on", "1"):
            self.findings.append(Finding(
                title="PHP allow_url_include is ON",
                severity=SEVERITY_CRITICAL,
                finding_id="CRIT-ET-08",
                description="allow_url_include is enabled, enabling Remote File Inclusion (RFI) attacks.",
                url=url,
                evidence=f"allow_url_include = {allow_url_include}",
                category=self.CATEGORY,
                recommendation="Set allow_url_include = Off in php.ini.",
            ))

        # Check allow_url_fopen
        allow_url_fopen = config_values.get("allow_url_fopen", "")
        if allow_url_fopen.lower() in ("on", "1"):
            self.findings.append(Finding(
                title="PHP allow_url_fopen is ON",
                severity=SEVERITY_MEDIUM,
                finding_id="CRIT-ET-08",
                description="allow_url_fopen is enabled, which may facilitate SSRF or data exfiltration.",
                url=url,
                evidence=f"allow_url_fopen = {allow_url_fopen}",
                category=self.CATEGORY,
                recommendation="Disable allow_url_fopen unless required by the application.",
            ))

        # Check display_errors
        display_errors = config_values.get("display_errors", "")
        if display_errors.lower() in ("on", "1"):
            self.findings.append(Finding(
                title="PHP display_errors is ON",
                severity=SEVERITY_MEDIUM,
                finding_id="CRIT-ET-08",
                description="PHP errors are displayed to users, potentially leaking paths and internal info.",
                url=url,
                evidence=f"display_errors = {display_errors}",
                category=self.CATEGORY,
                recommendation="Set display_errors = Off in production.",
            ))

        # Extract server info
        server_version = config_values.get("Server API", "")
        php_version = config_values.get("PHP Version", "")
        if php_version:
            self.findings.append(Finding(
                title=f"PHP version disclosed: {php_version}",
                severity=SEVERITY_INFO,
                finding_id="CRIT-ET-07",
                description=f"PHP {php_version} via {server_version}. Version disclosure aids targeted exploits.",
                url=url,
                evidence=f"PHP Version: {php_version}, Server API: {server_version}",
                category=self.CATEGORY,
                recommendation="Suppress version disclosure via expose_php = Off.",
            ))

    def _check_http_methods(self):
        """Check for dangerous HTTP methods."""
        url = self.base_url + "/"
        resp = self.client.options(url)
        allowed_methods: List[str] = []

        if resp is not None:
            allow_header = resp.headers.get("Allow", "")
            if allow_header:
                allowed_methods = [m.strip().upper() for m in allow_header.split(",")]

        # Also probe individually
        dangerous_methods = ["PUT", "DELETE", "TRACE"]
        for method in dangerous_methods:
            if method in allowed_methods:
                continue
            probe = self.client.request(method, url)
            if probe is not None and probe.status_code not in (405, 501, 403, 404):
                allowed_methods.append(method)

        dangerous_found = [m for m in allowed_methods if m in ("PUT", "DELETE", "TRACE")]
        if dangerous_found:
            self.findings.append(Finding(
                title=f"Dangerous HTTP methods enabled: {', '.join(dangerous_found)}",
                severity=SEVERITY_MEDIUM,
                finding_id="CRIT-ET-08",
                description=f"The server allows HTTP methods that could be abused: {', '.join(dangerous_found)}",
                url=url,
                evidence=f"Allowed methods: {', '.join(allowed_methods) if allowed_methods else '(probed individually)'}",
                category=self.CATEGORY,
                recommendation="Disable PUT, DELETE, and TRACE methods unless explicitly needed.",
            ))

        if "TRACE" in dangerous_found:
            self.findings.append(Finding(
                title="HTTP TRACE method enabled (XST risk)",
                severity=SEVERITY_MEDIUM,
                finding_id="CRIT-ET-08",
                description="TRACE method is enabled, which can be used for Cross-Site Tracing (XST) attacks.",
                url=url,
                evidence="TRACE method returned non-error response",
                category=self.CATEGORY,
                recommendation="Disable TRACE method via TraceEnable Off in Apache or equivalent.",
            ))


class WordPressScanner:
    """C2: WordPress-specific vulnerability detection."""

    CATEGORY = "WordPress"

    def __init__(self, base_url: str, client: HTTPClient):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.findings: List[Finding] = []
        self.is_wordpress = False
        self.wp_version: Optional[str] = None

    def run(self) -> List[Finding]:
        self._detect_wordpress()
        if not self.is_wordpress:
            return self.findings

        self._extract_version()
        self._check_rest_api_users()
        self._check_author_enum()
        self._check_xmlrpc()
        self._check_debug_log()
        self._check_config_backups()
        self._check_readme()
        return self.findings

    def _detect_wordpress(self):
        """Detect if the site runs WordPress."""
        # Check homepage for generator meta tag
        resp = self.client.get(self.base_url + "/")
        if resp and resp.status_code == 200:
            body = resp.text.lower()
            if "wp-content" in body or "wp-includes" in body:
                self.is_wordpress = True
            soup = BeautifulSoup(resp.text, "html.parser")
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen and "wordpress" in str(gen.get("content", "")).lower():
                self.is_wordpress = True

        # Check wp-login.php
        if not self.is_wordpress:
            resp = self.client.get(self.base_url + "/wp-login.php", allow_redirects=False)
            if resp and resp.status_code in (200, 302):
                if resp.status_code == 200 and ("wp-login" in resp.text.lower() or "wordpress" in resp.text.lower()):
                    self.is_wordpress = True
                elif resp.status_code == 302:
                    location = resp.headers.get("Location", "")
                    if "wp-login" in location or "wp-admin" in location:
                        self.is_wordpress = True

        # Check wp-admin redirect
        if not self.is_wordpress:
            resp = self.client.get(self.base_url + "/wp-admin/", allow_redirects=False)
            if resp and resp.status_code in (301, 302):
                location = resp.headers.get("Location", "")
                if "wp-login" in location:
                    self.is_wordpress = True

        if self.is_wordpress:
            self.findings.append(Finding(
                title="WordPress CMS detected",
                severity=SEVERITY_INFO,
                finding_id="CRIT-TB-01",
                description="The target is running WordPress.",
                url=self.base_url,
                category=self.CATEGORY,
                recommendation="Ensure WordPress core, themes, and plugins are up to date.",
            ))

    def _extract_version(self):
        """Extract WordPress version from source or RSS feed."""
        # From homepage source
        resp = self.client.get(self.base_url + "/")
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            gen = soup.find("meta", attrs={"name": "generator"})
            if gen:
                content = gen.get("content", "")
                match = re.search(r"WordPress\s+([\d.]+)", content, re.IGNORECASE)
                if match:
                    self.wp_version = match.group(1)

        # From feed
        if not self.wp_version:
            for feed_path in ["/feed/", "/feed/rss2/", "/?feed=rss2"]:
                resp = self.client.get(self.base_url + feed_path)
                if resp and resp.status_code == 200:
                    match = re.search(r"<generator>.*?WordPress.*?([\d.]+).*?</generator>", resp.text, re.I)
                    if match:
                        self.wp_version = match.group(1)
                        break

        # From readme.html
        if not self.wp_version:
            resp = self.client.get(self.base_url + "/readme.html")
            if resp and resp.status_code == 200 and "wordpress" in resp.text.lower():
                match = re.search(r"Version\s+([\d.]+)", resp.text)
                if match:
                    self.wp_version = match.group(1)

        if self.wp_version:
            self.findings.append(Finding(
                title=f"WordPress version disclosed: {self.wp_version}",
                severity=SEVERITY_LOW,
                finding_id="CRIT-TB-01",
                description=f"WordPress version {self.wp_version} is exposed. Attackers can look up known CVEs for this version.",
                url=self.base_url,
                evidence=f"Detected version: {self.wp_version}",
                category=self.CATEGORY,
                recommendation="Remove version info from meta tags and feeds. Use security through obscurity as a defense-in-depth measure.",
            ))

    def _check_rest_api_users(self):
        """Check WP REST API user enumeration (CRIT-TB-02)."""
        url = self.base_url + "/wp-json/wp/v2/users"
        resp = self.client.get(url)
        if resp is None or resp.status_code != 200:
            # Try with per_page
            url = self.base_url + "/wp-json/wp/v2/users?per_page=100"
            resp = self.client.get(url)

        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list) and len(users) > 0:
                    usernames = [u.get("slug", u.get("name", "unknown")) for u in users[:20]]
                    self.findings.append(Finding(
                        title=f"WP REST API user enumeration -- {len(users)} user(s) exposed",
                        severity=SEVERITY_HIGH,
                        finding_id="CRIT-TB-02",
                        description="WordPress REST API exposes user information including usernames, enabling brute-force attacks.",
                        url=url,
                        evidence=f"Enumerated users: {', '.join(usernames)}",
                        category=self.CATEGORY,
                        recommendation="Disable REST API user endpoints or require authentication. Use a plugin like Disable WP REST API or add capability checks.",
                    ))
            except (json.JSONDecodeError, ValueError):
                pass

    def _check_author_enum(self):
        """Check author archive enumeration."""
        found_users: List[str] = []
        for author_id in range(1, 21):
            url = f"{self.base_url}/?author={author_id}"
            resp = self.client.get(url, allow_redirects=True)
            if resp is None:
                continue
            # If redirected to /author/username/
            if resp.url and "/author/" in resp.url:
                match = re.search(r"/author/([^/]+)", resp.url)
                if match:
                    found_users.append(match.group(1))
            elif resp.status_code == 200 and "author" in resp.text.lower():
                soup = BeautifulSoup(resp.text, "html.parser")
                title = soup.find("title")
                if title and "author" in title.get_text().lower():
                    found_users.append(f"author_id={author_id}")

        if found_users:
            unique_users = list(dict.fromkeys(found_users))  # dedupe preserving order
            self.findings.append(Finding(
                title=f"WordPress author enumeration -- {len(unique_users)} user(s) found",
                severity=SEVERITY_MEDIUM,
                finding_id="CRIT-TB-02",
                description="User accounts can be enumerated via /?author=N redirects.",
                url=f"{self.base_url}/?author=1",
                evidence=f"Discovered users: {', '.join(unique_users)}",
                category=self.CATEGORY,
                recommendation="Block author archives or redirect /?author= queries. Use a security plugin to prevent enumeration.",
            ))

    def _check_xmlrpc(self):
        """Check XML-RPC exposure."""
        url = self.base_url + "/xmlrpc.php"
        resp = self.client.get(url)
        if resp and resp.status_code == 200:
            if "xml-rpc server accepts post requests only" in resp.text.lower() or "xmlrpc" in resp.text.lower():
                self.findings.append(Finding(
                    title="WordPress XML-RPC enabled",
                    severity=SEVERITY_HIGH,
                    finding_id="CRIT-TB-01",
                    description="XML-RPC interface is accessible. It can be abused for brute-force amplification (wp.multicall) and DDoS pingback attacks.",
                    url=url,
                    evidence=f"HTTP 200 -- {resp.text[:200]}",
                    category=self.CATEGORY,
                    recommendation="Disable XML-RPC via .htaccess, a security plugin, or remove xmlrpc.php if not needed.",
                ))

    def _check_debug_log(self):
        """Check wp-content/debug.log."""
        url = self.base_url + "/wp-content/debug.log"
        resp = self.client.get(url)
        if resp and resp.status_code == 200 and len(resp.text) > 50:
            # Verify it looks like a real log
            if "PHP" in resp.text or "Warning" in resp.text or "Error" in resp.text or "Notice" in resp.text:
                self.findings.append(Finding(
                    title="WordPress debug.log exposed",
                    severity=SEVERITY_HIGH,
                    finding_id="CRIT-DSH-05",
                    description="WordPress debug log is publicly accessible, potentially leaking file paths, database queries, and stack traces.",
                    url=url,
                    evidence=f"Log size: ~{len(resp.text)} bytes. First 300 chars: {resp.text[:300]}",
                    category=self.CATEGORY,
                    recommendation="Delete debug.log and set WP_DEBUG_LOG to false in wp-config.php, or protect it via .htaccess.",
                ))

    def _check_config_backups(self):
        """Check for wp-config.php backup files."""
        backup_suffixes = [".bak", ".old", "~", ".swp", ".save", ".orig", ".dist", ".txt"]
        for suffix in backup_suffixes:
            url = self.base_url + f"/wp-config.php{suffix}"
            resp = self.client.get(url)
            if resp and resp.status_code == 200 and len(resp.text) > 100:
                if "DB_NAME" in resp.text or "DB_PASSWORD" in resp.text or "db_name" in resp.text.lower():
                    self.findings.append(Finding(
                        title=f"WordPress config backup found: wp-config.php{suffix}",
                        severity=SEVERITY_CRITICAL,
                        finding_id="CRIT-DSH-01",
                        description="A backup of wp-config.php is publicly accessible, exposing database credentials and secret keys.",
                        url=url,
                        evidence=f"File contains WordPress configuration data (DB_NAME, secret keys, etc.)",
                        category=self.CATEGORY,
                        recommendation="Delete all wp-config.php backup files immediately. Never leave backups in web-accessible directories.",
                    ))

    def _check_readme(self):
        """Check for readme.html that discloses version."""
        url = self.base_url + "/readme.html"
        resp = self.client.get(url)
        if resp and resp.status_code == 200 and "wordpress" in resp.text.lower():
            self.findings.append(Finding(
                title="WordPress readme.html accessible",
                severity=SEVERITY_LOW,
                finding_id="CRIT-TB-01",
                description="readme.html discloses WordPress version information.",
                url=url,
                category=self.CATEGORY,
                recommendation="Remove readme.html from the web root.",
            ))


class SensitiveFileScanner:
    """C3: Sensitive file and backup detection."""

    CATEGORY = "Sensitive Files"

    def __init__(self, base_url: str, client: HTTPClient):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.findings: List[Finding] = []

    def run(self) -> List[Finding]:
        self._scan_files()
        return self.findings

    def _probe_file(self, path: str, severity: str, finding_id: str, desc: str) -> Optional[Finding]:
        """Probe a single file path and return a Finding if accessible."""
        url = self.base_url + path
        resp = self.client.get(url)
        if resp is None or resp.status_code not in (200, 403):
            return None

        # 200 means accessible
        if resp.status_code == 200:
            body = resp.text
            # Filter out generic error pages and empty responses
            if len(body) < 10:
                return None
            # Check for common soft-404 patterns
            lower_body = body.lower()
            if any(p in lower_body for p in ["page not found", "404 not found", "does not exist", "not be found"]):
                return None

            evidence_text = f"HTTP 200, {len(body)} bytes"
            # Special checks for .git/HEAD
            if ".git/HEAD" in path and "ref:" in body:
                evidence_text = f"Git HEAD: {body.strip()[:200]}"
            elif ".git/config" in path and "[core]" in body:
                evidence_text = f"Git config exposed: {body[:300]}"
            elif ".env" in path:
                # Check for real env vars
                if "=" in body and any(k in body.upper() for k in ["DB_", "API_", "SECRET", "KEY", "PASS", "TOKEN", "HOST"]):
                    evidence_text = f"Environment file with {body.count(chr(10))} lines"
                else:
                    return None
            elif path.endswith(".sql"):
                if not any(k in body.upper() for k in ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "ALTER TABLE", "MYSQL"]):
                    return None
                evidence_text = f"SQL dump, {len(body)} bytes"
            elif path.endswith((".zip", ".tar.gz", ".bak")):
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    return None
                evidence_text = f"Archive/backup file, Content-Type: {content_type}, {len(body)} bytes"

            return Finding(
                title=f"Sensitive file accessible: {path}",
                severity=severity,
                finding_id=finding_id,
                description=desc,
                url=url,
                evidence=evidence_text,
                category=self.CATEGORY,
                recommendation=f"Remove or restrict access to {path}. Block access via web server configuration.",
            )

        # 403 on sensitive paths is noteworthy but lower severity
        if resp.status_code == 403 and ".git" in path:
            return Finding(
                title=f"Path exists but forbidden: {path}",
                severity=SEVERITY_LOW,
                finding_id=finding_id,
                description=f"{path} returns 403 Forbidden -- the file/directory exists but is protected.",
                url=url,
                evidence="HTTP 403 Forbidden",
                category=self.CATEGORY,
                recommendation="Verify protection is complete and consider removing the resource entirely.",
            )

        return None

    def _scan_files(self):
        """Scan all sensitive file paths using thread pool."""
        with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as executor:
            future_to_path = {
                executor.submit(self._probe_file, path, sev, fid, desc): path
                for path, sev, fid, desc in SENSITIVE_FILES
            }
            for future in as_completed(future_to_path):
                result = future.result()
                if result is not None:
                    self.findings.append(result)


class AdminPanelScanner:
    """C4-C5: Admin panel and control panel detection."""

    CATEGORY = "Admin Panels"

    def __init__(self, base_url: str, client: HTTPClient):
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.findings: List[Finding] = []
        parsed = urlparse(self.base_url)
        self.hostname = parsed.hostname or ""

    def run(self) -> List[Finding]:
        self._scan_admin_paths()
        self._scan_control_panels()
        return self.findings

    def _probe_admin_path(self, path: str, label: str) -> Optional[Finding]:
        """Probe a single admin path."""
        url = self.base_url + path
        resp = self.client.get(url, allow_redirects=True)
        if resp is None:
            return None

        if resp.status_code == 200:
            body = resp.text.lower()
            # Verify it looks like a real admin/login page
            login_indicators = ["login", "password", "username", "sign in", "log in", "email", "authenticate",
                                "dashboard", "admin", "panel", "cpanel", "phpmyadmin", "adminer"]
            if any(ind in body for ind in login_indicators):
                return Finding(
                    title=f"Admin panel found: {path} ({label})",
                    severity=SEVERITY_MEDIUM,
                    finding_id="CRIT-DSH-06",
                    description=f"{label} is accessible at {path}.",
                    url=resp.url,
                    evidence=f"HTTP {resp.status_code}, final URL: {resp.url}",
                    category=self.CATEGORY,
                    recommendation="Restrict admin panel access by IP or VPN. Use strong authentication and MFA.",
                )
        elif resp.status_code == 401:
            return Finding(
                title=f"Admin panel found (auth required): {path} ({label})",
                severity=SEVERITY_LOW,
                finding_id="CRIT-DSH-06",
                description=f"{label} exists at {path} and requires authentication (401).",
                url=url,
                evidence=f"HTTP 401 Unauthorized",
                category=self.CATEGORY,
                recommendation="Verify strong credentials and consider IP-based access restrictions.",
            )
        return None

    def _scan_admin_paths(self):
        """Scan common admin panel paths using thread pool."""
        with ThreadPoolExecutor(max_workers=DEFAULT_WORKERS) as executor:
            future_to_info = {
                executor.submit(self._probe_admin_path, path, label): path
                for path, label in ADMIN_PANELS
            }
            for future in as_completed(future_to_info):
                result = future.result()
                if result is not None:
                    self.findings.append(result)

    def _probe_control_panel(self, port: int, scheme: str, label: str) -> Optional[Finding]:
        """Probe a control panel on a specific port."""
        url = f"{scheme}://{self.hostname}:{port}/"
        resp = self.client.get(url, allow_redirects=True)
        if resp is None:
            return None
        if resp.status_code in (200, 301, 302, 401):
            sev = SEVERITY_HIGH if resp.status_code in (200, 302) else SEVERITY_MEDIUM
            return Finding(
                title=f"Control panel detected: {label} on port {port}",
                severity=sev,
                finding_id="CRIT-DSH-06",
                description=f"{label} is accessible on port {port}.",
                url=resp.url if resp.url else url,
                evidence=f"HTTP {resp.status_code} on {scheme}://{self.hostname}:{port}",
                category=self.CATEGORY,
                recommendation=f"Restrict {label} access to trusted IPs only. Consider disabling if not needed.",
            )
        return None

    def _scan_control_panels(self):
        """Scan control panel ports."""
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_info = {
                executor.submit(self._probe_control_panel, port, scheme, label): label
                for port, scheme, label in CONTROL_PANELS
            }
            for future in as_completed(future_to_info):
                result = future.result()
                if result is not None:
                    self.findings.append(result)


# ---------------------------------------------------------------------------
# Report generators
# ---------------------------------------------------------------------------

def compute_risk_score(findings: List[Finding]) -> Tuple[int, str]:
    """Compute overall risk score from findings."""
    if not findings:
        return 0, "NONE"
    total = sum(f.score for f in findings)
    crit_count = sum(1 for f in findings if f.severity == SEVERITY_CRITICAL)
    high_count = sum(1 for f in findings if f.severity == SEVERITY_HIGH)

    # Weighted score: base + amplifier for critical mass
    score = total
    if crit_count >= 3:
        score += 15
    if high_count >= 5:
        score += 10

    # Normalize to 0-100
    score = min(score, 100)

    if score >= 70 or crit_count >= 2:
        rating = "CRITICAL"
    elif score >= 50 or crit_count >= 1:
        rating = "HIGH"
    elif score >= 30:
        rating = "MEDIUM"
    elif score >= 10:
        rating = "LOW"
    else:
        rating = "INFORMATIONAL"

    return score, rating


def save_json_report(findings: List[Finding], target_url: str, scan_duration: float,
                     request_count: int, output_name: str) -> str:
    """Save findings as JSON report."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    score, rating = compute_risk_score(findings)

    report = {
        "meta": {
            "tool": "HAKA Web Application Scanner",
            "version": VERSION,
            "scan_date": datetime.utcnow().isoformat() + "Z",
            "target": target_url,
            "duration_seconds": round(scan_duration, 2),
            "total_requests": request_count,
        },
        "risk": {
            "score": score,
            "rating": rating,
            "total_findings": len(findings),
            "by_severity": {
                SEVERITY_CRITICAL: sum(1 for f in findings if f.severity == SEVERITY_CRITICAL),
                SEVERITY_HIGH: sum(1 for f in findings if f.severity == SEVERITY_HIGH),
                SEVERITY_MEDIUM: sum(1 for f in findings if f.severity == SEVERITY_MEDIUM),
                SEVERITY_LOW: sum(1 for f in findings if f.severity == SEVERITY_LOW),
                SEVERITY_INFO: sum(1 for f in findings if f.severity == SEVERITY_INFO),
            },
        },
        "findings": [f.to_dict() for f in sorted(findings, key=lambda x: -x.score)],
    }

    filepath = os.path.join(REPORTS_DIR, f"{output_name}.json")
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return filepath


def save_html_report(findings: List[Finding], target_url: str, scan_duration: float,
                     request_count: int, output_name: str) -> str:
    """Save findings as HTML report."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    score, rating = compute_risk_score(findings)
    sorted_findings = sorted(findings, key=lambda x: -x.score)

    severity_counts = {
        SEVERITY_CRITICAL: sum(1 for f in findings if f.severity == SEVERITY_CRITICAL),
        SEVERITY_HIGH: sum(1 for f in findings if f.severity == SEVERITY_HIGH),
        SEVERITY_MEDIUM: sum(1 for f in findings if f.severity == SEVERITY_MEDIUM),
        SEVERITY_LOW: sum(1 for f in findings if f.severity == SEVERITY_LOW),
        SEVERITY_INFO: sum(1 for f in findings if f.severity == SEVERITY_INFO),
    }

    rating_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#e74c3c",
        "MEDIUM": "#f39c12",
        "LOW": "#3498db",
        "INFORMATIONAL": "#6c757d",
        "NONE": "#28a745",
    }
    severity_css_colors = {
        SEVERITY_CRITICAL: "#dc3545",
        SEVERITY_HIGH: "#e74c3c",
        SEVERITY_MEDIUM: "#f39c12",
        SEVERITY_LOW: "#3498db",
        SEVERITY_INFO: "#6c757d",
    }

    findings_html = ""
    for idx, f in enumerate(sorted_findings, 1):
        sev_color = severity_css_colors.get(f.severity, "#6c757d")
        evidence_block = ""
        if f.evidence:
            evidence_block = f"""
            <div class="evidence">
                <strong>Evidence:</strong><br>
                <code>{html_escape(f.evidence)}</code>
            </div>"""
        url_block = ""
        if f.url:
            evidence_url = html_escape(f.url)
            url_block = f'<div class="finding-url"><strong>URL:</strong> <a href="{evidence_url}" target="_blank">{evidence_url}</a></div>'
        rec_block = ""
        if f.recommendation:
            rec_block = f'<div class="recommendation"><strong>Recommendation:</strong> {html_escape(f.recommendation)}</div>'

        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="finding-num">#{idx}</span>
                <span class="severity-badge" style="background-color:{sev_color}">{html_escape(f.severity)}</span>
                <span class="finding-id">{html_escape(f.finding_id)}</span>
                <span class="finding-title">{html_escape(f.title)}</span>
            </div>
            <div class="finding-body">
                <p>{html_escape(f.description)}</p>
                {url_block}
                {evidence_block}
                {rec_block}
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HAKA Web Scanner Report - {html_escape(target_url)}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}
    header {{ background: linear-gradient(135deg, #161b22, #1a2332); border: 1px solid #30363d; border-radius: 8px; padding: 30px; margin-bottom: 24px; }}
    header h1 {{ color: #58a6ff; font-size: 1.8em; margin-bottom: 4px; }}
    header .subtitle {{ color: #8b949e; font-size: 0.95em; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }}
    .meta-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 16px; }}
    .meta-card .label {{ color: #8b949e; font-size: 0.8em; text-transform: uppercase; letter-spacing: 1px; }}
    .meta-card .value {{ color: #f0f6fc; font-size: 1.3em; font-weight: 600; margin-top: 4px; }}
    .risk-banner {{ background: #161b22; border: 2px solid {rating_colors.get(rating, '#6c757d')}; border-radius: 8px; padding: 24px; margin-bottom: 24px; text-align: center; }}
    .risk-banner .risk-score {{ font-size: 3em; font-weight: 700; color: {rating_colors.get(rating, '#6c757d')}; }}
    .risk-banner .risk-rating {{ font-size: 1.3em; color: {rating_colors.get(rating, '#6c757d')}; font-weight: 600; }}
    .severity-summary {{ display: flex; gap: 12px; justify-content: center; margin: 16px 0; flex-wrap: wrap; }}
    .severity-summary .sev-item {{ padding: 8px 16px; border-radius: 4px; font-weight: 600; font-size: 0.9em; }}
    .findings-section {{ margin-top: 24px; }}
    .findings-section h2 {{ color: #58a6ff; margin-bottom: 16px; }}
    .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; margin-bottom: 12px; overflow: hidden; }}
    .finding-header {{ padding: 14px 18px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; border-bottom: 1px solid #21262d; }}
    .finding-num {{ color: #8b949e; font-weight: 600; min-width: 30px; }}
    .severity-badge {{ color: #fff; padding: 2px 10px; border-radius: 3px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }}
    .finding-id {{ color: #8b949e; font-family: monospace; font-size: 0.85em; }}
    .finding-title {{ color: #f0f6fc; font-weight: 600; }}
    .finding-body {{ padding: 14px 18px; }}
    .finding-body p {{ margin-bottom: 10px; }}
    .finding-url {{ margin-bottom: 8px; }}
    .finding-url a {{ color: #58a6ff; text-decoration: none; word-break: break-all; }}
    .finding-url a:hover {{ text-decoration: underline; }}
    .evidence {{ background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 12px; margin: 10px 0; }}
    .evidence code {{ color: #f0883e; font-size: 0.9em; white-space: pre-wrap; word-break: break-all; }}
    .recommendation {{ background: #0e2a1f; border: 1px solid #238636; border-radius: 4px; padding: 12px; margin-top: 10px; color: #3fb950; }}
    footer {{ text-align: center; padding: 30px 0; color: #484f58; font-size: 0.85em; border-top: 1px solid #21262d; margin-top: 40px; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>HAKA Web Application Scanner</h1>
        <div class="subtitle">Security Assessment Report</div>
    </header>

    <div class="meta-grid">
        <div class="meta-card">
            <div class="label">Target</div>
            <div class="value" style="font-size:1em;word-break:break-all;">{html_escape(target_url)}</div>
        </div>
        <div class="meta-card">
            <div class="label">Scan Date</div>
            <div class="value" style="font-size:1em;">{datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</div>
        </div>
        <div class="meta-card">
            <div class="label">Duration</div>
            <div class="value">{scan_duration:.1f}s</div>
        </div>
        <div class="meta-card">
            <div class="label">Requests</div>
            <div class="value">{request_count}</div>
        </div>
    </div>

    <div class="risk-banner">
        <div class="risk-score">{score}/100</div>
        <div class="risk-rating">Overall Risk: {rating}</div>
        <div class="severity-summary">
            <span class="sev-item" style="background:#dc354520;color:#dc3545;">CRITICAL: {severity_counts[SEVERITY_CRITICAL]}</span>
            <span class="sev-item" style="background:#e74c3c20;color:#e74c3c;">HIGH: {severity_counts[SEVERITY_HIGH]}</span>
            <span class="sev-item" style="background:#f39c1220;color:#f39c12;">MEDIUM: {severity_counts[SEVERITY_MEDIUM]}</span>
            <span class="sev-item" style="background:#3498db20;color:#3498db;">LOW: {severity_counts[SEVERITY_LOW]}</span>
            <span class="sev-item" style="background:#6c757d20;color:#6c757d;">INFO: {severity_counts[SEVERITY_INFO]}</span>
        </div>
    </div>

    <div class="findings-section">
        <h2>Findings ({len(findings)})</h2>
        {findings_html if findings_html else '<p style="color:#8b949e;">No findings to report.</p>'}
    </div>

    <footer>
        HAKA AI Framework v{VERSION} &mdash; For authorized security testing only
    </footer>
</div>
</body>
</html>"""

    filepath = os.path.join(REPORTS_DIR, f"{output_name}.html")
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(html)
    return filepath


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

def print_banner():
    banner = rf"""
{Fore.RED}{Style.BRIGHT}
    ██╗  ██╗ █████╗ ██╗  ██╗ █████╗     ██╗    ██╗███████╗██████╗
    ██║  ██║██╔══██╗██║ ██╔╝██╔══██╗    ██║    ██║██╔════╝██╔══██╗
    ███████║███████║█████╔╝ ███████║    ██║ █╗ ██║█████╗  ██████╔╝
    ██╔══██║██╔══██║██╔═██╗ ██╔══██║    ██║███╗██║██╔══╝  ██╔══██╗
    ██║  ██║██║  ██║██║  ██╗██║  ██║    ╚███╔███╔╝███████╗██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚══╝╚══╝ ╚══════╝╚═════╝
{Style.RESET_ALL}
    {Fore.CYAN}HAKA AI - Web Application Scanner v{VERSION}{Style.RESET_ALL}
    {Fore.WHITE}Sections C1-C5: PHP | WordPress | Files | Admin Panels{Style.RESET_ALL}
    {Style.DIM}For authorized security testing only{Style.RESET_ALL}
"""
    print(banner)


def print_section(title: str):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[*] {title}{Style.RESET_ALL}")
    print(f"    {'=' * len(title)}")


def print_finding(finding: Finding):
    print(finding.console_line())


def print_summary(findings: List[Finding], duration: float, request_count: int):
    score, rating = compute_risk_score(findings)
    rating_color = SEVERITY_COLORS.get(rating, Fore.WHITE)

    counts = {}
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        counts[sev] = sum(1 for f in findings if f.severity == sev)

    print(f"\n{'=' * 68}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{'=' * 68}")
    print(f"  Total Findings : {len(findings)}")
    print(f"  Risk Score     : {rating_color}{score}/100 ({rating}){Style.RESET_ALL}")
    print(f"  Duration       : {duration:.1f}s")
    print(f"  HTTP Requests  : {request_count}")
    print()
    print(f"  {SEVERITY_COLORS[SEVERITY_CRITICAL]}CRITICAL : {counts[SEVERITY_CRITICAL]}{Style.RESET_ALL}")
    print(f"  {SEVERITY_COLORS[SEVERITY_HIGH]}HIGH     : {counts[SEVERITY_HIGH]}{Style.RESET_ALL}")
    print(f"  {SEVERITY_COLORS[SEVERITY_MEDIUM]}MEDIUM   : {counts[SEVERITY_MEDIUM]}{Style.RESET_ALL}")
    print(f"  {SEVERITY_COLORS[SEVERITY_LOW]}LOW      : {counts[SEVERITY_LOW]}{Style.RESET_ALL}")
    print(f"  {SEVERITY_COLORS[SEVERITY_INFO]}INFO     : {counts[SEVERITY_INFO]}{Style.RESET_ALL}")
    print(f"{'=' * 68}")


# ---------------------------------------------------------------------------
# Main scanner orchestrator
# ---------------------------------------------------------------------------

class HAKAWebScanner:
    """Main scanner that orchestrates all scan modules."""

    def __init__(self, target_url: str, delay: float = 0.0, timeout: int = DEFAULT_TIMEOUT,
                 wordpress_only: bool = False, full_scan: bool = False):
        # Normalize URL
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url.rstrip("/")
        self.wordpress_only = wordpress_only
        self.full_scan = full_scan
        self.client = HTTPClient(timeout=timeout, delay=delay)
        self.findings: List[Finding] = []

    def preflight_check(self) -> bool:
        """Verify the target is reachable."""
        print(f"\n{Fore.YELLOW}[*] Preflight: checking target connectivity...{Style.RESET_ALL}")
        resp = self.client.get(self.target_url + "/")
        if resp is None:
            print(f"{Fore.RED}[!] Target unreachable: {self.target_url}{Style.RESET_ALL}")
            return False
        print(f"{Fore.GREEN}[+] Target is up: HTTP {resp.status_code}{Style.RESET_ALL}")

        # Show basic server info
        server = resp.headers.get("Server", "Not disclosed")
        powered_by = resp.headers.get("X-Powered-By", "Not disclosed")
        print(f"    Server       : {server}")
        print(f"    X-Powered-By : {powered_by}")

        if server and server != "Not disclosed":
            self.findings.append(Finding(
                title=f"Server header disclosed: {server}",
                severity=SEVERITY_INFO,
                finding_id="CRIT-ET-07",
                description="Server software and version are disclosed in HTTP headers.",
                url=self.target_url,
                evidence=f"Server: {server}",
                category="Information Disclosure",
                recommendation="Suppress the Server header or set it to a generic value.",
            ))
        if powered_by and powered_by != "Not disclosed":
            self.findings.append(Finding(
                title=f"X-Powered-By header disclosed: {powered_by}",
                severity=SEVERITY_LOW,
                finding_id="CRIT-ET-07",
                description="Technology stack is disclosed via X-Powered-By header.",
                url=self.target_url,
                evidence=f"X-Powered-By: {powered_by}",
                category="Information Disclosure",
                recommendation="Remove the X-Powered-By header from server responses.",
            ))

        # Check security headers
        self._check_security_headers(resp)

        return True

    def _check_security_headers(self, resp: requests.Response):
        """Check for missing security headers."""
        important_headers = {
            "Strict-Transport-Security": ("HSTS header missing", "Enables downgrade attacks and SSL stripping."),
            "X-Content-Type-Options": ("X-Content-Type-Options missing", "Browser may MIME-sniff responses, enabling XSS."),
            "X-Frame-Options": ("X-Frame-Options missing", "Site may be vulnerable to clickjacking."),
            "Content-Security-Policy": ("Content-Security-Policy missing", "No CSP to mitigate XSS and injection attacks."),
        }
        missing = []
        for header, (title, desc) in important_headers.items():
            if header.lower() not in {k.lower(): v for k, v in resp.headers.items()}:
                missing.append(header)

        if missing:
            self.findings.append(Finding(
                title=f"Missing security headers: {', '.join(missing)}",
                severity=SEVERITY_LOW,
                finding_id="CRIT-ET-08",
                description="Important security headers are not set, reducing defense-in-depth.",
                url=self.target_url,
                evidence=f"Missing: {', '.join(missing)}",
                category="HTTP Security",
                recommendation="Configure the web server to send all recommended security headers.",
            ))

    def run(self) -> List[Finding]:
        """Execute the scan."""
        start_time = time.time()

        if not self.preflight_check():
            return self.findings

        if self.wordpress_only:
            # WordPress checks only
            print_section("WordPress Security Checks")
            wp_scanner = WordPressScanner(self.target_url, self.client)
            wp_findings = wp_scanner.run()
            self.findings.extend(wp_findings)
            if not wp_scanner.is_wordpress:
                print(f"  {Fore.YELLOW}[!] WordPress not detected on this target.{Style.RESET_ALL}")
            for f in wp_findings:
                print_finding(f)
        else:
            # PHP checks
            print_section("PHP Security Configuration")
            php_scanner = PHPSecurityScanner(self.target_url, self.client)
            php_findings = php_scanner.run()
            self.findings.extend(php_findings)
            for f in php_findings:
                print_finding(f)
            if not php_findings:
                print(f"  {Style.DIM}  No PHP-specific findings.{Style.RESET_ALL}")

            # WordPress checks
            print_section("WordPress Detection & Enumeration")
            wp_scanner = WordPressScanner(self.target_url, self.client)
            wp_findings = wp_scanner.run()
            self.findings.extend(wp_findings)
            if not wp_scanner.is_wordpress:
                print(f"  {Style.DIM}  WordPress not detected.{Style.RESET_ALL}")
            for f in wp_findings:
                print_finding(f)

            # Sensitive files
            print_section("Sensitive File Discovery")
            file_scanner = SensitiveFileScanner(self.target_url, self.client)
            file_findings = file_scanner.run()
            self.findings.extend(file_findings)
            for f in file_findings:
                print_finding(f)
            if not file_findings:
                print(f"  {Style.DIM}  No sensitive files found.{Style.RESET_ALL}")

            # Admin panels
            if self.full_scan:
                print_section("Admin Panel & Control Panel Detection")
                admin_scanner = AdminPanelScanner(self.target_url, self.client)
                admin_findings = admin_scanner.run()
                self.findings.extend(admin_findings)
                for f in admin_findings:
                    print_finding(f)
                if not admin_findings:
                    print(f"  {Style.DIM}  No admin panels discovered.{Style.RESET_ALL}")
            else:
                # Basic admin panel check (no port probing)
                print_section("Admin Panel Detection (use --full-scan for port probing)")
                admin_scanner = AdminPanelScanner(self.target_url, self.client)
                admin_scanner._scan_admin_paths()
                self.findings.extend(admin_scanner.findings)
                for f in admin_scanner.findings:
                    print_finding(f)
                if not admin_scanner.findings:
                    print(f"  {Style.DIM}  No admin panels discovered on default paths.{Style.RESET_ALL}")

        duration = time.time() - start_time
        print_summary(self.findings, duration, self.client.request_count)

        return self.findings

    @property
    def duration(self) -> float:
        """Return 0; actual duration tracked in run()."""
        return 0.0


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="haka_web_scanner",
        description="HAKA AI - Web Application Security Scanner (Tool 6)",
        epilog="For authorized security testing only. Sections C1-C5.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--url", "-u",
        required=True,
        help="Target URL (e.g., https://example.com)",
    )
    parser.add_argument(
        "--wordpress-only", "-w",
        action="store_true",
        default=False,
        help="Only run WordPress-specific checks",
    )
    parser.add_argument(
        "--full-scan", "-f",
        action="store_true",
        default=False,
        help="Full scan including control panel port probing",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output report base name (saved to reports dir). If omitted, auto-generated.",
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=0.0,
        help="Delay between requests in seconds (rate limiting)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        default=False,
        help="Output JSON report only, suppress console output",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.no_color:
        # Strip ANSI by reinitializing colorama with strip=True
        colorama_init(strip=True)

    if not args.json_only:
        print_banner()

    # Determine output name
    if args.output:
        output_name = args.output
    else:
        parsed = urlparse(args.url)
        host_part = (parsed.hostname or "unknown").replace(".", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_name = f"haka_web_{host_part}_{timestamp}"

    # Run scanner
    start = time.time()
    scanner = HAKAWebScanner(
        target_url=args.url,
        delay=args.delay,
        timeout=args.timeout,
        wordpress_only=args.wordpress_only,
        full_scan=args.full_scan,
    )
    findings = scanner.run()
    duration = time.time() - start

    # Save reports
    json_path = save_json_report(findings, args.url, duration, scanner.client.request_count, output_name)
    html_path = save_html_report(findings, args.url, duration, scanner.client.request_count, output_name)

    print(f"\n{Fore.GREEN}[+] JSON report saved: {json_path}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] HTML report saved: {html_path}{Style.RESET_ALL}")
    print()

    # Exit with non-zero if critical findings
    crit_count = sum(1 for f in findings if f.severity == SEVERITY_CRITICAL)
    if crit_count > 0:
        sys.exit(2)
    elif findings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
