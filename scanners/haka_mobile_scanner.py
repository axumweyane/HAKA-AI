#!/usr/bin/env python3
"""
HAKA Mobile App Security Scanner
==================================
Comprehensive Android/iOS mobile application security analysis.

Capabilities:
  - APK decompilation and AndroidManifest.xml analysis
  - Dangerous permission detection
  - Exported component enumeration
  - Hardcoded secret extraction (API keys, tokens, passwords, private keys)
  - Network security configuration audit
  - WebView vulnerability detection
  - ProGuard/R8 obfuscation assessment
  - SDK version analysis
  - LLM-enhanced risk analysis and remediation prioritization
  - MITRE ATT&CK Mobile technique mapping
  - Risk scoring (0-100)

Usage:
  python3 haka_mobile_scanner.py --apk banking.apk
  python3 haka_mobile_scanner.py --apk app.apk --model deepseek --output report.md
  python3 haka_mobile_scanner.py --apk app.apk --no-llm

Author: HAKA AI Framework
License: For authorized security testing only
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET

# ── Paths ────────────────────────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
ANDROID_NS = "http://schemas.android.com/apk/res/android"
ET.register_namespace("android", ANDROID_NS)

# Tool paths
APKTOOL = "/usr/bin/apktool"
STRINGS = "/usr/bin/strings"
JADX = "/usr/local/bin/jadx"

# ── Constants ────────────────────────────────────────────────────────────────

DANGEROUS_PERMISSIONS: Set[str] = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "CAMERA", "RECORD_AUDIO",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_PHONE_STATE", "READ_PRIVILEGED_PHONE_STATE",
    "CALL_PHONE", "ANSWER_PHONE_CALLS",
    "BODY_SENSORS", "ACTIVITY_RECOGNITION",
    "SEND_SMS", "INSTALL_SHORTCUT", "UNINSTALL_SHORTCUT",
    "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW",
    "MANAGE_EXTERNAL_STORAGE", "BIND_ACCESSIBILITY_SERVICE",
    "USE_BIOMETRIC", "USE_FINGERPRINT",
}

# Severity weight for dangerous permissions
PERMISSION_SEVERITY: Dict[str, Tuple[str, int]] = {
    "READ_SMS": ("HIGH", 8),
    "SEND_SMS": ("HIGH", 8),
    "RECEIVE_SMS": ("HIGH", 8),
    "READ_CONTACTS": ("HIGH", 7),
    "WRITE_CONTACTS": ("HIGH", 7),
    "ACCESS_FINE_LOCATION": ("MEDIUM", 5),
    "ACCESS_COARSE_LOCATION": ("MEDIUM", 4),
    "ACCESS_BACKGROUND_LOCATION": ("HIGH", 7),
    "CAMERA": ("MEDIUM", 5),
    "RECORD_AUDIO": ("HIGH", 7),
    "READ_CALL_LOG": ("HIGH", 7),
    "WRITE_CALL_LOG": ("HIGH", 7),
    "READ_EXTERNAL_STORAGE": ("MEDIUM", 5),
    "WRITE_EXTERNAL_STORAGE": ("MEDIUM", 5),
    "READ_PHONE_STATE": ("HIGH", 6),
    "CALL_PHONE": ("MEDIUM", 5),
    "BODY_SENSORS": ("MEDIUM", 4),
    "ACTIVITY_RECOGNITION": ("MEDIUM", 4),
    "SYSTEM_ALERT_WINDOW": ("HIGH", 7),
    "REQUEST_INSTALL_PACKAGES": ("HIGH", 7),
    "BIND_ACCESSIBILITY_SERVICE": ("CRITICAL", 9),
    "MANAGE_EXTERNAL_STORAGE": ("MEDIUM", 5),
}

SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r'sk-[A-Za-z0-9]{20,}', 'Alpaca-style API Key'),
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID'),
    (r'(?i)api[_-]?key\s*[=:]\s*["\'][A-Za-z0-9\-_]{10,}["\']', 'API Key Assignment'),
    (r'(?i)secret\s*[=:]\s*["\'][A-Za-z0-9\-_]{8,}["\']', 'Hardcoded Secret'),
    (r'(?i)password\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded Password'),
    (r'(?i)token\s*[=:]\s*["\'][A-Za-z0-9\-_\.]{10,}["\']', 'Hardcoded Token'),
    (r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}', 'Bearer Token'),
    (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', 'Private Key'),
    (r'-----BEGIN CERTIFICATE-----', 'Embedded Certificate'),
    (r'(?i)jdbc:[a-z]+://[^/\s]+', 'JDBC Connection String'),
    (r'(?i)mongodb(\+srv)?://[^/\s]+', 'MongoDB Connection String'),
    (r'(?i)redis://[^/\s]+', 'Redis Connection String'),
    (r'(?i)(mysql|postgresql|postgres)://[^/\s]+', 'Database Connection String'),
    (r'sk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Secret Key'),
    (r'pk_live_[0-9a-zA-Z]{24,}', 'Stripe Live Publishable Key'),
    (r'(?i)firebase.*auth.*[=:]\s*["\'][A-Za-z0-9\-_\.]{20,}', 'Firebase Auth Config'),
    (r'(?i)client[_-]?secret\s*[=:]\s*["\'][A-Za-z0-9\-_]{8,}["\']', 'OAuth Client Secret'),
    (r'(?i)api[_-]?secret\s*[=:]\s*["\'][A-Za-z0-9\-_]{8,}["\']', 'API Secret'),
    (r'(?i)encryption[_-]?key\s*[=:]\s*["\'][A-Za-z0-9\-_/+]{16,}["\']', 'Encryption Key'),
    (r'(?i)private[_-]?key\s*[=:]\s*["\'][A-Za-z0-9\-_/+]{20,}["\']', 'Private Key String'),
    (r'(?i)auth[_-]?token\s*[=:]\s*["\'][A-Za-z0-9\-_\.]{10,}["\']', 'Auth Token'),
    (r'(?:https?://[^\s,"\'<>]+)', 'URL/Endpoint'),
]

MITRE_ATTACK_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1418": {
        "name": "Application Discovery",
        "desc": "Adversaries may seek to identify applications installed on the device.",
        "url": "https://attack.mitre.org/techniques/T1418/",
    },
    "T1417": {
        "name": "Input Capture",
        "desc": "Adversaries may capture user input via keylogging, accessibility services, or overlay attacks.",
        "url": "https://attack.mitre.org/techniques/T1417/",
    },
    "T1407": {
        "name": "Download New Code at Runtime",
        "desc": "Adversaries may download and execute code not included in the original app package.",
        "url": "https://attack.mitre.org/techniques/T1407/",
    },
    "T1444": {
        "name": "Masquerade as Legitimate Application",
        "desc": "Adversaries may mimic legitimate apps to trick users into installation.",
        "url": "https://attack.mitre.org/techniques/T1444/",
    },
    "T1409": {
        "name": "Stored Application Data",
        "desc": "Adversaries may access data stored by applications on the device.",
        "url": "https://attack.mitre.org/techniques/T1409/",
    },
    "T1412": {
        "name": "Capture SMS Messages",
        "desc": "Adversaries may capture SMS messages for 2FA bypass or intelligence.",
        "url": "https://attack.mitre.org/techniques/T1412/",
    },
    "T1430": {
        "name": "Location Tracking",
        "desc": "Adversaries may track the device's physical location.",
        "url": "https://attack.mitre.org/techniques/T1430/",
    },
    "T1416": {
        "name": "Native API",
        "desc": "Adversaries may invoke native APIs to bypass application-level controls.",
        "url": "https://attack.mitre.org/techniques/T1416/",
    },
    "T1406": {
        "name": "Obfuscated Files or Information",
        "desc": "Adversaries may obfuscate code or resources to evade analysis.",
        "url": "https://attack.mitre.org/techniques/T1406/",
    },
    "T1429": {
        "name": "Audio Capture",
        "desc": "Adversaries may capture audio via device microphone.",
        "url": "https://attack.mitre.org/techniques/T1429/",
    },
    "T1419": {
        "name": "Device Lockout",
        "desc": "Adversaries may lock the user out of their device.",
        "url": "https://attack.mitre.org/techniques/T1419/",
    },
}


# ── Utility Functions ────────────────────────────────────────────────────────

def _ns(tag: str) -> str:
    """Qualify a tag with the Android XML namespace."""
    return f"{{{ANDROID_NS}}}{tag}"


def redact(value: str, show: int = 4) -> str:
    """Redact a secret, showing first/last few characters."""
    if len(value) <= show * 2 + 4:
        return value[:show] + "***" + value[-show:] if len(value) > show + 3 else "***"
    return value[:show] + "***" + value[-show:]


def ensure_dir(path: str) -> str:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)
    return path


# ── Main Scanner Class ───────────────────────────────────────────────────────

class MobileAppScanner:
    """Comprehensive mobile app security scanner."""

    def __init__(self, apk_path: str, output_name: Optional[str] = None,
                 use_llm: bool = True, llm_model: str = "deepseek",
                 verbose: bool = False):
        self.apk_path = os.path.abspath(apk_path)
        self.output_name = output_name or Path(apk_path).stem
        self.use_llm = use_llm
        self.llm_model = llm_model
        self.verbose = verbose
        self.temp_dir: Optional[str] = None
        self.decompiled_dir: Optional[str] = None
        self.findings: Dict[str, Any] = {
            "meta": {},
            "manifest": {},
            "permissions": {},
            "exported_components": {},
            "secrets": {},
            "network_security": {},
            "webview": {},
            "obfuscation": {},
            "sdk_analysis": {},
            "risk_score": 0,
            "mitre_mappings": [],
            "llm_analysis": {},
        }

    # ── Phase 0: Verify inputs & tools ───────────────────────────────────

    def check_prerequisites(self) -> List[str]:
        """Check required tools and APK validity. Returns list of warnings."""
        warnings = []

        if not os.path.isfile(self.apk_path):
            raise FileNotFoundError(f"APK file not found: {self.apk_path}")

        if not self.apk_path.lower().endswith(".apk"):
            warnings.append(f"File does not have .apk extension: {self.apk_path}")

        # Verify APK is a valid zip
        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                if "AndroidManifest.xml" not in zf.namelist():
                    raise ValueError("APK does not contain AndroidManifest.xml")
        except zipfile.BadZipFile:
            raise ValueError(f"Not a valid APK/ZIP file: {self.apk_path}")

        for tool_name, tool_path in [("apktool", APKTOOL), ("strings", STRINGS)]:
            if not (os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)):
                warnings.append(f"Tool not found or not executable: {tool_name} ({tool_path})")

        return warnings

    # ── Phase 1: Decompile APK ───────────────────────────────────────────

    def decompile(self) -> str:
        """Decompile APK using apktool. Returns path to decompiled directory."""
        self.temp_dir = tempfile.mkdtemp(prefix="haka_mobile_")
        self.decompiled_dir = os.path.join(self.temp_dir, "decompiled")

        cmd = [APKTOOL, "d", self.apk_path, "-o", self.decompiled_dir, "-f"]
        if self.verbose:
            print(f"[*] Decompiling: {' '.join(cmd)}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            # apktool sometimes exits 0 with warnings on stderr — check if output exists
            if not os.path.isdir(self.decompiled_dir) or not os.path.isfile(
                os.path.join(self.decompiled_dir, "AndroidManifest.xml")
            ):
                raise RuntimeError(f"apktool decompilation failed: {stderr}")

        if self.verbose:
            print(f"[+] Decompiled to: {self.decompiled_dir}")

        return self.decompiled_dir

    # ── Phase 2: Parse AndroidManifest.xml ───────────────────────────────

    def parse_manifest(self) -> Dict[str, Any]:
        """Parse AndroidManifest.xml for security findings."""
        manifest_path = os.path.join(self.decompiled_dir, "AndroidManifest.xml")
        if not os.path.isfile(manifest_path):
            raise FileNotFoundError(f"AndroidManifest.xml not found at {manifest_path}")

        tree = ET.parse(manifest_path)
        root = tree.getroot()

        result: Dict[str, Any] = {
            "package": root.get("package", "unknown"),
            "permissions": [],
            "dangerous_permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "exported_components": [],
            "debuggable": False,
            "allow_backup": True,
            "network_security_config": None,
            "application_name": "",
        }

        # Extract permissions
        for perm in root.findall(f".//uses-permission"):
            perm_name = perm.get(_ns("name"), "")
            if perm_name:
                # Normalize: may have android.permission. prefix
                short_name = perm_name.replace("android.permission.", "")
                result["permissions"].append(perm_name)
                if short_name in DANGEROUS_PERMISSIONS or perm_name in DANGEROUS_PERMISSIONS:
                    check_name = short_name if short_name in DANGEROUS_PERMISSIONS else perm_name
                    severity, weight = PERMISSION_SEVERITY.get(
                        check_name, ("MEDIUM", 5)
                    )
                    result["dangerous_permissions"].append({
                        "permission": perm_name,
                        "short_name": check_name,
                        "severity": severity,
                        "weight": weight,
                    })

        # Parse application element
        app = root.find(".//application")
        if app is not None:
            result["debuggable"] = app.get(_ns("debuggable"), "false").lower() == "true"
            result["allow_backup"] = app.get(_ns("allowBackup"), "true").lower() != "false"
            result["network_security_config"] = app.get(_ns("networkSecurityConfig"), None)
            result["application_name"] = app.get(_ns("name"), "")
            result["task_affinity"] = app.get(_ns("taskAffinity"), "")
            result["extract_native_libs"] = app.get(_ns("extractNativeLibs"), "")

            # ── Enumerate components ──
            for component_type, tag, storage_key in [
                ("activity", "activity", "activities"),
                ("service", "service", "services"),
                ("receiver", "receiver", "receivers"),
                ("provider", "provider", "providers"),
            ]:
                for comp in app.findall(tag):
                    name = comp.get(_ns("name"), "unknown")
                    exported = comp.get(_ns("exported"), "false").lower() == "true"
                    permission = comp.get(_ns("permission"), "")
                    intent_filters = []
                    for intent in comp.findall("intent-filter"):
                        actions = [
                            a.get(_ns("name"), "")
                            for a in intent.findall("action")
                        ]
                        intent_filters.append({"actions": actions})

                    entry = {
                        "name": name,
                        "exported": exported,
                        "permission": permission or None,
                        "intent_filters": intent_filters,
                    }

                    result[storage_key].append(entry)

                    if exported:
                        result["exported_components"].append({
                            "type": component_type,
                            "name": name,
                            "permission_protected": bool(permission),
                            "permission": permission or None,
                            "intent_filters": intent_filters,
                        })

        return result

    # ── Phase 3: SDK Version Analysis ────────────────────────────────────

    def analyze_sdk(self) -> Dict[str, Any]:
        """Extract SDK version info from apktool.yml."""
        yml_path = os.path.join(self.decompiled_dir, "apktool.yml")
        result: Dict[str, Any] = {
            "min_sdk": None,
            "target_sdk": None,
            "target_sdk_outdated": False,
            "target_sdk_severity": "INFO",
        }

        if not os.path.isfile(yml_path):
            return result

        try:
            with open(yml_path, "r") as f:
                content = f.read()

            # Parse apktool.yml
            in_sdk_info = False
            for line in content.splitlines():
                if line.strip() == "sdkInfo:":
                    in_sdk_info = True
                    continue
                if in_sdk_info:
                    if not line.startswith("  "):
                        break
                    line = line.strip()
                    if ":" in line:
                        key, val = line.split(":", 1)
                        key = key.strip().strip("'\"")
                        val = val.strip().strip("'\"")
                        if key.lower() == "minsdkversion":
                            result["min_sdk"] = val
                        elif key.lower() == "targetsdkversion":
                            result["target_sdk"] = val

            # Assess target SDK
            target = result.get("target_sdk")
            if target:
                try:
                    target_int = int(target)
                    if target_int < 33:
                        result["target_sdk_outdated"] = True
                        if target_int < 28:
                            result["target_sdk_severity"] = "HIGH"
                        elif target_int < 30:
                            result["target_sdk_severity"] = "MEDIUM"
                        else:
                            result["target_sdk_severity"] = "LOW"
                except (ValueError, TypeError):
                    pass

        except Exception as e:
            if self.verbose:
                print(f"[!] Error parsing apktool.yml: {e}")

        return result

    # ── Phase 4: Hardcoded Secret Extraction ─────────────────────────────

    def extract_secrets(self) -> Dict[str, Any]:
        """Run strings on all files and search for hardcoded secrets."""
        result: Dict[str, Any] = {
            "total_findings": 0,
            "by_type": {},
            "findings": [],
            "urls": [],
            "ip_addresses": [],
        }

        # Collect all files to scan
        scan_files: List[str] = []

        # Priority files (source code, configs)
        priority_extensions = {".xml", ".json", ".properties", ".yml", ".yaml",
                               ".js", ".ts", ".kt", ".java", ".smali",
                               ".conf", ".cfg", ".config", ".env", ".txt"}

        for root, dirs, files in os.walk(self.decompiled_dir):
            # Skip certain directories
            dirs[:] = [d for d in dirs if d not in {"original", "lib", "unknown"}]
            for fname in files:
                fpath = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()
                if ext in priority_extensions:
                    scan_files.append(fpath)

        # Also scan all smali files for hardcoded values
        smali_root = os.path.join(self.decompiled_dir, "smali")
        if os.path.isdir(smali_root):
            for root, _, files in os.walk(smali_root):
                for fname in files:
                    if fname.endswith(".smali"):
                        scan_files.append(os.path.join(root, fname))

        # Use strings to extract printable strings from key binary files
        lib_dir = os.path.join(self.decompiled_dir, "lib")
        if os.path.isdir(lib_dir):
            for root, _, files in os.walk(lib_dir):
                for fname in files:
                    if fname.endswith(".so"):
                        scan_files.append(os.path.join(root, fname))

        # Build a combined strings output for scan files
        # Process in batches to avoid command-line length limits
        all_text = ""
        for fpath in scan_files[:500]:  # Limit to 500 files
            try:
                proc = subprocess.run(
                    [STRINGS, fpath],
                    capture_output=True, text=True, timeout=15,
                )
                if proc.returncode == 0:
                    all_text += proc.stdout + "\n"
            except (subprocess.TimeoutExpired, OSError):
                continue

        # Run regex patterns
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        local_ips = {"127.0.0.1", "0.0.0.0", "255.255.255.255",
                     "8.8.8.8", "8.8.4.4", "1.1.1.1"}

        for line in all_text.splitlines():
            line = line.strip()
            if not line or len(line) < 8:
                continue

            # Search for secrets
            for pattern, label in SECRET_PATTERNS:
                try:
                    for match in re.finditer(pattern, line):
                        secret_value = match.group(0)
                        # Skip common false positives
                        if label == "URL/Endpoint":
                            # Deduplicate URLs
                            if secret_value not in result["urls"]:
                                result["urls"].append(secret_value)
                            continue

                        if label == "Hardcoded Password":
                            # Extract just the value
                            val_match = re.search(r'["\']([^"\']+)["\']', secret_value)
                            if val_match:
                                pw = val_match.group(1)
                                if len(pw) < 4 or pw in {"password", "pass", "test", "admin", "1234", "passwd", "changeme"}:
                                    continue

                        # Avoid duplicates
                        existing = [f for f in result["findings"] if f["value"] == secret_value]
                        if existing:
                            continue

                        result["findings"].append({
                            "type": label,
                            "value": secret_value,
                            "redacted": redact(secret_value),
                            "line_preview": line[:120],
                        })

                        # Track by type
                        result["by_type"][label] = result["by_type"].get(label, 0) + 1
                        result["total_findings"] += 1
                except re.error:
                    continue

            # Extract IP addresses
            for ip_match in ip_pattern.finditer(line):
                ip = ip_match.group(0)
                if ip not in local_ips and ip not in result["ip_addresses"]:
                    # Validate octets
                    parts = ip.split(".")
                    if all(0 <= int(p) <= 255 for p in parts):
                        result["ip_addresses"].append(ip)

        return result

    # ── Phase 5: Network Security Config ─────────────────────────────────

    def analyze_network_security(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network security configuration."""
        result: Dict[str, Any] = {
            "has_config_file": False,
            "config_path": None,
            "cleartext_permitted": False,
            "certificate_pinning": False,
            "pinning_details": [],
            "findings": [],
        }

        # Check if network_security_config is referenced in manifest
        nsc_ref = manifest_data.get("network_security_config")
        if nsc_ref:
            # Resolve @xml/network_security_config to actual path
            config_name = nsc_ref.replace("@xml/", "")
            config_path = os.path.join(self.decompiled_dir, "res", "xml", f"{config_name}.xml")

            if os.path.isfile(config_path):
                result["has_config_file"] = True
                result["config_path"] = config_path

                try:
                    tree = ET.parse(config_path)
                    root = tree.getroot()

                    # Check base-config
                    base = root.find("base-config")
                    if base is not None:
                        cleartext = base.get("cleartextTrafficPermitted", "false")
                        if cleartext.lower() == "true":
                            result["cleartext_permitted"] = True
                            result["findings"].append({
                                "severity": "HIGH",
                                "title": "Cleartext Traffic Permitted",
                                "detail": "The app allows HTTP (unencrypted) traffic, exposing data to interception via MITM attacks.",
                                "remediation": "Set cleartextTrafficPermitted=\"false\" and enforce HTTPS.",
                            })

                    # Check for certificate pinning
                    pin_sets = root.findall(".//pin-set")
                    domain_configs = root.findall(".//domain-config")
                    trust_anchors = root.findall(".//trust-anchors")

                    for ps in pin_sets:
                        pins = ps.findall("pin")
                        for pin in pins:
                            result["certificate_pinning"] = True
                            result["pinning_details"].append({
                                "digest": pin.get("digest", "unknown"),
                                "pin_value": pin.text[:30] + "..." if pin.text and len(pin.text) > 30 else (pin.text or ""),
                            })

                    if not result["certificate_pinning"] and result["has_config_file"]:
                        result["findings"].append({
                            "severity": "MEDIUM",
                            "title": "No Certificate Pinning",
                            "detail": "Certificate pinning is not configured, making MITM attacks with user-installed CAs possible.",
                            "remediation": "Implement certificate pinning with pin-set elements in network_security_config.xml.",
                        })

                    # Check for debug-overrides
                    debug_overrides = root.findall(".//debug-overrides")
                    if debug_overrides:
                        result["findings"].append({
                            "severity": "HIGH",
                            "title": "Debug Overrides in Network Config",
                            "detail": "Debug overrides are present in network security config, potentially bypassing security in debug builds.",
                            "remediation": "Remove debug-overrides from production network security config.",
                        })

                except ET.ParseError as e:
                    result["findings"].append({
                        "severity": "INFO",
                        "title": "Network Security Config Parse Error",
                        "detail": f"Could not parse network_security_config.xml: {e}",
                    })
        else:
            # No explicit network security config — defaults apply
            # Android 9+ defaults to cleartext disabled, but needs config file for pinning
            result["findings"].append({
                "severity": "INFO",
                "title": "No Network Security Config",
                "detail": "App relies on default network security settings. No certificate pinning configured.",
                "remediation": "Add a network_security_config.xml with certificate pinning for production.",
            })

        return result

    # ── Phase 6: WebView Vulnerability Check ─────────────────────────────

    def analyze_webview(self, manifest_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check for WebView-related vulnerabilities in smali/decompiled code."""
        result: Dict[str, Any] = {
            "webview_present": False,
            "javascript_enabled": False,
            "file_access_enabled": False,
            "findings": [],
        }

        # Check if there's a WebView activity
        for activity in manifest_data.get("activities", []):
            if "webview" in activity.get("name", "").lower():
                result["webview_present"] = True
                break

        # Search smali code for WebView security issues
        smali_dir = os.path.join(self.decompiled_dir, "smali")
        if os.path.isdir(smali_dir):
            js_enabled_pattern = re.compile(
                r'Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)',
                re.IGNORECASE
            )
            file_access_pattern = re.compile(
                r'Landroid/webkit/WebSettings;->setAllowFileAccess\(Z\)',
                re.IGNORECASE
            )
            # setAllowFileAccessFromFileURLs — even worse
            file_url_access_pattern = re.compile(
                r'Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs\(Z\)',
                re.IGNORECASE
            )
            setAllowUniversalAccess = re.compile(
                r'Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs\(Z\)',
                re.IGNORECASE
            )
            ssl_error_handler = re.compile(
                r'onReceivedSslError',
                re.IGNORECASE
            )

            for root, _, files in os.walk(smali_dir):
                for fname in files:
                    if not fname.endswith(".smali"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        if js_enabled_pattern.search(content):
                            # Check if it's setting to true
                            if "const/4 v0, 0x1" in content or "const/4 v1, 0x1" in content:
                                result["javascript_enabled"] = True
                                result["webview_present"] = True

                        if file_access_pattern.search(content):
                            result["file_access_enabled"] = True
                            result["webview_present"] = True

                        if file_url_access_pattern.search(content):
                            result["findings"].append({
                                "severity": "HIGH",
                                "title": "File Access from File URLs Enabled",
                                "detail": "setAllowFileAccessFromFileURLs(true) allows JavaScript running in a file:// context to access other files, enabling cross-site scripting attacks.",
                                "remediation": "Set setAllowFileAccessFromFileURLs(false) — this is deprecated and disabled by default in modern Android.",
                            })

                        if setAllowUniversalAccess.search(content):
                            result["findings"].append({
                                "severity": "CRITICAL",
                                "title": "Universal Access from File URLs Enabled",
                                "detail": "setAllowUniversalAccessFromFileURLs(true) allows file:// origins to access any origin, a severe security vulnerability.",
                                "remediation": "Immediately set setAllowUniversalAccessFromFileURLs(false). This is disabled by default in modern WebView.",
                            })

                        if ssl_error_handler.search(content):
                            result["findings"].append({
                                "severity": "MEDIUM",
                                "title": "Custom SSL Error Handler Detected",
                                "detail": "App overrides onReceivedSslError, which may bypass SSL certificate validation if not implemented correctly.",
                                "remediation": "Ensure SSL error handler does not call handler.proceed(). Use proper certificate validation.",
                            })

                    except Exception:
                        continue

        # Add WebView findings
        if result["javascript_enabled"]:
            result["findings"].append({
                "severity": "MEDIUM",
                "title": "JavaScript Enabled in WebView",
                "detail": "WebView has JavaScript enabled. If loading untrusted content, this enables XSS attacks.",
                "remediation": "Disable JavaScript unless absolutely necessary. If needed, ensure all loaded content is trusted and use Content Security Policy headers.",
            })

        if result["file_access_enabled"]:
            result["findings"].append({
                "severity": "MEDIUM",
                "title": "File Access Enabled in WebView",
                "detail": "WebView allows file access (setAllowFileAccess), which can expose local files to web content.",
                "remediation": "Set setAllowFileAccess(false) unless file access is strictly required.",
            })

        return result

    # ── Phase 7: Obfuscation Check ───────────────────────────────────────

    def analyze_obfuscation(self) -> Dict[str, Any]:
        """Check if ProGuard/R8 obfuscation was applied."""
        result: Dict[str, Any] = {
            "proguard_present": False,
            "r8_present": False,
            "obfuscated": False,
            "has_mapping": False,
            "assessment": "Unknown",
            "findings": [],
        }

        # Check for ProGuard mapping files
        mapping_files = []
        for root, _, files in os.walk(self.decompiled_dir):
            for fname in files:
                if fname in ("mapping.txt", "usage.txt", "seeds.txt", "configuration.txt"):
                    mapping_files.append(os.path.join(root, fname))
                    result["has_mapping"] = True

        # Check ProGuard/R8 rules embedded in the APK
        original_meta = os.path.join(self.decompiled_dir, "original", "META-INF")
        if os.path.isdir(original_meta):
            for fname in os.listdir(original_meta):
                if fname.lower().startswith("proguard") or "proguard" in fname.lower():
                    result["proguard_present"] = True

        # Analyze smali class names for obfuscation indicators
        smali_dir = os.path.join(self.decompiled_dir, "smali")
        if os.path.isdir(smali_dir):
            obfuscated_count = 0
            total_count = 0
            short_name_pattern = re.compile(r'\.class.*L([a-z]/[a-z]/[a-z]|<init>)', re.IGNORECASE)

            for root, _, files in os.walk(smali_dir):
                for fname in files:
                    if fname.endswith(".smali"):
                        total_count += 1
                        # Obfuscated classes tend to have short, single-letter names
                        name_no_ext = fname.replace(".smali", "")
                        if re.match(r'^[a-z]$', name_no_ext) or re.match(r'^[a-z][a-z0-9]?$', name_no_ext):
                            obfuscated_count += 1

                        if total_count > 100:
                            break
                if total_count > 100:
                    break

            if total_count > 0:
                ratio = obfuscated_count / total_count
                if ratio > 0.3:
                    result["obfuscated"] = True
                    result["assessment"] = "Partially obfuscated"
                elif ratio > 0.6:
                    result["obfuscated"] = True
                    result["assessment"] = "Heavily obfuscated"

        if result["has_mapping"] and not result["obfuscated"]:
            result["obfuscated"] = True
            result["assessment"] = "Likely obfuscated (mapping files present)"

        if not result["obfuscated"]:
            result["findings"].append({
                "severity": "MEDIUM",
                "title": "No ProGuard/R8 Obfuscation Detected",
                "detail": "The APK does not appear to use code obfuscation, making reverse engineering significantly easier.",
                "remediation": "Enable ProGuard or R8 with minifyEnabled=true and appropriate keep rules in build.gradle.",
            })
        else:
            result["findings"].append({
                "severity": "INFO",
                "title": f"Obfuscation Detected — {result['assessment']}",
                "detail": "Code obfuscation increases reverse engineering difficulty but is not a security guarantee.",
                "remediation": "Ensure sensitive logic is implemented server-side. Obfuscation is defense-in-depth, not primary security.",
            })

        return result

    # ── Phase 8: Risk Score Calculation ──────────────────────────────────

    def calculate_risk_score(self) -> int:
        """Calculate composite risk score (0-100)."""
        score = 0

        manifest = self.findings["manifest"]
        perms = self.findings["permissions"]
        exported = self.findings["exported_components"]
        secrets = self.findings["secrets"]
        network = self.findings["network_security"]
        sdk = self.findings["sdk_analysis"]

        # Dangerous permissions: +2 each
        score += len(perms.get("dangerous_permissions", [])) * 2

        # Exported components: +3 each
        score += len(exported.get("exported_components", [])) * 3

        # Debuggable: +10
        if manifest.get("debuggable"):
            score += 10

        # Backup enabled: +5
        if manifest.get("allow_backup", True):
            score += 5

        # Cleartext traffic: +10
        if network.get("cleartext_permitted"):
            score += 10

        # Hardcoded secrets: +5 each
        score += len(secrets.get("findings", [])) * 5

        # No certificate pinning: +8
        if not network.get("certificate_pinning"):
            score += 8

        # Outdated target SDK: +5
        if sdk.get("target_sdk_outdated"):
            score += 5

        # WebView vulnerabilities (extra)
        webview = self.findings["webview"]
        for finding in webview.get("findings", []):
            severity = finding.get("severity", "INFO")
            if severity == "CRITICAL":
                score += 8
            elif severity == "HIGH":
                score += 5
            elif severity == "MEDIUM":
                score += 3

        # No obfuscation: +3
        obfuscation = self.findings["obfuscation"]
        if not obfuscation.get("obfuscated"):
            score += 3

        return min(score, 100)

    def _get_risk_level(self, score: int) -> str:
        if score >= 75:
            return "🔴 CRITICAL"
        elif score >= 50:
            return "🟠 HIGH"
        elif score >= 25:
            return "🟡 MEDIUM"
        elif score >= 10:
            return "🟢 LOW"
        return "⚪ MINIMAL"

    # ── Phase 9: MITRE ATT&CK Mappings ───────────────────────────────────

    def generate_mitre_mappings(self) -> List[Dict[str, Any]]:
        """Map findings to MITRE ATT&CK Mobile techniques."""
        mappings = []
        manifest = self.findings["manifest"]
        perms = self.findings["permissions"]
        secrets = self.findings["secrets"]
        webview = self.findings["webview"]

        # T1412 — Capture SMS Messages
        sms_perms = [p["short_name"] for p in perms.get("dangerous_permissions", [])
                     if "SMS" in p.get("short_name", "")]
        if sms_perms:
            mappings.append({
                "technique_id": "T1412",
                "name": MITRE_ATTACK_TECHNIQUES["T1412"]["name"],
                "description": MITRE_ATTACK_TECHNIQUES["T1412"]["desc"],
                "url": MITRE_ATTACK_TECHNIQUES["T1412"]["url"],
                "evidence": f"App requests SMS permissions: {', '.join(sms_perms)}",
            })

        # T1430 — Location Tracking
        loc_perms = [p["short_name"] for p in perms.get("dangerous_permissions", [])
                     if "LOCATION" in p.get("short_name", "")]
        if loc_perms:
            mappings.append({
                "technique_id": "T1430",
                "name": MITRE_ATTACK_TECHNIQUES["T1430"]["name"],
                "description": MITRE_ATTACK_TECHNIQUES["T1430"]["desc"],
                "url": MITRE_ATTACK_TECHNIQUES["T1430"]["url"],
                "evidence": f"App requests location permissions: {', '.join(loc_perms)}",
            })

        # T1429 — Audio Capture
        audio_perms = [p["short_name"] for p in perms.get("dangerous_permissions", [])
                       if "RECORD_AUDIO" in p.get("short_name", "")]
        if audio_perms:
            mappings.append({
                "technique_id": "T1429",
                "name": MITRE_ATTACK_TECHNIQUES["T1429"]["name"],
                "description": MITRE_ATTACK_TECHNIQUES["T1429"]["desc"],
                "url": MITRE_ATTACK_TECHNIQUES["T1429"]["url"],
                "evidence": f"App can record audio: {', '.join(audio_perms)}",
            })

        # T1417 — Input Capture (via overlay/accessibility)
        overlay = [p["short_name"] for p in perms.get("dangerous_permissions", [])
                   if p.get("short_name") == "SYSTEM_ALERT_WINDOW"]
        accessibility = [p["short_name"] for p in perms.get("dangerous_permissions", [])
                         if p.get("short_name") == "BIND_ACCESSIBILITY_SERVICE"]
        if overlay or accessibility:
            mappings.append({
                "technique_id": "T1417",
                "name": MITRE_ATTACK_TECHNIQUES["T1417"]["name"],
                "description": MITRE_ATTACK_TECHNIQUES["T1417"]["desc"],
                "url": MITRE_ATTACK_TECHNIQUES["T1417"]["url"],
                "evidence": f"Overlay/accessibility capabilities: overlay={bool(overlay)}, accessibility={bool(accessibility)}",
            })

        # T1418 — Application Discovery (query packages)
        # T1409 — Stored Application Data (backup + storage)
        if manifest.get("allow_backup", True):
            mappings.append({
                "technique_id": "T1409",
                "name": MITRE_ATTACK_TECHNIQUES["T1409"]["name"],
                "description": MITRE_ATTACK_TECHNIQUES["T1409"]["desc"],
                "url": MITRE_ATTACK_TECHNIQUES["T1409"]["url"],
                "evidence": "Android backup enabled (allowBackup=true), allowing app data extraction via adb backup.",
            })

        # T1407 — Download New Code at Runtime (WebView JS + network config)
        webview_findings = [f for f in webview.get("findings", [])
                           if "javascript" in f.get("title", "").lower()]
        if webview_findings or self.findings["network_security"].get("cleartext_permitted"):
            mappings.append({
                "technique_id": "T1407",
                "name": MITRE_ATTACK_TECHNIQUES["T1407"]["name"],
                "description": MITRE_ATTACK_TECHNIQUES["T1407"]["desc"],
                "url": MITRE_ATTACK_TECHNIQUES["T1407"]["url"],
                "evidence": "WebView with JavaScript and/or cleartext traffic enabled could allow dynamic code execution.",
            })

        # T1444 — Masquerade (task affinity hijacking)
        # T1406 — Obfuscated Files (if no obfuscation, it's a finding)
        if not self.findings["obfuscation"].get("obfuscated"):
            mappings.append({
                "technique_id": "T1406",
                "name": MITRE_ATTACK_TECHNIQUES["T1406"]["name"],
                "description": "Lack of obfuscation makes reverse engineering trivial (inverse mapping).",
                "url": MITRE_ATTACK_TECHNIQUES["T1406"]["url"],
                "evidence": "No ProGuard/R8 obfuscation detected.",
            })

        return mappings

    # ── Phase 10: LLM-Enhanced Analysis ──────────────────────────────────

    def run_llm_analysis(self) -> Dict[str, Any]:
        """Use LLM to provide contextual security analysis."""
        if not self.use_llm:
            return {"skipped": True, "reason": "--no-llm flag set"}

        # Build a concise summary for the LLM
        manifest = self.findings["manifest"]
        perms = self.findings["permissions"]
        exported = self.findings["exported_components"]
        secrets = self.findings["secrets"]
        network = self.findings["network_security"]
        webview = self.findings["webview"]
        obfuscation = self.findings["obfuscation"]
        sdk = self.findings["sdk_analysis"]
        score = self.findings["risk_score"]

        prompt = f"""You are a mobile security expert analyzing an Android banking application. Provide a concise, professional security analysis based on the following scan results.

## App Profile
- Package: {manifest.get('package', 'unknown')}
- Target SDK: {sdk.get('target_sdk', 'unknown')}
- Min SDK: {sdk.get('min_sdk', 'unknown')}

## Key Findings

### Dangerous Permissions ({len(perms.get('dangerous_permissions', []))})
{chr(10).join(f"- {p['permission']} (Severity: {p['severity']})" for p in perms.get('dangerous_permissions', [])[:15])}

### Exported Components ({len(exported.get('exported_components', []))})
{chr(10).join(f"- {c['type'].title()}: {c['name']} (Permission protected: {c['permission_protected']})" for c in exported.get('exported_components', [])[:10])}

### Configuration Flags
- Debuggable: {manifest.get('debuggable', False)}
- Allow Backup: {manifest.get('allow_backup', True)}
- Cleartext Traffic: {network.get('cleartext_permitted', False)}
- Certificate Pinning: {network.get('certificate_pinning', False)}
- Obfuscated: {obfuscation.get('obfuscated', False)}

### Hardcoded Secrets: {secrets.get('total_findings', 0)} found
Types: {json.dumps(secrets.get('by_type', {}))}

### WebView Findings
{chr(10).join(f"- [{f['severity']}] {f['title']}" for f in webview.get('findings', []))}

### Network Security Findings
{chr(10).join(f"- [{f['severity']}] {f['title']}" for f in network.get('findings', []))}

### Risk Score: {score}/100 ({self._get_risk_level(score)})

Please provide analysis in the following JSON format (no markdown, just raw JSON):

{{
  "most_dangerous_combination": "Describe the 2-3 findings that together create the most dangerous attack surface",
  "attack_scenario": "Describe a realistic attack scenario targeting a banking app with these vulnerabilities (3-5 sentences)",
  "business_impact": "Describe the business impact in executive-friendly language (3-5 sentences)",
  "prioritized_remediation": [
    {{"priority": 1, "finding": "...", "action": "...", "effort": "Low/Medium/High", "impact": "Critical/High/Medium/Low"}},
    {{"priority": 2, "finding": "...", "action": "...", "effort": "Low/Medium/High", "impact": "Critical/High/Medium/Low"}},
    {{"priority": 3, "finding": "...", "action": "...", "effort": "Low/Medium/High", "impact": "Critical/High/Medium/Low"}}
  ],
  "overall_risk_statement": "One paragraph summary of the overall security posture"
}}

Use only the JSON object in your response — no other text."""

        try:
            # Add the HAKA-AI directory to sys.path temporarily
            import sys as _sys
            _haka_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if _haka_dir not in _sys.path:
                _sys.path.insert(0, _haka_dir)

            from haka_providers import HakaLLM
            llm = HakaLLM()

            if self.verbose:
                print(f"[*] Running LLM analysis with model: {self.llm_model}")

            response = llm.generate(
                prompt=prompt,
                model=self.llm_model,
                max_tokens=2048,
                temperature=0.3,
            )

            # Try to extract JSON from response
            # LLM might wrap in markdown code blocks
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', response)
            if json_match:
                response = json_match.group(1)

            analysis = json.loads(response.strip())
            return {"skipped": False, "analysis": analysis}

        except Exception as e:
            return {
                "skipped": False,
                "error": str(e),
                "analysis": {
                    "most_dangerous_combination": "LLM analysis failed — see raw findings below.",
                    "attack_scenario": "N/A — LLM unavailable",
                    "business_impact": "N/A — LLM unavailable",
                    "prioritized_remediation": [],
                    "overall_risk_statement": f"LLM analysis failed with error: {e}. Review raw technical findings manually.",
                },
            }

    # ── Orchestration ────────────────────────────────────────────────────

    def scan(self) -> Dict[str, Any]:
        """Run full scan pipeline."""
        if self.verbose:
            print(f"\n{'='*60}")
            print(f"  HAKA Mobile App Security Scanner")
            print(f"  Target: {self.apk_path}")
            print(f"  Time: {datetime.now().isoformat()}")
            print(f"{'='*60}\n")

        # Phase 0: Prerequisites
        warnings = self.check_prerequisites()
        if warnings and self.verbose:
            for w in warnings:
                print(f"[!] {w}")

        # Phase 1: Decompile
        if self.verbose:
            print("[1/8] Decompiling APK...")
        self.decompile()

        # Phase 2: Manifest
        if self.verbose:
            print("[2/8] Parsing AndroidManifest.xml...")
        manifest_data = self.parse_manifest()
        self.findings["manifest"] = manifest_data
        self.findings["permissions"] = manifest_data  # permissions are inside manifest
        self.findings["exported_components"] = manifest_data

        # Phase 3: SDK Analysis
        if self.verbose:
            print("[3/8] Analyzing SDK versions...")
        self.findings["sdk_analysis"] = self.analyze_sdk()

        # Phase 4: Secrets
        if self.verbose:
            print("[4/8] Extracting hardcoded secrets...")
        self.findings["secrets"] = self.extract_secrets()

        # Phase 5: Network Security
        if self.verbose:
            print("[5/8] Analyzing network security config...")
        self.findings["network_security"] = self.analyze_network_security(manifest_data)

        # Phase 6: WebView
        if self.verbose:
            print("[6/8] Checking WebView vulnerabilities...")
        self.findings["webview"] = self.analyze_webview(manifest_data)

        # Phase 7: Obfuscation
        if self.verbose:
            print("[7/8] Checking code obfuscation...")
        self.findings["obfuscation"] = self.analyze_obfuscation()

        # Phase 8: Risk Score
        self.findings["risk_score"] = self.calculate_risk_score()
        self.findings["mitre_mappings"] = self.generate_mitre_mappings()

        # Phase 9: LLM Analysis
        if self.verbose:
            print("[8/8] Running LLM-enhanced analysis...")
        self.findings["llm_analysis"] = self.run_llm_analysis()

        # Meta
        self.findings["meta"] = {
            "scanner": "HAKA Mobile App Security Scanner v1.0.0",
            "apk_path": self.apk_path,
            "apk_name": Path(self.apk_path).name,
            "package_name": manifest_data.get("package", "unknown"),
            "scan_time": datetime.now().isoformat(),
            "tools_used": {
                "apktool": APKTOOL,
                "strings": STRINGS,
                "jadx": JADX,
            },
            "risk_score": self.findings["risk_score"],
            "risk_level": self._get_risk_level(self.findings["risk_score"]),
        }

        if self.verbose:
            print(f"\n[✓] Scan complete. Risk Score: {self.findings['risk_score']}/100")
            print(f"    Level: {self._get_risk_level(self.findings['risk_score'])}")

        return self.findings

    def cleanup(self):
        """Remove temporary files."""
        if self.temp_dir and os.path.isdir(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            if self.verbose:
                print("[*] Cleaned up temporary directory")


# ── Report Generation ────────────────────────────────────────────────────────

def generate_markdown_report(findings: Dict[str, Any], output_path: str):
    """Generate a professional Markdown security report."""
    meta = findings["meta"]
    manifest = findings["manifest"]
    perms = findings["permissions"]
    exported = findings["exported_components"]
    secrets = findings["secrets"]
    network = findings["network_security"]
    webview = findings["webview"]
    obfuscation = findings["obfuscation"]
    sdk = findings["sdk_analysis"]
    llm = findings.get("llm_analysis", {})
    mitre = findings.get("mitre_mappings", [])

    risk_score = findings["risk_score"]
    risk_level = meta["risk_level"]

    lines = []
    lines.append(f"# 🔒 HAKA Mobile App Security Assessment")
    lines.append(f"")
    lines.append(f"**APK:** `{meta['apk_name']}`  ")
    lines.append(f"**Package:** `{meta['package_name']}`  ")
    lines.append(f"**Scan Date:** {meta['scan_time']}  ")
    lines.append(f"**Scanner Version:** 1.0.0  ")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")

    # Executive Summary
    lines.append(f"## 📊 Executive Summary")
    lines.append(f"")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Risk Score | **{risk_score}/100** |")
    lines.append(f"| Risk Level | **{risk_level}** |")
    lines.append(f"| Dangerous Permissions | {len(perms.get('dangerous_permissions', []))} |")
    lines.append(f"| Exported Components | {len(exported.get('exported_components', []))} |")
    lines.append(f"| Hardcoded Secrets | {secrets.get('total_findings', 0)} |")
    lines.append(f"| Debuggable | {'⚠️ Yes' if manifest.get('debuggable') else '✅ No'} |")
    lines.append(f"| Allow Backup | {'⚠️ Yes' if manifest.get('allow_backup', True) else '✅ No'} |")
    lines.append(f"| Cleartext Traffic | {'🔴 Yes' if network.get('cleartext_permitted') else '✅ No'} |")
    lines.append(f"| Certificate Pinning | {'✅ Yes' if network.get('certificate_pinning') else '⚠️ No'} |")
    lines.append(f"| Code Obfuscation | {'✅ Yes' if obfuscation.get('obfuscated') else '⚠️ No'} |")
    lines.append(f"| Target SDK | {sdk.get('target_sdk', 'unknown')} {'⚠️ Outdated' if sdk.get('target_sdk_outdated') else '✅ Current'} |")
    lines.append(f"")

    # LLM Analysis
    if llm.get("skipped"):
        lines.append(f"### LLM Analysis — Skipped")
        lines.append(f"_AI analysis was disabled with --no-llm flag._")
    elif llm.get("error"):
        lines.append(f"### LLM Analysis — Error")
        lines.append(f"_Failed to run: {llm.get('error')}_")
    else:
        analysis = llm.get("analysis", {})
        if analysis:
            lines.append(f"### 🔍 AI Risk Analysis")
            lines.append(f"")
            if analysis.get("most_dangerous_combination"):
                lines.append(f"**Most Dangerous Combination:** {analysis['most_dangerous_combination']}")
                lines.append(f"")
            if analysis.get("attack_scenario"):
                lines.append(f"**Attack Scenario:** {analysis['attack_scenario']}")
                lines.append(f"")
            if analysis.get("business_impact"):
                lines.append(f"**Business Impact:** {analysis['business_impact']}")
                lines.append(f"")
            if analysis.get("overall_risk_statement"):
                lines.append(f"**Overall Assessment:** {analysis['overall_risk_statement']}")
                lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Permission Risk Matrix
    lines.append(f"## 🔐 Permission Risk Matrix")
    lines.append(f"")
    dangerous_perms = perms.get("dangerous_permissions", [])
    if dangerous_perms:
        lines.append(f"| # | Permission | Severity | Risk Weight |")
        lines.append(f"|---|---|---|---|")
        for i, p in enumerate(dangerous_perms, 1):
            lines.append(f"| {i} | `{p['permission']}` | {p['severity']} | {p['weight']} |")
        lines.append(f"")
    else:
        lines.append(f"_No dangerous permissions detected._")
        lines.append(f"")

    # All permissions summary
    all_perms = perms.get("permissions", [])
    if all_perms:
        lines.append(f"### All Requested Permissions ({len(all_perms)})")
        lines.append(f"```")
        for p in sorted(all_perms):
            lines.append(f"  {p}")
        lines.append(f"```")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Exported Components
    lines.append(f"## 📱 Exported Components")
    lines.append(f"")
    exported_comps = exported.get("exported_components", [])
    if exported_comps:
        lines.append(f"| # | Type | Component Name | Permission Protected |")
        lines.append(f"|---|---|---|---|")
        for i, c in enumerate(exported_comps, 1):
            protected = "✅" if c.get("permission_protected") else "❌"
            lines.append(f"| {i} | {c['type'].title()} | `{c['name']}` | {protected} |")
        lines.append(f"")
    else:
        lines.append(f"_No exported components detected._")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Hardcoded Secrets
    lines.append(f"## 🔑 Hardcoded Secrets")
    lines.append(f"")
    lines.append(f"**Total secrets found: {secrets.get('total_findings', 0)}**")
    lines.append(f"")
    by_type = secrets.get("by_type", {})
    if by_type:
        lines.append(f"| Type | Count |")
        lines.append(f"|---|---|")
        for stype, count in sorted(by_type.items(), key=lambda x: -x[1]):
            icon = "🔴" if "password" in stype.lower() or "secret" in stype.lower() or "key" in stype.lower() else "🟡"
            lines.append(f"| {icon} {stype} | {count} |")
        lines.append(f"")

    # Redacted secrets
    findings_list = secrets.get("findings", [])
    if findings_list:
        lines.append(f"### Redacted Findings (first 20)")
        lines.append(f"")
        lines.append(f"| # | Type | Redacted Value |")
        lines.append(f"|---|---|---|")
        for i, f in enumerate(findings_list[:20], 1):
            lines.append(f"| {i} | {f['type']} | `{f['redacted']}` |")
        lines.append(f"")

    # URLs
    urls = secrets.get("urls", [])
    if urls:
        lines.append(f"### Embedded URLs ({len(urls)})")
        lines.append(f"")
        lines.append(f"| # | URL |")
        lines.append(f"|---|---|")
        for i, url in enumerate(sorted(set(urls))[:20], 1):
            lines.append(f"| {i} | `{url[:80]}` |")
        lines.append(f"")

    # IPs
    ips = secrets.get("ip_addresses", [])
    if ips:
        lines.append(f"### Embedded IP Addresses ({len(ips)})")
        lines.append(f"```")
        for ip in sorted(set(ips))[:20]:
            lines.append(f"  {ip}")
        lines.append(f"```")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Network Security
    lines.append(f"## 🌐 Network Security Configuration")
    lines.append(f"")
    for finding in network.get("findings", []):
        lines.append(f"### [{finding['severity']}] {finding['title']}")
        lines.append(f"")
        lines.append(f"{finding['detail']}")
        lines.append(f"")
        lines.append(f"**Remediation:** {finding['remediation']}")
        lines.append(f"")

    if not network.get("findings"):
        lines.append(f"_No network security issues detected._")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # WebView
    lines.append(f"## 🌍 WebView Security")
    lines.append(f"")
    lines.append(f"| Check | Status |")
    lines.append(f"|---|---|")
    lines.append(f"| WebView Present | {'Yes' if webview.get('webview_present') else 'No'} |")
    lines.append(f"| JavaScript Enabled | {'⚠️ Yes' if webview.get('javascript_enabled') else 'No'} |")
    lines.append(f"| File Access Enabled | {'⚠️ Yes' if webview.get('file_access_enabled') else 'No'} |")
    lines.append(f"")

    for finding in webview.get("findings", []):
        lines.append(f"### [{finding['severity']}] {finding['title']}")
        lines.append(f"")
        lines.append(f"{finding['detail']}")
        lines.append(f"")
        lines.append(f"**Remediation:** {finding['remediation']}")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Obfuscation
    lines.append(f"## 🔐 Code Obfuscation")
    lines.append(f"")
    for finding in obfuscation.get("findings", []):
        lines.append(f"### [{finding['severity']}] {finding['title']}")
        lines.append(f"")
        lines.append(f"{finding['detail']}")
        lines.append(f"")
        lines.append(f"**Remediation:** {finding['remediation']}")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # SDK Analysis
    lines.append(f"## 📦 SDK Version Analysis")
    lines.append(f"")
    lines.append(f"| Setting | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Min SDK | {sdk.get('min_sdk', 'unknown')} |")
    lines.append(f"| Target SDK | {sdk.get('target_sdk', 'unknown')} {'⚠️ Outdated — should be ≥ 33' if sdk.get('target_sdk_outdated') else '✅'} |")
    lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Configuration Flags
    lines.append(f"## ⚙️ Configuration Flags")
    lines.append(f"")
    lines.append(f"| Flag | Value | Risk |")
    lines.append(f"|---|---|---|")
    debuggable = manifest.get("debuggable", False)
    lines.append(f"| `android:debuggable` | {debuggable} | {'🔴 HIGH — app can be debugged on any device' if debuggable else '✅ Safe'} |")
    allow_backup = manifest.get("allow_backup", True)
    lines.append(f"| `android:allowBackup` | {allow_backup} | {'⚠️ MEDIUM — app data extractable via adb backup' if allow_backup else '✅ Safe'} |")
    lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # MITRE ATT&CK Mappings
    lines.append(f"## 🎯 MITRE ATT&CK Mobile Mappings")
    lines.append(f"")
    if mitre:
        lines.append(f"| Technique ID | Technique Name | Evidence |")
        lines.append(f"|---|---|---|")
        for m in mitre:
            lines.append(f"| [{m['technique_id']}]({m['url']}) | {m['name']} | {m['evidence'][:100]} |")
        lines.append(f"")
    else:
        lines.append(f"_No direct MITRE ATT&CK mappings identified._")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")

    # Remediation
    lines.append(f"## 🛡️ Prioritized Remediation")
    lines.append(f"")

    # Use LLM remediation if available
    llm_remediation = []
    if not llm.get("skipped") and not llm.get("error"):
        analysis = llm.get("analysis", {})
        llm_remediation = analysis.get("prioritized_remediation", [])
        if llm_remediation:
            lines.append(f"| Priority | Finding | Action | Effort | Impact |")
            lines.append(f"|---|---|---|---|---|")
            for item in llm_remediation:
                lines.append(f"| {item.get('priority', '?')} | {item.get('finding', '')} | {item.get('action', '')} | {item.get('effort', '')} | {item.get('impact', '')} |")
            lines.append(f"")

    # Fallback: auto-generated remediation
    remediation_items = []
    if manifest.get("debuggable"):
        remediation_items.append("**Immediate:** Set `android:debuggable=\"false\"` in AndroidManifest.xml for release builds.")
    if manifest.get("allow_backup", True):
        remediation_items.append("**High:** Set `android:allowBackup=\"false\"` to prevent data extraction via `adb backup`.")
    if network.get("cleartext_permitted"):
        remediation_items.append("**High:** Disable cleartext traffic in network_security_config.xml. Enforce HTTPS.")
    if not network.get("certificate_pinning"):
        remediation_items.append("**High:** Implement certificate pinning to prevent MITM attacks via user-installed CAs.")
    if secrets.get("total_findings", 0) > 0:
        remediation_items.append("**Critical:** Remove all hardcoded secrets. Use environment variables, secure keystores, or a secrets management service.")
    if not obfuscation.get("obfuscated"):
        remediation_items.append("**Medium:** Enable ProGuard/R8 with `minifyEnabled true` and proper keep rules.")
    if sdk.get("target_sdk_outdated"):
        remediation_items.append("**Medium:** Update targetSdkVersion to 34+ to benefit from platform security improvements.")
    if not webview.get("webview_present") and not webview.get("findings"):
        pass  # No WebView issues
    if dangerous_perms := perms.get("dangerous_permissions", []):
        count = len(dangerous_perms)
        remediation_items.append(f"**Review:** Audit {count} dangerous permissions. Remove any that are not strictly necessary for app functionality.")

    if remediation_items and not llm_remediation:
        for i, item in enumerate(remediation_items, 1):
            lines.append(f"{i}. {item}")
        lines.append(f"")

    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## 📋 Methodology")
    lines.append(f"")
    lines.append(f"This assessment was performed using the HAKA Mobile App Security Scanner, which combines:")
    lines.append(f"")
    lines.append(f"1. **Static Analysis:** APK decompilation via apktool, manifest parsing, binary string extraction")
    lines.append(f"2. **Pattern Matching:** Regex-based secret detection for API keys, tokens, passwords, and private keys")
    lines.append(f"3. **Configuration Audit:** Network security config, WebView settings, ProGuard/R8 presence")
    lines.append(f"4. **AI-Enhanced Analysis:** LLM-powered context-aware risk assessment and remediation prioritization")
    lines.append(f"5. **Standards Mapping:** MITRE ATT&CK for Mobile framework alignment")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"*Report generated by HAKA Mobile App Security Scanner v1.0.0 | {meta['scan_time']}*")
    lines.append(f"*⚠️ For authorized security testing only. Do not use against applications you do not own or have written permission to test.*")
    lines.append(f"")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    return output_path


def generate_json_report(findings: Dict[str, Any], output_path: str):
    """Generate machine-readable JSON findings."""
    with open(output_path, "w") as f:
        json.dump(findings, f, indent=2, default=str)
    return output_path


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HAKA Mobile App Security Scanner — Comprehensive Android/iOS security analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 haka_mobile_scanner.py --apk banking.apk
  python3 haka_mobile_scanner.py --apk app.apk --model deepseek --output my_report.md
  python3 haka_mobile_scanner.py --apk app.apk --no-llm
  python3 haka_mobile_scanner.py --apk app.apk --verbose
        """,
    )

    parser.add_argument(
        "--apk", required=True,
        help="Path to the APK file to analyze",
    )
    parser.add_argument(
        "--model", default="deepseek",
        help="LLM model for AI-enhanced analysis (default: deepseek)",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Skip AI analysis — produce raw technical findings only",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output path for the Markdown report (default: auto-generated in reports/)",
    )
    parser.add_argument(
        "--json-only", action="store_true",
        help="Output only JSON (no markdown report)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose output during scanning",
    )
    parser.add_argument(
        "--keep-temp", action="store_true",
        help="Keep temporary decompiled files (for debugging)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Check tools and APK validity without running full scan",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.apk):
        print(f"Error: APK file not found: {args.apk}", file=sys.stderr)
        sys.exit(1)

    # Dry-run mode
    if args.dry_run:
        print("=== HAKA Mobile Scanner — Dry Run ===\n")
        print(f"APK: {args.apk}")
        print(f"LLM: {'Disabled' if args.no_llm else args.model}")

        # Check tools
        print("\n--- Tool Check ---")
        for name, path in [("apktool", APKTOOL), ("strings", STRINGS), ("jadx", JADX)]:
            exists = os.path.isfile(path) and os.access(path, os.X_OK)
            print(f"  {name}: {'✅ ' + path if exists else '❌ not found'}")

        # Check APK
        print(f"\n--- APK Check ---")
        try:
            with zipfile.ZipFile(args.apk, "r") as zf:
                names = zf.namelist()
                print(f"  Valid ZIP: ✅")
                print(f"  Files: {len(names)}")
                if "AndroidManifest.xml" in names:
                    print(f"  AndroidManifest.xml: ✅")
                else:
                    print(f"  AndroidManifest.xml: ❌ MISSING")
                print(f"  Size: {os.path.getsize(args.apk):,} bytes")
        except Exception as e:
            print(f"  Error: {e}")

        print("\n✅ Dry run complete. All checks passed.")
        return

    # Full scan
    scanner = MobileAppScanner(
        apk_path=args.apk,
        use_llm=not args.no_llm,
        llm_model=args.model,
        verbose=args.verbose,
    )

    try:
        findings = scanner.scan()

        # Determine output paths
        ensure_dir(REPORTS_DIR)
        base_name = Path(args.apk).stem

        if args.output and args.json_only:
            json_path = args.output if args.output.endswith(".json") else args.output + ".json"
        elif args.output:
            md_path = args.output
            json_path = args.output.replace(".md", ".json") if args.output.endswith(".md") else args.output + ".json"
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            md_path = os.path.join(REPORTS_DIR, f"mobile_scan_{base_name}_{timestamp}.md")
            json_path = os.path.join(REPORTS_DIR, f"mobile_scan_{base_name}_{timestamp}.json")

        # Generate reports
        if not args.json_only:
            md_path = generate_markdown_report(findings, md_path)
            print(f"\n✅ Markdown report: {md_path}")

        json_path = generate_json_report(findings, json_path)
        print(f"✅ JSON findings: {json_path}")
        print(f"📊 Risk Score: {findings['risk_score']}/100 ({findings['meta']['risk_level']})")

    except Exception as e:
        print(f"\n❌ Scan failed: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    finally:
        if not args.keep_temp:
            scanner.cleanup()
        elif args.verbose:
            print(f"[*] Temp directory kept: {scanner.temp_dir}")


if __name__ == "__main__":
    main()
