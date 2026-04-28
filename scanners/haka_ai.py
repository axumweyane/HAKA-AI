#!/usr/bin/env python3
"""
HAKA AI - Unified Security Assessment Framework (Master Orchestrator)
=====================================================================
Runs ALL HAKA AI scanner modules against a target, aggregates findings
into a unified risk score, and generates executive-level reports with
MITRE ATT&CK mappings, attack chain analysis, and Wazuh detection rules.

Author : HAKA AI Framework / Kironix
Version: 1.0.0
"""

import argparse
import importlib
import json
import logging
import os
import re
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional dependency soft-imports
# ---------------------------------------------------------------------------

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _Stub:
        def __getattr__(self, _: str) -> str:
            return ""
    Fore = Style = _Stub()  # type: ignore[assignment]

try:
    import yaml  # PyYAML
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
SCANNERS_DIR = Path(__file__).resolve().parent
DETECTORS_DIR = SCANNERS_DIR.parent / "detectors"
DEFAULT_REPORTS_DIR = SCANNERS_DIR.parent / "reports"

BANNER = rf"""
{Fore.CYAN}{Style.BRIGHT} ██╗  ██╗ █████╗ ██╗  ██╗ █████╗      █████╗ ██╗
 ██║  ██║██╔══██╗██║ ██╔╝██╔══██╗    ██╔══██╗██║
 ████████║███████║█████╔╝ ███████║    ███████║██║
 ██╔══██║██╔══██║██╔═██╗ ██╔══██║    ██╔══██║██║
 ██║  ██║██║  ██║██║  ██╗██║  ██║    ██║  ██║██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝{Style.RESET_ALL}
{Fore.YELLOW} HAKA AI v{VERSION} — AI-Powered Security Assessment Framework{Style.RESET_ALL}
{Fore.WHITE} By: Kironix | github.com/axumweyane{Style.RESET_ALL}
"""

# ---------------------------------------------------------------------------
# Scanner module registry
# ---------------------------------------------------------------------------

# Each entry: key  -> (python_module, callable, cli_script, description)
# callable is the function/method to invoke via import; cli_script is the
# fallback command when the import path is unavailable.

SCANNER_REGISTRY: Dict[str, Dict[str, Any]] = {
    "email": {
        "module": "haka_email_scanner",
        "description": "Email Security (DMARC/DKIM/SPF)",
        "mitre_ids": ["T1566", "T1586.002"],
        "invoke": "_run_email_scanner",
    },
    "dns": {
        "module": "haka_dns_scanner",
        "description": "DNS Reconnaissance",
        "mitre_ids": ["T1590.002"],
        "invoke": "_run_dns_scanner",
    },
    "exchange": {
        "module": "haka_exchange_scanner",
        "description": "Exchange / NTLM Scanning",
        "mitre_ids": ["T1589.002", "T1110"],
        "invoke": "_run_exchange_scanner",
    },
    "web": {
        "module": "haka_web_scanner",
        "description": "Web Application Scanning",
        "mitre_ids": ["T1190", "T1595.002"],
        "invoke": "_run_web_scanner",
    },
    "tls": {
        "module": "haka_tls_scanner",
        "description": "TLS/SSL Analysis",
        "mitre_ids": ["T1557", "T1040"],
        "invoke": "_run_tls_scanner",
    },
    "s3": {
        "module": "haka_s3_scanner",
        "description": "S3 Bucket Scanning",
        "mitre_ids": ["T1530"],
        "invoke": "_run_s3_scanner",
    },
    "ct": {
        "module": "haka_ct_scanner",
        "description": "Certificate Transparency OSINT",
        "mitre_ids": ["T1596.003"],
        "invoke": "_run_ct_scanner",
    },
    "vpn": {
        "module": "haka_vpn_scanner",
        "description": "VPN Gateway Scanning",
        "mitre_ids": ["T1133"],
        "invoke": "_run_vpn_scanner",
    },
    "collab": {
        "module": "haka_collab_scanner",
        "description": "Collaboration Platform Scanning",
        "mitre_ids": ["T1199", "T1078"],
        "invoke": "_run_collab_scanner",
    },
}

ALL_MODULE_KEYS = list(SCANNER_REGISTRY.keys())

# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping table (technique -> name + tactic)
# ---------------------------------------------------------------------------

MITRE_MAPPING: Dict[str, Dict[str, str]] = {
    "T1566":     {"name": "Phishing", "tactic": "Initial Access"},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "T1566.002": {"name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
    "T1586.002": {"name": "Compromise Accounts: Email Accounts", "tactic": "Resource Development"},
    "T1590.002": {"name": "Gather Victim Network Info: DNS", "tactic": "Reconnaissance"},
    "T1589.002": {"name": "Gather Victim Identity Info: Email Addresses", "tactic": "Reconnaissance"},
    "T1110":     {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.003": {"name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "T1190":     {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1595.002": {"name": "Active Scanning: Vulnerability Scanning", "tactic": "Reconnaissance"},
    "T1557":     {"name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "T1040":     {"name": "Network Sniffing", "tactic": "Credential Access"},
    "T1530":     {"name": "Data from Cloud Storage", "tactic": "Collection"},
    "T1596.003": {"name": "Search Open Technical Databases: Digital Certificates", "tactic": "Reconnaissance"},
    "T1133":     {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1199":     {"name": "Trusted Relationship", "tactic": "Initial Access"},
    "T1078":     {"name": "Valid Accounts", "tactic": "Defense Evasion"},
    "T1114":     {"name": "Email Collection", "tactic": "Collection"},
    "T1071":     {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1592":     {"name": "Gather Victim Host Info", "tactic": "Reconnaissance"},
    "T1596":     {"name": "Search Open Technical Databases", "tactic": "Reconnaissance"},
    "T1583":     {"name": "Acquire Infrastructure", "tactic": "Resource Development"},
    "T1598":     {"name": "Phishing for Information", "tactic": "Reconnaissance"},
    "T1499":     {"name": "Endpoint Denial of Service", "tactic": "Impact"},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1059":     {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1021":     {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1018":     {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1046":     {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1082":     {"name": "System Information Discovery", "tactic": "Discovery"},
}

# Severity weights for unified risk score
SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.5,
    "INFO": 0.0,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def setup_logging(log_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure file + console logging and return the root logger."""
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"haka_ai_{ts}.log"

    logger = logging.getLogger("haka_ai")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    fh = logging.FileHandler(str(log_file), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.DEBUG if verbose else logging.WARNING)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(ch)

    logger.info("HAKA AI v%s started — log file: %s", VERSION, log_file)
    return logger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.BLUE,
        "INFO": Fore.CYAN,
    }.get(severity.upper(), Fore.WHITE)


def _tag(severity: str, message: str) -> str:
    color = _severity_color(severity)
    return f"  {color}[{severity.upper()}]{Style.RESET_ALL} {message}"


def _section_header(title: str) -> None:
    width = 72
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}{Style.RESET_ALL}")


def _import_scanner(module_name: str) -> Any:
    """Try to import a scanner module from the scanners directory."""
    # Ensure scanners dir is on sys.path
    scanners_str = str(SCANNERS_DIR)
    if scanners_str not in sys.path:
        sys.path.insert(0, scanners_str)
    return importlib.import_module(module_name)


def _subprocess_scanner(module_name: str, target: str, extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Fallback: run a scanner as a subprocess and capture JSON output."""
    script = SCANNERS_DIR / f"{module_name}.py"
    if not script.exists():
        return {
            "error": f"Scanner script not found: {script}",
            "findings": [],
            "risk_score": 0,
        }

    cmd = [sys.executable, str(script), "--target", target, "--json"]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, cwd=str(SCANNERS_DIR)
        )
        # Try to extract JSON from stdout (scanner may print non-JSON too)
        stdout = result.stdout.strip()
        # Find the last JSON object in output
        json_match = None
        brace_depth = 0
        json_start = -1
        for i, ch in enumerate(stdout):
            if ch == "{":
                if brace_depth == 0:
                    json_start = i
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
                if brace_depth == 0 and json_start >= 0:
                    json_match = stdout[json_start : i + 1]
        if json_match:
            return json.loads(json_match)
        return {
            "raw_output": stdout,
            "findings": [],
            "risk_score": 0,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Scanner timed out after 300s", "findings": [], "risk_score": 0}
    except Exception as exc:
        return {"error": str(exc), "findings": [], "risk_score": 0}


# ---------------------------------------------------------------------------
# Individual scanner runner functions
# ---------------------------------------------------------------------------
# Each function tries a direct Python import first, then falls back to
# subprocess invocation.  Returns a standardised dict with at least
# {"findings": [...], "risk_score": float, "module": str}.

def _normalise_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Ensure every finding has consistent keys."""
    normalised = []
    for f in findings:
        nf = {
            "severity": f.get("severity", "INFO").upper(),
            "title": f.get("title") or f.get("message") or f.get("finding", "Unnamed finding"),
            "description": f.get("description", ""),
            "mitre_attack": f.get("mitre_attack") or f.get("mitre_technique", ""),
            "module": f.get("module", ""),
            "remediation": f.get("remediation", ""),
        }
        normalised.append(nf)
    return normalised


def _run_email_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """Email Security Scanner (DMARC/DKIM/SPF)."""
    module_name = "haka_email_scanner"
    try:
        mod = _import_scanner(module_name)
        result = mod.scan_domain(target, smtp_check=kwargs.get("smtp_check", False))
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "email"
        return {
            "module": "email",
            "description": SCANNER_REGISTRY["email"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "email"
    return {
        "module": "email",
        "description": SCANNER_REGISTRY["email"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_dns_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """DNS Reconnaissance Scanner."""
    module_name = "haka_dns_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        elif hasattr(mod, "DNSScanner"):
            scanner = mod.DNSScanner(target, **kwargs)
            result = scanner.run_scan() if hasattr(scanner, "run_scan") else scanner.scan()
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "dns"
        return {
            "module": "dns",
            "description": SCANNER_REGISTRY["dns"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "dns"
    return {
        "module": "dns",
        "description": SCANNER_REGISTRY["dns"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_exchange_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """Exchange / NTLM Scanner."""
    module_name = "haka_exchange_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        elif hasattr(mod, "ExchangeScanner"):
            scanner = mod.ExchangeScanner(target, **kwargs)
            result = scanner.run_scan() if hasattr(scanner, "run_scan") else scanner.scan()
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "exchange"
        return {
            "module": "exchange",
            "description": SCANNER_REGISTRY["exchange"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "exchange"
    return {
        "module": "exchange",
        "description": SCANNER_REGISTRY["exchange"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_web_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """Web Application Scanner."""
    module_name = "haka_web_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        elif hasattr(mod, "WebScanner"):
            scanner = mod.WebScanner(target, **kwargs)
            result = scanner.run_scan() if hasattr(scanner, "run_scan") else scanner.scan()
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "web"
        return {
            "module": "web",
            "description": SCANNER_REGISTRY["web"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "web"
    return {
        "module": "web",
        "description": SCANNER_REGISTRY["web"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_tls_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """TLS / SSL Analysis Scanner."""
    module_name = "haka_tls_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        elif hasattr(mod, "TLSScanner"):
            scanner = mod.TLSScanner(target, **kwargs)
            result = scanner.run_scan() if hasattr(scanner, "run_scan") else scanner.scan()
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "tls"
        return {
            "module": "tls",
            "description": SCANNER_REGISTRY["tls"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "tls"
    return {
        "module": "tls",
        "description": SCANNER_REGISTRY["tls"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_s3_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """S3 Bucket Scanner."""
    module_name = "haka_s3_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        elif hasattr(mod, "S3Scanner"):
            scanner = mod.S3Scanner(target, **kwargs)
            result = scanner.run_scan() if hasattr(scanner, "run_scan") else scanner.scan()
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "s3"
        return {
            "module": "s3",
            "description": SCANNER_REGISTRY["s3"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "s3"
    return {
        "module": "s3",
        "description": SCANNER_REGISTRY["s3"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_ct_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """Certificate Transparency OSINT Scanner."""
    module_name = "haka_ct_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "CTScanner"):
            scanner = mod.CTScanner(target)
            result = scanner.run_scan()
        elif hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "ct"
        return {
            "module": "ct",
            "description": SCANNER_REGISTRY["ct"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "ct"
    return {
        "module": "ct",
        "description": SCANNER_REGISTRY["ct"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_vpn_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """VPN Gateway Scanner."""
    module_name = "haka_vpn_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        elif hasattr(mod, "VPNScanner"):
            scanner = mod.VPNScanner(target, **kwargs)
            result = scanner.run_scan() if hasattr(scanner, "run_scan") else scanner.scan()
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "vpn"
        return {
            "module": "vpn",
            "description": SCANNER_REGISTRY["vpn"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "vpn"
    return {
        "module": "vpn",
        "description": SCANNER_REGISTRY["vpn"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


def _run_collab_scanner(target: str, logger: logging.Logger, **kwargs: Any) -> Dict[str, Any]:
    """Collaboration Platform Scanner."""
    module_name = "haka_collab_scanner"
    try:
        mod = _import_scanner(module_name)
        if hasattr(mod, "scan_domain"):
            result = mod.scan_domain(target)
        elif hasattr(mod, "CollabScanner"):
            scanner = mod.CollabScanner(target, **kwargs)
            result = scanner.run_scan() if hasattr(scanner, "run_scan") else scanner.scan()
        else:
            result = _subprocess_scanner(module_name, target)
        findings = _normalise_findings(result.get("findings", []))
        for f in findings:
            f["module"] = "collab"
        return {
            "module": "collab",
            "description": SCANNER_REGISTRY["collab"]["description"],
            "raw": result,
            "findings": findings,
            "risk_score": float(result.get("risk_score", 0)),
        }
    except ImportError:
        logger.warning("Cannot import %s — falling back to subprocess", module_name)
    except Exception as exc:
        logger.error("Import-based run of %s failed: %s", module_name, exc)

    result = _subprocess_scanner(module_name, target)
    findings = _normalise_findings(result.get("findings", []))
    for f in findings:
        f["module"] = "collab"
    return {
        "module": "collab",
        "description": SCANNER_REGISTRY["collab"]["description"],
        "raw": result,
        "findings": findings,
        "risk_score": float(result.get("risk_score", 0)),
    }


# Lookup table: module key -> runner function
_RUNNER_MAP = {
    "email": _run_email_scanner,
    "dns": _run_dns_scanner,
    "exchange": _run_exchange_scanner,
    "web": _run_web_scanner,
    "tls": _run_tls_scanner,
    "s3": _run_s3_scanner,
    "ct": _run_ct_scanner,
    "vpn": _run_vpn_scanner,
    "collab": _run_collab_scanner,
}


# ---------------------------------------------------------------------------
# Risk score aggregation
# ---------------------------------------------------------------------------


def compute_unified_risk_score(all_findings: List[Dict[str, Any]]) -> Tuple[float, str]:
    """
    Compute a 0-100 unified risk score from all findings.

    Scoring methodology:
      - Sum weighted severity points (capped contributions per severity)
      - Normalize to 0-100 scale
      - Critical findings are weighted heavily to ensure any critical
        finding pushes the score above 70.
    """
    if not all_findings:
        return 0.0, "Secure"

    counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1

    # Weighted score with diminishing returns per category
    raw = 0.0
    raw += min(counts["CRITICAL"] * 15.0, 60.0)   # up to 60 from criticals
    raw += min(counts["HIGH"] * 8.0, 30.0)         # up to 30 from highs
    raw += min(counts["MEDIUM"] * 3.0, 15.0)       # up to 15 from mediums
    raw += min(counts["LOW"] * 1.0, 5.0)           # up to 5 from lows
    # INFO contributes nothing

    # If any critical exists, floor is 70
    if counts["CRITICAL"] > 0:
        raw = max(raw, 70.0)
    elif counts["HIGH"] > 0:
        raw = max(raw, 40.0)
    elif counts["MEDIUM"] > 0:
        raw = max(raw, 15.0)

    score = min(raw, 100.0)

    if score >= 80:
        label = "Critical Risk"
    elif score >= 60:
        label = "High Risk"
    elif score >= 40:
        label = "Medium Risk"
    elif score >= 20:
        label = "Low Risk"
    else:
        label = "Secure"

    return round(score, 1), label


# ---------------------------------------------------------------------------
# Executive summary generation
# ---------------------------------------------------------------------------


def generate_executive_summary(
    target: str,
    score: float,
    label: str,
    all_findings: List[Dict[str, Any]],
    module_results: Dict[str, Dict[str, Any]],
) -> str:
    """Generate a 3-5 sentence executive summary."""
    counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for f in all_findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1

    total = len(all_findings)
    modules_run = len(module_results)
    failed_modules = [k for k, v in module_results.items() if v.get("raw", {}).get("error")]

    lines = []
    lines.append(
        f"A comprehensive security assessment of {target} was conducted using "
        f"{modules_run} scanning modules, identifying {total} total finding(s)."
    )

    if counts["CRITICAL"] > 0:
        lines.append(
            f"The assessment revealed {counts['CRITICAL']} CRITICAL and "
            f"{counts['HIGH']} HIGH severity issue(s) that require immediate attention."
        )
    elif counts["HIGH"] > 0:
        lines.append(
            f"The assessment identified {counts['HIGH']} HIGH severity issue(s) "
            f"alongside {counts['MEDIUM']} MEDIUM findings requiring timely remediation."
        )
    else:
        lines.append(
            f"No critical or high severity findings were detected; however, "
            f"{counts['MEDIUM']} medium and {counts['LOW']} low severity items "
            f"should be reviewed."
        )

    lines.append(
        f"The overall risk score is {score}/100 ({label}), reflecting the "
        f"combined exposure across email security, network services, web "
        f"applications, and infrastructure configurations."
    )

    if failed_modules:
        lines.append(
            f"Note: {len(failed_modules)} module(s) encountered errors and "
            f"produced incomplete results ({', '.join(failed_modules)}). "
            f"Re-scanning these modules is recommended."
        )

    # Attack surface summary
    surface_areas = []
    if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
        for f in all_findings:
            if f["severity"] in ("CRITICAL", "HIGH") and f.get("module"):
                desc = SCANNER_REGISTRY.get(f["module"], {}).get("description", f["module"])
                if desc not in surface_areas:
                    surface_areas.append(desc)
        if surface_areas:
            lines.append(
                f"Primary attack surface areas include: {', '.join(surface_areas[:4])}."
            )

    return " ".join(lines)


# ---------------------------------------------------------------------------
# Attack chain analysis
# ---------------------------------------------------------------------------


def analyze_attack_chains(all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify the most likely attack paths based on combined findings.
    Returns a list of attack chain objects.
    """
    chains: List[Dict[str, Any]] = []

    # Collect MITRE IDs present
    mitre_ids = set()
    modules_with_findings: Dict[str, List[str]] = {}
    for f in all_findings:
        mid = f.get("mitre_attack", "")
        if mid:
            mitre_ids.add(mid)
        mod = f.get("module", "unknown")
        if mod not in modules_with_findings:
            modules_with_findings[mod] = []
        modules_with_findings[mod].append(f["severity"])

    # Chain 1: Email -> Credential Harvest -> Lateral Movement
    email_vuln = "email" in modules_with_findings and any(
        s in ("CRITICAL", "HIGH") for s in modules_with_findings.get("email", [])
    )
    exchange_vuln = "exchange" in modules_with_findings and any(
        s in ("CRITICAL", "HIGH") for s in modules_with_findings.get("exchange", [])
    )
    if email_vuln:
        chain = {
            "name": "Email Spoofing to Credential Harvest",
            "likelihood": "HIGH" if exchange_vuln else "MEDIUM",
            "steps": [
                {"phase": "Reconnaissance", "technique": "T1598", "action": "Enumerate email security posture (SPF/DMARC/DKIM gaps)"},
                {"phase": "Initial Access", "technique": "T1566", "action": "Send spoofed phishing email exploiting missing controls"},
                {"phase": "Credential Access", "technique": "T1110", "action": "Harvest credentials via phishing landing page"},
            ],
            "impact": "Full mailbox compromise, potential lateral movement via harvested credentials",
        }
        if exchange_vuln:
            chain["steps"].append(
                {"phase": "Lateral Movement", "technique": "T1021", "action": "Use NTLM relay or harvested creds to access Exchange/AD"}
            )
        chains.append(chain)

    # Chain 2: Web App -> Server Compromise
    web_vuln = "web" in modules_with_findings and any(
        s in ("CRITICAL", "HIGH") for s in modules_with_findings.get("web", [])
    )
    if web_vuln:
        chains.append({
            "name": "Web Application Exploitation",
            "likelihood": "HIGH",
            "steps": [
                {"phase": "Reconnaissance", "technique": "T1595.002", "action": "Identify web application vulnerabilities"},
                {"phase": "Initial Access", "technique": "T1190", "action": "Exploit public-facing web application"},
                {"phase": "Execution", "technique": "T1059", "action": "Execute commands on compromised web server"},
                {"phase": "Collection", "technique": "T1530", "action": "Access sensitive data from application or connected storage"},
            ],
            "impact": "Web server compromise, data exfiltration, pivot to internal network",
        })

    # Chain 3: TLS Downgrade -> MITM
    tls_vuln = "tls" in modules_with_findings and any(
        s in ("CRITICAL", "HIGH") for s in modules_with_findings.get("tls", [])
    )
    if tls_vuln:
        chains.append({
            "name": "TLS Downgrade to Man-in-the-Middle",
            "likelihood": "MEDIUM",
            "steps": [
                {"phase": "Reconnaissance", "technique": "T1046", "action": "Identify weak TLS configurations and deprecated protocols"},
                {"phase": "Credential Access", "technique": "T1557", "action": "Perform protocol downgrade and intercept traffic"},
                {"phase": "Collection", "technique": "T1040", "action": "Capture credentials and sensitive data in transit"},
            ],
            "impact": "Session hijacking, credential theft, data interception",
        })

    # Chain 4: VPN + Exposed Services -> Internal Access
    vpn_vuln = "vpn" in modules_with_findings and any(
        s in ("CRITICAL", "HIGH") for s in modules_with_findings.get("vpn", [])
    )
    if vpn_vuln:
        chains.append({
            "name": "VPN Gateway Exploitation to Internal Network",
            "likelihood": "HIGH",
            "steps": [
                {"phase": "Reconnaissance", "technique": "T1046", "action": "Identify VPN gateway type and version"},
                {"phase": "Initial Access", "technique": "T1133", "action": "Exploit VPN vulnerability or use credential stuffing"},
                {"phase": "Discovery", "technique": "T1018", "action": "Enumerate internal network from VPN foothold"},
                {"phase": "Lateral Movement", "technique": "T1021", "action": "Move laterally using VPN-granted network access"},
            ],
            "impact": "Full internal network access, bypass perimeter controls",
        })

    # Chain 5: CT OSINT -> Shadow IT Discovery -> Exploitation
    ct_vuln = "ct" in modules_with_findings and any(
        s in ("CRITICAL", "HIGH") for s in modules_with_findings.get("ct", [])
    )
    if ct_vuln:
        chains.append({
            "name": "Certificate Transparency OSINT to Shadow IT Exploitation",
            "likelihood": "MEDIUM",
            "steps": [
                {"phase": "Reconnaissance", "technique": "T1596.003", "action": "Mine CT logs for hidden subdomains and internal hostnames"},
                {"phase": "Reconnaissance", "technique": "T1592", "action": "Fingerprint discovered services and identify unpatched systems"},
                {"phase": "Initial Access", "technique": "T1190", "action": "Exploit unmonitored shadow IT service"},
            ],
            "impact": "Compromise of unmonitored services, potential internal pivot",
        })

    # Chain 6: S3 Data Exposure
    s3_vuln = "s3" in modules_with_findings and any(
        s in ("CRITICAL", "HIGH") for s in modules_with_findings.get("s3", [])
    )
    if s3_vuln:
        chains.append({
            "name": "Cloud Storage Data Exfiltration",
            "likelihood": "HIGH",
            "steps": [
                {"phase": "Reconnaissance", "technique": "T1596", "action": "Discover open S3 buckets via enumeration"},
                {"phase": "Collection", "technique": "T1530", "action": "Access and download data from misconfigured buckets"},
                {"phase": "Exfiltration", "technique": "T1048", "action": "Exfiltrate sensitive data from cloud storage"},
            ],
            "impact": "Mass data exposure, regulatory compliance violations",
        })

    # Default chain if no specific ones matched
    if not chains and all_findings:
        chains.append({
            "name": "General Reconnaissance and Exploitation",
            "likelihood": "LOW",
            "steps": [
                {"phase": "Reconnaissance", "technique": "T1590.002", "action": "Gather target network and service information"},
                {"phase": "Reconnaissance", "technique": "T1592", "action": "Identify potential entry points from scan results"},
            ],
            "impact": "Information disclosure facilitating further targeted attacks",
        })

    return chains


# ---------------------------------------------------------------------------
# Wazuh rule generation
# ---------------------------------------------------------------------------


def generate_wazuh_rules(all_findings: List[Dict[str, Any]], target: str) -> List[Dict[str, str]]:
    """Generate Wazuh detection rules for discovered findings."""
    rules = []
    rule_id_base = 100500
    seen_patterns: set = set()

    for idx, f in enumerate(all_findings):
        sev = f.get("severity", "INFO").upper()
        if sev == "INFO":
            continue

        mitre_id = f.get("mitre_attack", "")
        module = f.get("module", "unknown")
        title = f.get("title", "Unknown Finding")

        # Avoid duplicate rule patterns
        pattern_key = f"{module}:{mitre_id}:{sev}"
        if pattern_key in seen_patterns:
            continue
        seen_patterns.add(pattern_key)

        rule_id = rule_id_base + len(rules)
        wazuh_level = {"CRITICAL": 15, "HIGH": 12, "MEDIUM": 7, "LOW": 3}.get(sev, 3)

        mitre_name = MITRE_MAPPING.get(mitre_id, {}).get("name", mitre_id)
        mitre_tactic = MITRE_MAPPING.get(mitre_id, {}).get("tactic", "")

        rule_xml = textwrap.dedent(f"""\
            <rule id="{rule_id}" level="{wazuh_level}">
              <if_sid>530</if_sid>
              <field name="srcip">{target}</field>
              <description>HAKA AI [{module.upper()}] {title}</description>
              <mitre>
                <id>{mitre_id}</id>
              </mitre>
              <group>haka_ai,{module}_scan,</group>
            </rule>""")

        rules.append({
            "rule_id": str(rule_id),
            "level": str(wazuh_level),
            "module": module,
            "mitre_id": mitre_id,
            "mitre_name": mitre_name,
            "mitre_tactic": mitre_tactic,
            "description": f"HAKA AI [{module.upper()}] {title}",
            "xml": rule_xml,
        })

    return rules


# ---------------------------------------------------------------------------
# Remediation priority list
# ---------------------------------------------------------------------------


def build_remediation_list(all_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build a prioritised remediation list from findings."""
    # Deduplicate and sort by severity
    seen = set()
    items: List[Dict[str, Any]] = []
    priority = 1

    for sev in SEVERITY_ORDER:
        for f in all_findings:
            if f["severity"] != sev:
                continue
            key = (f.get("module", ""), f.get("title", ""))
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "priority": priority,
                "severity": sev,
                "module": f.get("module", ""),
                "finding": f.get("title", ""),
                "remediation": f.get("remediation", "Refer to module-specific report for details."),
                "mitre_attack": f.get("mitre_attack", ""),
            })
            priority += 1

    return items


# ---------------------------------------------------------------------------
# Console report output
# ---------------------------------------------------------------------------


def print_console_report(
    target: str,
    score: float,
    label: str,
    summary: str,
    all_findings: List[Dict[str, Any]],
    module_results: Dict[str, Dict[str, Any]],
    chains: List[Dict[str, Any]],
    remediation: List[Dict[str, Any]],
    wazuh_rules: List[Dict[str, str]],
    elapsed: float,
) -> None:
    """Print a full color-coded console report."""

    # --- Scan completion ---
    _section_header("SCAN COMPLETE")
    print(f"  Target:       {Fore.WHITE}{Style.BRIGHT}{target}{Style.RESET_ALL}")
    print(f"  Duration:     {elapsed:.1f}s")
    print(f"  Modules:      {len(module_results)}")
    total_findings = len(all_findings)
    print(f"  Findings:     {total_findings}")

    # --- Risk Score Gauge ---
    _section_header("UNIFIED RISK SCORE")
    gauge_width = 50
    filled = int(score / 100 * gauge_width)
    empty = gauge_width - filled
    if score >= 80:
        gauge_color = Fore.RED + Style.BRIGHT
    elif score >= 60:
        gauge_color = Fore.RED
    elif score >= 40:
        gauge_color = Fore.YELLOW
    elif score >= 20:
        gauge_color = Fore.BLUE
    else:
        gauge_color = Fore.GREEN
    bar = f"  {gauge_color}[{'█' * filled}{'░' * empty}] {score}/100 — {label}{Style.RESET_ALL}"
    print(bar)

    # --- Executive Summary ---
    _section_header("EXECUTIVE SUMMARY")
    for line in textwrap.wrap(summary, width=70):
        print(f"  {line}")

    # --- Module Results ---
    _section_header("MODULE RESULTS")
    for key, res in module_results.items():
        reg = SCANNER_REGISTRY.get(key, {})
        desc = reg.get("description", key)
        n_findings = len(res.get("findings", []))
        mod_score = res.get("risk_score", 0)
        err = res.get("raw", {}).get("error")
        if err:
            status = f"{Fore.RED}ERROR{Style.RESET_ALL}"
            detail = f" — {err}"
        elif n_findings == 0:
            status = f"{Fore.GREEN}PASS{Style.RESET_ALL}"
            detail = ""
        else:
            status = f"{Fore.YELLOW}{n_findings} finding(s){Style.RESET_ALL}"
            detail = ""
        print(f"  [{status}] {desc:<40}{detail}")

    # --- Findings by Severity ---
    _section_header("FINDINGS BY SEVERITY")
    for sev in SEVERITY_ORDER:
        group = [f for f in all_findings if f["severity"] == sev]
        if not group:
            continue
        color = _severity_color(sev)
        print(f"\n  {color}--- {sev} ({len(group)}) ---{Style.RESET_ALL}")
        for f in group:
            mod_label = f.get("module", "").upper()
            mitre = f.get("mitre_attack", "")
            mitre_tag = f" [{mitre}]" if mitre else ""
            print(f"  {color}  [{mod_label}]{mitre_tag} {f['title']}{Style.RESET_ALL}")
            if f.get("description"):
                for line in textwrap.wrap(f["description"], width=64):
                    print(f"           {Fore.WHITE}{line}{Style.RESET_ALL}")

    # --- MITRE ATT&CK Mapping ---
    _section_header("MITRE ATT&CK MAPPING")
    seen_mitre: set = set()
    for f in all_findings:
        mid = f.get("mitre_attack", "")
        if not mid or mid in seen_mitre:
            continue
        seen_mitre.add(mid)
        info = MITRE_MAPPING.get(mid, {"name": mid, "tactic": "Unknown"})
        print(
            f"  {Fore.MAGENTA}{mid:<15}{Style.RESET_ALL} "
            f"{info['name']:<45} "
            f"{Fore.CYAN}({info['tactic']}){Style.RESET_ALL}"
        )

    # --- Attack Chains ---
    _section_header("ATTACK CHAIN ANALYSIS")
    if chains:
        for i, chain in enumerate(chains, 1):
            likelihood_color = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.BLUE}.get(
                chain["likelihood"], Fore.WHITE
            )
            print(
                f"\n  {Fore.WHITE}{Style.BRIGHT}Chain {i}: {chain['name']}{Style.RESET_ALL} "
                f"[{likelihood_color}{chain['likelihood']}{Style.RESET_ALL} likelihood]"
            )
            for step in chain["steps"]:
                print(
                    f"    {Fore.CYAN}{step['phase']:<20}{Style.RESET_ALL} "
                    f"{Fore.MAGENTA}{step['technique']:<12}{Style.RESET_ALL} "
                    f"{step['action']}"
                )
            print(f"    {Fore.RED}Impact: {chain['impact']}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}No significant attack chains identified.{Style.RESET_ALL}")

    # --- Remediation Priority ---
    _section_header("REMEDIATION PRIORITY LIST")
    if remediation:
        for item in remediation[:20]:  # Top 20
            sev_color = _severity_color(item["severity"])
            print(
                f"  {Fore.WHITE}{item['priority']:>3}.{Style.RESET_ALL} "
                f"{sev_color}[{item['severity']}]{Style.RESET_ALL} "
                f"[{item['module'].upper()}] {item['finding']}"
            )
    else:
        print(f"  {Fore.GREEN}No remediation items — target appears well-configured.{Style.RESET_ALL}")

    # --- Wazuh Rules ---
    _section_header(f"WAZUH DETECTION RULES ({len(wazuh_rules)} generated)")
    for rule in wazuh_rules[:10]:  # Show first 10
        print(
            f"  Rule {Fore.CYAN}{rule['rule_id']}{Style.RESET_ALL} "
            f"(Level {rule['level']}) — {rule['description']}"
        )
    if len(wazuh_rules) > 10:
        print(f"  {Fore.WHITE}... and {len(wazuh_rules) - 10} more (see full report){Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}  Scan finished at {timestamp_now()}{Style.RESET_ALL}\n")


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------


def write_json_report(report: Dict[str, Any], output_dir: Path) -> Path:
    """Write the full JSON report and return the file path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = re.sub(r"[^a-zA-Z0-9._-]", "_", report.get("target", "unknown"))
    path = output_dir / f"haka_ai_{target_safe}_{ts}.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
    return path


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


def _severity_html_color(sev: str) -> str:
    return {
        "CRITICAL": "#dc3545",
        "HIGH": "#e74c3c",
        "MEDIUM": "#f39c12",
        "LOW": "#3498db",
        "INFO": "#6c757d",
    }.get(sev.upper(), "#6c757d")


def _gauge_css_color(score: float) -> str:
    if score >= 80:
        return "#dc3545"
    if score >= 60:
        return "#e74c3c"
    if score >= 40:
        return "#f39c12"
    if score >= 20:
        return "#3498db"
    return "#28a745"


def write_html_report(report: Dict[str, Any], output_dir: Path) -> Path:
    """Generate a professional, printable HTML report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = re.sub(r"[^a-zA-Z0-9._-]", "_", report.get("target", "unknown"))
    path = output_dir / f"haka_ai_{target_safe}_{ts}.html"

    target = report.get("target", "N/A")
    score = report.get("unified_risk_score", 0)
    label = report.get("risk_label", "N/A")
    summary = report.get("executive_summary", "")
    findings = report.get("all_findings", [])
    chains = report.get("attack_chains", [])
    remediation = report.get("remediation_priority", [])
    wazuh_rules = report.get("wazuh_rules", [])
    module_results = report.get("module_results", {})
    scan_time = report.get("scan_timestamp", "")
    elapsed = report.get("scan_duration_seconds", 0)

    gauge_color = _gauge_css_color(score)
    gauge_pct = min(score, 100)

    # --- Findings table rows ---
    findings_rows = ""
    for f in findings:
        sev = f.get("severity", "INFO")
        sev_color = _severity_html_color(sev)
        mitre = f.get("mitre_attack", "")
        mitre_link = (
            f'<a href="https://attack.mitre.org/techniques/{mitre.replace(".", "/")}/" '
            f'target="_blank">{mitre}</a>' if mitre else "N/A"
        )
        findings_rows += f"""
        <tr>
          <td><span class="badge" style="background:{sev_color}">{sev}</span></td>
          <td>{f.get("module", "").upper()}</td>
          <td>{f.get("title", "")}</td>
          <td>{f.get("description", "")}</td>
          <td>{mitre_link}</td>
        </tr>"""

    # --- Module summary rows ---
    module_rows = ""
    for key, res in module_results.items():
        reg = SCANNER_REGISTRY.get(key, {})
        desc = reg.get("description", key)
        n = len(res.get("findings", []))
        err = res.get("raw", {}).get("error")
        if err:
            status = '<span class="badge" style="background:#dc3545">ERROR</span>'
        elif n == 0:
            status = '<span class="badge" style="background:#28a745">PASS</span>'
        else:
            status = f'<span class="badge" style="background:#f39c12">{n} findings</span>'
        module_rows += f"<tr><td>{desc}</td><td>{status}</td><td>{n}</td></tr>"

    # --- Attack chain HTML ---
    chains_html = ""
    for i, chain in enumerate(chains, 1):
        steps_html = ""
        for step in chain.get("steps", []):
            mid = step.get("technique", "")
            mitre_info = MITRE_MAPPING.get(mid, {})
            steps_html += f"""
            <tr>
              <td>{step.get("phase", "")}</td>
              <td><code>{mid}</code></td>
              <td>{mitre_info.get("name", mid)}</td>
              <td>{step.get("action", "")}</td>
            </tr>"""
        likelihood_color = {"HIGH": "#dc3545", "MEDIUM": "#f39c12", "LOW": "#3498db"}.get(
            chain.get("likelihood", ""), "#6c757d"
        )
        chains_html += f"""
        <div class="chain-block">
          <h4>Chain {i}: {chain.get("name", "")}
            <span class="badge" style="background:{likelihood_color}">{chain.get("likelihood", "")} Likelihood</span>
          </h4>
          <table class="data-table">
            <thead><tr><th>Phase</th><th>Technique</th><th>Name</th><th>Action</th></tr></thead>
            <tbody>{steps_html}</tbody>
          </table>
          <p class="chain-impact"><strong>Impact:</strong> {chain.get("impact", "")}</p>
        </div>"""

    # --- Remediation rows ---
    remed_rows = ""
    for item in remediation:
        sev_color = _severity_html_color(item.get("severity", "INFO"))
        remed_rows += f"""
        <tr>
          <td>{item.get("priority", "")}</td>
          <td><span class="badge" style="background:{sev_color}">{item.get("severity", "")}</span></td>
          <td>{item.get("module", "").upper()}</td>
          <td>{item.get("finding", "")}</td>
          <td>{item.get("remediation", "")}</td>
        </tr>"""

    # --- Wazuh rules HTML ---
    wazuh_html = ""
    for rule in wazuh_rules:
        wazuh_html += f"""
        <div class="wazuh-rule">
          <strong>Rule {rule.get("rule_id", "")} (Level {rule.get("level", "")})</strong> —
          {rule.get("description", "")} | MITRE: {rule.get("mitre_id", "")}
          <pre>{rule.get("xml", "")}</pre>
        </div>"""

    # --- MITRE mapping rows ---
    mitre_rows = ""
    seen_mitre: set = set()
    for f in findings:
        mid = f.get("mitre_attack", "")
        if not mid or mid in seen_mitre:
            continue
        seen_mitre.add(mid)
        info = MITRE_MAPPING.get(mid, {"name": mid, "tactic": "Unknown"})
        mitre_link = (
            f'<a href="https://attack.mitre.org/techniques/{mid.replace(".", "/")}/" '
            f'target="_blank">{mid}</a>'
        )
        mitre_rows += f"""
        <tr>
          <td>{mitre_link}</td>
          <td>{info.get("name", "")}</td>
          <td>{info.get("tactic", "")}</td>
        </tr>"""

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HAKA AI Security Assessment — {target}</title>
<style>
  :root {{
    --bg: #0d1117;
    --card-bg: #161b22;
    --text: #c9d1d9;
    --heading: #58a6ff;
    --border: #30363d;
    --accent: #1f6feb;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 0;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}

  /* Header */
  .header {{
    background: linear-gradient(135deg, #161b22, #1a2332);
    border-bottom: 3px solid var(--accent);
    padding: 30px 0;
    text-align: center;
    margin-bottom: 30px;
  }}
  .header h1 {{
    font-size: 2.2em;
    color: #58a6ff;
    letter-spacing: 4px;
    font-family: monospace;
  }}
  .header .subtitle {{
    color: #8b949e;
    font-size: 0.95em;
    margin-top: 5px;
  }}
  .header .meta {{
    color: #6e7681;
    font-size: 0.85em;
    margin-top: 10px;
  }}

  /* Cards */
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 24px;
  }}
  .card h2 {{
    color: var(--heading);
    font-size: 1.3em;
    margin-bottom: 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }}

  /* Risk gauge */
  .gauge-container {{
    text-align: center;
    padding: 20px 0;
  }}
  .gauge-bar {{
    width: 100%;
    max-width: 500px;
    height: 32px;
    background: #21262d;
    border-radius: 16px;
    margin: 0 auto;
    overflow: hidden;
    position: relative;
  }}
  .gauge-fill {{
    height: 100%;
    border-radius: 16px;
    background: {gauge_color};
    width: {gauge_pct}%;
    transition: width 1s ease;
  }}
  .gauge-label {{
    font-size: 2.5em;
    font-weight: bold;
    color: {gauge_color};
    margin-top: 12px;
  }}
  .gauge-sublabel {{
    font-size: 1.1em;
    color: #8b949e;
  }}

  /* Tables */
  .data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9em;
  }}
  .data-table th {{
    background: #21262d;
    color: #58a6ff;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 2px solid var(--border);
    cursor: pointer;
    user-select: none;
  }}
  .data-table th:hover {{ background: #282e36; }}
  .data-table td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  .data-table tr:hover {{ background: #1c2128; }}

  /* Badges */
  .badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    color: #fff;
    font-size: 0.8em;
    font-weight: 600;
    white-space: nowrap;
  }}

  /* Links */
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Chain blocks */
  .chain-block {{
    background: #1c2128;
    border-left: 4px solid var(--accent);
    padding: 16px;
    margin: 12px 0;
    border-radius: 4px;
  }}
  .chain-block h4 {{ color: #c9d1d9; margin-bottom: 10px; }}
  .chain-impact {{ color: #f85149; margin-top: 8px; }}

  /* Wazuh rules */
  .wazuh-rule {{
    background: #1c2128;
    padding: 12px;
    margin: 8px 0;
    border-radius: 4px;
    border-left: 3px solid #3fb950;
  }}
  .wazuh-rule pre {{
    background: #0d1117;
    padding: 10px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 0.82em;
    margin-top: 6px;
    color: #7ee787;
  }}

  /* Summary text */
  .summary-text {{
    font-size: 1.05em;
    line-height: 1.8;
    color: #c9d1d9;
  }}

  /* Print styles */
  @media print {{
    body {{ background: #fff; color: #000; }}
    .card {{ border: 1px solid #ccc; break-inside: avoid; }}
    .header {{ background: #f5f5f5; border-bottom: 3px solid #333; }}
    .header h1 {{ color: #333; }}
    .data-table th {{ background: #eee; color: #333; }}
    .gauge-fill {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
    .badge {{ print-color-adjust: exact; -webkit-print-color-adjust: exact; }}
  }}

  /* Responsive */
  @media (max-width: 768px) {{
    .container {{ padding: 10px; }}
    .data-table {{ font-size: 0.8em; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>HAKA AI</h1>
  <div class="subtitle">AI-Powered Security Assessment Framework v{VERSION}</div>
  <div class="meta">Target: <strong>{target}</strong> | Scanned: {scan_time} | Duration: {elapsed:.1f}s</div>
</div>

<div class="container">

  <!-- Risk Score -->
  <div class="card">
    <h2>Unified Risk Score</h2>
    <div class="gauge-container">
      <div class="gauge-bar"><div class="gauge-fill"></div></div>
      <div class="gauge-label">{score}/100</div>
      <div class="gauge-sublabel">{label}</div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="card">
    <h2>Executive Summary</h2>
    <p class="summary-text">{summary}</p>
  </div>

  <!-- Module Results -->
  <div class="card">
    <h2>Module Results</h2>
    <table class="data-table">
      <thead><tr><th>Module</th><th>Status</th><th>Findings</th></tr></thead>
      <tbody>{module_rows}</tbody>
    </table>
  </div>

  <!-- Findings -->
  <div class="card">
    <h2>All Findings</h2>
    <table class="data-table" id="findingsTable">
      <thead>
        <tr>
          <th onclick="sortTable('findingsTable', 0)">Severity</th>
          <th onclick="sortTable('findingsTable', 1)">Module</th>
          <th onclick="sortTable('findingsTable', 2)">Finding</th>
          <th>Description</th>
          <th onclick="sortTable('findingsTable', 4)">MITRE ATT&CK</th>
        </tr>
      </thead>
      <tbody>{findings_rows}</tbody>
    </table>
  </div>

  <!-- MITRE ATT&CK Mapping -->
  <div class="card">
    <h2>MITRE ATT&CK Mapping</h2>
    <table class="data-table">
      <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th></tr></thead>
      <tbody>{mitre_rows}</tbody>
    </table>
  </div>

  <!-- Attack Chains -->
  <div class="card">
    <h2>Attack Chain Analysis</h2>
    {chains_html if chains_html else "<p>No significant attack chains identified.</p>"}
  </div>

  <!-- Remediation Priority -->
  <div class="card">
    <h2>Remediation Priority List</h2>
    <table class="data-table">
      <thead><tr><th>#</th><th>Severity</th><th>Module</th><th>Finding</th><th>Remediation</th></tr></thead>
      <tbody>{remed_rows}</tbody>
    </table>
  </div>

  <!-- Wazuh Rules -->
  <div class="card">
    <h2>Wazuh Detection Rules ({len(wazuh_rules)} generated)</h2>
    {wazuh_html if wazuh_html else "<p>No Wazuh rules generated.</p>"}
  </div>

  <!-- Footer -->
  <div style="text-align:center; padding:30px 0; color:#6e7681; font-size:0.85em;">
    Generated by HAKA AI v{VERSION} | github.com/axumweyane | {scan_time}
  </div>

</div>

<script>
// Simple table sorting
function sortTable(tableId, colIdx) {{
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const sevOrder = {{"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}};
  const dir = table.dataset.sortDir === 'asc' ? 'desc' : 'asc';
  table.dataset.sortDir = dir;
  rows.sort((a, b) => {{
    let aVal = a.cells[colIdx]?.textContent.trim() || '';
    let bVal = b.cells[colIdx]?.textContent.trim() || '';
    // Severity-aware sort
    if (colIdx === 0) {{
      aVal = sevOrder[aVal] !== undefined ? sevOrder[aVal] : 99;
      bVal = sevOrder[bVal] !== undefined ? sevOrder[bVal] : 99;
      return dir === 'asc' ? aVal - bVal : bVal - aVal;
    }}
    return dir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


# ---------------------------------------------------------------------------
# Configuration file handling
# ---------------------------------------------------------------------------


def load_config(config_path: str) -> Dict[str, Any]:
    """Load YAML or JSON config file."""
    path = Path(config_path)
    if not path.exists():
        print(f"{Fore.RED}[!] Config file not found: {config_path}{Style.RESET_ALL}")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as fh:
        if path.suffix in (".yaml", ".yml"):
            if not HAS_YAML:
                print(f"{Fore.RED}[!] PyYAML required for YAML configs: pip install pyyaml{Style.RESET_ALL}")
                sys.exit(1)
            return yaml.safe_load(fh) or {}
        else:
            return json.load(fh)


DEFAULT_CONFIG: Dict[str, Any] = {
    "target": None,
    "modules": ALL_MODULE_KEYS,
    "output_dir": str(DEFAULT_REPORTS_DIR),
    "formats": ["console", "json"],
    "parallel": True,
    "max_workers": 4,
    "verbose": False,
    "thresholds": {
        "critical_min": 80,
        "high_min": 60,
        "medium_min": 40,
        "low_min": 20,
    },
    "smtp_check": False,
}


# ---------------------------------------------------------------------------
# Progress tracking
# ---------------------------------------------------------------------------


class ProgressTracker:
    """Thin wrapper: uses tqdm if available, otherwise prints status lines."""

    def __init__(self, total: int, description: str = "Scanning"):
        self.total = total
        self.description = description
        self.completed = 0
        self._bar = None
        if HAS_TQDM:
            self._bar = tqdm(
                total=total,
                desc=f"  {description}",
                bar_format="  {l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                ncols=72,
            )

    def update(self, module_name: str) -> None:
        self.completed += 1
        if self._bar:
            self._bar.set_postfix_str(module_name)
            self._bar.update(1)
        else:
            pct = int(self.completed / self.total * 100)
            bar_len = 30
            filled = int(bar_len * self.completed / self.total)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(
                f"\r  [{bar}] {pct:>3}% ({self.completed}/{self.total}) — {module_name:<20}",
                end="", flush=True,
            )

    def close(self) -> None:
        if self._bar:
            self._bar.close()
        else:
            print()  # newline after progress bar


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


class HakaAI:
    """Master orchestrator that runs all HAKA AI scanner modules."""

    def __init__(self, config: Dict[str, Any]):
        self.config = {**DEFAULT_CONFIG, **config}
        self.target: str = self.config["target"]
        self.modules: List[str] = self.config["modules"]
        self.output_dir = Path(self.config["output_dir"])
        self.formats: List[str] = self.config["formats"]
        self.parallel: bool = self.config["parallel"]
        self.max_workers: int = self.config["max_workers"]
        self.verbose: bool = self.config["verbose"]

        self.logger = setup_logging(self.output_dir / "logs", self.verbose)

        # Results storage
        self.module_results: Dict[str, Dict[str, Any]] = {}
        self.all_findings: List[Dict[str, Any]] = []
        self.unified_score: float = 0.0
        self.risk_label: str = ""
        self.executive_summary: str = ""
        self.attack_chains: List[Dict[str, Any]] = []
        self.remediation: List[Dict[str, Any]] = []
        self.wazuh_rules: List[Dict[str, str]] = []
        self.elapsed: float = 0.0

    def _run_single_module(self, key: str) -> Tuple[str, Dict[str, Any]]:
        """Run a single scanner module and return (key, result)."""
        runner = _RUNNER_MAP.get(key)
        if not runner:
            self.logger.error("No runner registered for module: %s", key)
            return key, {
                "module": key,
                "description": SCANNER_REGISTRY.get(key, {}).get("description", key),
                "raw": {"error": f"No runner for module '{key}'"},
                "findings": [],
                "risk_score": 0,
            }
        try:
            self.logger.info("Starting module: %s", key)
            result = runner(self.target, self.logger, **self.config)
            self.logger.info(
                "Module %s complete: %d findings", key, len(result.get("findings", []))
            )
            return key, result
        except Exception as exc:
            self.logger.error("Module %s failed: %s", key, exc, exc_info=True)
            return key, {
                "module": key,
                "description": SCANNER_REGISTRY.get(key, {}).get("description", key),
                "raw": {"error": str(exc)},
                "findings": [],
                "risk_score": 0,
            }

    def run(self) -> Dict[str, Any]:
        """Execute the full scan pipeline."""
        start_time = time.time()

        # Print banner
        print(BANNER)
        _section_header(f"HAKA AI UNIFIED SCAN — {self.target}")
        print(f"  Modules: {', '.join(self.modules)}")
        print(f"  Parallel: {self.parallel} (workers: {self.max_workers})")
        print(f"  Output:  {self.output_dir}")
        print(f"  Formats: {', '.join(self.formats)}")
        print(f"  Started: {timestamp_now()}")

        # --- Run modules ---
        _section_header("RUNNING SCANNERS")
        progress = ProgressTracker(len(self.modules), "Scanning modules")

        if self.parallel and len(self.modules) > 1:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._run_single_module, key): key
                    for key in self.modules
                }
                for future in as_completed(futures):
                    key = futures[future]
                    try:
                        mod_key, result = future.result()
                        self.module_results[mod_key] = result
                    except Exception as exc:
                        self.logger.error("Future for %s raised: %s", key, exc)
                        self.module_results[key] = {
                            "module": key,
                            "raw": {"error": str(exc)},
                            "findings": [],
                            "risk_score": 0,
                        }
                    progress.update(key)
        else:
            for key in self.modules:
                mod_key, result = self._run_single_module(key)
                self.module_results[mod_key] = result
                progress.update(key)

        progress.close()

        # --- Aggregate findings ---
        for key in self.modules:
            res = self.module_results.get(key, {})
            self.all_findings.extend(res.get("findings", []))

        # Sort findings: CRITICAL first
        sev_order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        self.all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "INFO"), 99))

        # --- Compute unified risk score ---
        self.unified_score, self.risk_label = compute_unified_risk_score(self.all_findings)

        # --- Generate executive summary ---
        self.executive_summary = generate_executive_summary(
            self.target, self.unified_score, self.risk_label,
            self.all_findings, self.module_results,
        )

        # --- Attack chain analysis ---
        self.attack_chains = analyze_attack_chains(self.all_findings)

        # --- Remediation priority ---
        self.remediation = build_remediation_list(self.all_findings)

        # --- Wazuh rules ---
        self.wazuh_rules = generate_wazuh_rules(self.all_findings, self.target)

        self.elapsed = time.time() - start_time

        # --- Build full report dict ---
        report = self._build_report()

        # --- Output ---
        if "console" in self.formats:
            print_console_report(
                self.target, self.unified_score, self.risk_label,
                self.executive_summary, self.all_findings,
                self.module_results, self.attack_chains,
                self.remediation, self.wazuh_rules, self.elapsed,
            )

        output_files: List[str] = []
        if "json" in self.formats:
            json_path = write_json_report(report, self.output_dir)
            output_files.append(str(json_path))
            print(f"  {Fore.GREEN}[+] JSON report: {json_path}{Style.RESET_ALL}")

        if "html" in self.formats:
            html_path = write_html_report(report, self.output_dir)
            output_files.append(str(html_path))
            print(f"  {Fore.GREEN}[+] HTML report: {html_path}{Style.RESET_ALL}")

        report["output_files"] = output_files
        return report

    def _build_report(self) -> Dict[str, Any]:
        """Build the full report dictionary."""
        counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in self.all_findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1

        return {
            "tool": "HAKA AI Unified Scanner",
            "version": VERSION,
            "target": self.target,
            "scan_timestamp": timestamp_now(),
            "scan_duration_seconds": round(self.elapsed, 2),
            "modules_executed": self.modules,
            "modules_total": len(self.modules),
            "unified_risk_score": self.unified_score,
            "risk_label": self.risk_label,
            "executive_summary": self.executive_summary,
            "finding_counts": counts,
            "total_findings": len(self.all_findings),
            "all_findings": self.all_findings,
            "module_results": {
                k: {
                    "module": v.get("module", k),
                    "description": v.get("description", ""),
                    "findings_count": len(v.get("findings", [])),
                    "risk_score": v.get("risk_score", 0),
                    "error": v.get("raw", {}).get("error"),
                    "findings": v.get("findings", []),
                }
                for k, v in self.module_results.items()
            },
            "attack_chains": self.attack_chains,
            "mitre_techniques": list({
                f.get("mitre_attack", "") for f in self.all_findings if f.get("mitre_attack")
            }),
            "remediation_priority": self.remediation,
            "wazuh_rules": self.wazuh_rules,
        }


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="haka_ai",
        description="HAKA AI — Unified Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python haka_ai.py --target haka.local --full-scan
              python haka_ai.py --target 192.168.122.210 --modules email,dns,exchange
              python haka_ai.py --target haka.local --output /reports/ --format html,json
              python haka_ai.py --config haka_config.yaml
        """),
    )

    parser.add_argument(
        "--target", "-t",
        help="Target domain or IP address to scan",
    )
    parser.add_argument(
        "--full-scan", "-F",
        action="store_true",
        help="Run all scanner modules (default if no --modules specified)",
    )
    parser.add_argument(
        "--modules", "-m",
        help=(
            f"Comma-separated list of modules to run. "
            f"Available: {', '.join(ALL_MODULE_KEYS)}"
        ),
    )
    parser.add_argument(
        "--output", "-o",
        default=str(DEFAULT_REPORTS_DIR),
        help=f"Output directory for reports (default: {DEFAULT_REPORTS_DIR})",
    )
    parser.add_argument(
        "--format", "-f",
        default="console,json",
        help="Comma-separated output formats: console, json, html (default: console,json)",
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to YAML/JSON configuration file",
    )
    parser.add_argument(
        "--parallel",
        dest="parallel",
        action="store_true",
        default=True,
        help="Enable parallel module execution (default: enabled)",
    )
    parser.add_argument(
        "--no-parallel",
        dest="parallel",
        action="store_false",
        help="Disable parallel module execution",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=4,
        help="Maximum parallel workers (default: 4)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output and debug logging",
    )
    parser.add_argument(
        "--smtp-check",
        action="store_true",
        help="Enable SMTP banner / VRFY checks in the email module",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"HAKA AI v{VERSION}",
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List available scanner modules and exit",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    args = parse_args()

    # List modules and exit
    if args.list_modules:
        print(BANNER)
        _section_header("AVAILABLE SCANNER MODULES")
        for key, reg in SCANNER_REGISTRY.items():
            script_path = SCANNERS_DIR / f"{reg['module']}.py"
            exists = script_path.exists()
            status = f"{Fore.GREEN}installed{Style.RESET_ALL}" if exists else f"{Fore.RED}not found{Style.RESET_ALL}"
            mitre = ", ".join(reg.get("mitre_ids", []))
            print(
                f"  {Fore.CYAN}{key:<12}{Style.RESET_ALL} "
                f"{reg['description']:<40} "
                f"[{status}] "
                f"{Fore.MAGENTA}{mitre}{Style.RESET_ALL}"
            )
        sys.exit(0)

    # Load config file if provided
    file_config: Dict[str, Any] = {}
    if args.config:
        file_config = load_config(args.config)

    # Build effective config: file < CLI overrides
    config: Dict[str, Any] = {**DEFAULT_CONFIG, **file_config}

    if args.target:
        config["target"] = args.target
    if not config.get("target"):
        print(f"{Fore.RED}[!] --target is required (or set target in config file){Style.RESET_ALL}")
        sys.exit(1)

    if args.modules:
        requested = [m.strip().lower() for m in args.modules.split(",")]
        invalid = [m for m in requested if m not in SCANNER_REGISTRY]
        if invalid:
            print(f"{Fore.RED}[!] Unknown module(s): {', '.join(invalid)}{Style.RESET_ALL}")
            print(f"    Available: {', '.join(ALL_MODULE_KEYS)}")
            sys.exit(1)
        config["modules"] = requested
    elif args.full_scan:
        config["modules"] = ALL_MODULE_KEYS
    elif "modules" not in file_config:
        # Default: all modules
        config["modules"] = ALL_MODULE_KEYS

    config["output_dir"] = args.output
    config["formats"] = [f.strip().lower() for f in args.format.split(",")]
    config["parallel"] = args.parallel
    config["max_workers"] = args.workers
    config["verbose"] = args.verbose
    config["smtp_check"] = args.smtp_check

    # Validate formats
    valid_formats = {"console", "json", "html"}
    bad_formats = set(config["formats"]) - valid_formats
    if bad_formats:
        print(f"{Fore.RED}[!] Unknown format(s): {', '.join(bad_formats)}{Style.RESET_ALL}")
        print(f"    Available: {', '.join(valid_formats)}")
        sys.exit(1)

    # Run the orchestrator
    orchestrator = HakaAI(config)
    try:
        report = orchestrator.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as exc:
        print(f"\n{Fore.RED}[!] Fatal error: {exc}{Style.RESET_ALL}")
        logging.getLogger("haka_ai").critical("Fatal error", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
