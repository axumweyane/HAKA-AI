#!/usr/bin/env python3
"""
HAKA AI Framework - Tool 7: S3 Bucket Scanner
==============================================
Section D1 - S3 Exfiltration (MITRE ATT&CK T1530)
Finding: CRIT-CBE-09

Discovers and audits S3 buckets (AWS and MinIO) for public access,
misconfigured ACLs, and data exposure risks.

Author : HAKA AI Framework
Version: 1.0.0
"""

import argparse
import json
import os
import sys
import time
import signal
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree

# ---------------------------------------------------------------------------
# Optional dependency handling
# ---------------------------------------------------------------------------

try:
    import requests
except ImportError:
    print("[!] 'requests' library is required. Install: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    # Provide no-op stubs so the rest of the code works without colorama.
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = _NoColor()
    Style = _NoColor()

BOTO3_AVAILABLE = False
try:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BANNER = rf"""
{Fore.CYAN}
  ██╗  ██╗ █████╗ ██╗  ██╗ █████╗     ███████╗██████╗
  ██║  ██║██╔══██╗██║ ██╔╝██╔══██╗    ██╔════╝╚════██╗
  ███████║███████║█████╔╝ ███████║    ███████╗ █████╔╝
  ██╔══██║██╔══██║██╔═██╗ ██╔══██║    ╚════██║ ╚═══██╗
  ██║  ██║██║  ██║██║  ██╗██║  ██║    ███████║██████╔╝
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝╚═════╝
{Style.RESET_ALL}
  {Fore.WHITE}HAKA AI - S3 Bucket Scanner{Style.RESET_ALL}
  {Fore.YELLOW}T1530 - Data from Cloud Storage Object{Style.RESET_ALL}
  {Fore.RED}Finding: CRIT-CBE-09{Style.RESET_ALL}
"""

AWS_S3_ENDPOINT = "https://s3.amazonaws.com"
DEFAULT_REPORT_DIR = Path("/home/kironix/HAKA-AI/reports")
MAX_LIST_FILES = 20
DEFAULT_THREADS = 10
DEFAULT_RATE_LIMIT = 0.3  # seconds between requests per thread
REQUEST_TIMEOUT = 10

# S3 XML namespace
S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"

# Risk levels
RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"

RISK_COLORS = {
    RISK_CRITICAL: Fore.RED,
    RISK_HIGH: Fore.LIGHTRED_EX,
    RISK_MEDIUM: Fore.YELLOW,
    RISK_LOW: Fore.CYAN,
    RISK_INFO: Fore.WHITE,
}

# ---------------------------------------------------------------------------
# Bucket name generation
# ---------------------------------------------------------------------------

BUCKET_PATTERNS = [
    "{org}",
    "{org}-backup",
    "{org}-backups",
    "{org}-data",
    "{org}-logs",
    "{org}-dev",
    "{org}-staging",
    "{org}-assets",
    "{org}-media",
    "{org}-uploads",
    "{org}-static",
    "{org}-public",
    "{org}-private",
    "{org}-internal",
    "{org}-prod",
    "{org}-production",
    "{org}-test",
    "{org}-testing",
    "{org}-config",
    "{org}-db",
    "{org}-database",
    "{org}-archive",
    "{org}-cdn",
    "{org}-web",
    "{org}-www",
    "{org}-api",
    "{org}-docs",
    "{org}-images",
    "{org}-files",
    "{org}-tmp",
    "{org}-temp",
    "backup-{org}",
    "backups-{org}",
    "data-{org}",
    "www-{org}",
    "cdn-{org}",
    "files-{org}",
    "logs-{org}",
    "media-{org}",
    "assets-{org}",
    "static-{org}",
    "uploads-{org}",
    "dev-{org}",
    "staging-{org}",
    "prod-{org}",
    "s3-{org}",
    "{org}-s3",
    "{org}-bucket",
    "{org}-storage",
]


def generate_bucket_names(org: str) -> list[str]:
    """Generate candidate bucket names from organization name / domain."""
    names = set()
    # Normalize: lowercase, strip common TLDs, replace dots/spaces with hyphens
    org_clean = org.lower().strip()
    variants = [org_clean]

    # If it looks like a domain, derive short name
    if "." in org_clean:
        parts = org_clean.split(".")
        # e.g. "example.com" -> "example"
        variants.append(parts[0])
        # e.g. "example.co.uk" -> "example"
        variants.append(org_clean.replace(".", "-"))

    for variant in variants:
        for pattern in BUCKET_PATTERNS:
            bucket = pattern.format(org=variant)
            # S3 bucket name rules: 3-63 chars, lowercase, no underscores
            bucket = bucket.replace("_", "-").replace(" ", "-")
            if 3 <= len(bucket) <= 63:
                names.add(bucket)

    return sorted(names)


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def log_info(msg: str) -> None:
    print(f"  {Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def log_ok(msg: str) -> None:
    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def log_warn(msg: str) -> None:
    print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def log_crit(msg: str) -> None:
    print(f"  {Fore.RED}[!!!]{Style.RESET_ALL} {msg}")


def log_fail(msg: str) -> None:
    print(f"  {Fore.LIGHTBLACK_EX}[-]{Style.RESET_ALL} {msg}")


def risk_label(level: str) -> str:
    color = RISK_COLORS.get(level, "")
    return f"{color}[{level}]{Style.RESET_ALL}"


# ---------------------------------------------------------------------------
# Size formatting
# ---------------------------------------------------------------------------

def human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} PB"


# ---------------------------------------------------------------------------
# S3 Bucket Scanner (requests-based)
# ---------------------------------------------------------------------------

class S3BucketResult:
    """Holds the scan result for a single bucket."""

    def __init__(self, name: str):
        self.name: str = name
        self.exists: bool = False
        self.is_listable: bool = False
        self.is_readable: bool = False
        self.acl_readable: bool = False
        self.upload_allowed: bool = False
        self.access_denied: bool = False
        self.risk: str = RISK_INFO
        self.files: list[dict] = []
        self.total_size: int = 0
        self.total_files: int = 0
        self.acl_grants: list[dict] = []
        self.errors: list[str] = []
        self.url: str = ""

    def to_dict(self) -> dict:
        return {
            "bucket": self.name,
            "url": self.url,
            "exists": self.exists,
            "publicly_listable": self.is_listable,
            "files_readable": self.is_readable,
            "acl_readable": self.acl_readable,
            "upload_allowed": self.upload_allowed,
            "access_denied": self.access_denied,
            "risk_level": self.risk,
            "total_files_found": self.total_files,
            "total_size_bytes": self.total_size,
            "total_size_human": human_size(self.total_size),
            "sample_files": self.files[:MAX_LIST_FILES],
            "acl_grants": self.acl_grants,
            "errors": self.errors,
        }


class S3Scanner:
    """Core scanner that checks S3 buckets via HTTP requests and optionally boto3."""

    def __init__(
        self,
        endpoint: str = AWS_S3_ENDPOINT,
        threads: int = DEFAULT_THREADS,
        rate_limit: float = DEFAULT_RATE_LIMIT,
        use_boto3: bool = True,
        timeout: int = REQUEST_TIMEOUT,
        verify_ssl: bool = True,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.threads = threads
        self.rate_limit = rate_limit
        self.use_boto3 = use_boto3 and BOTO3_AVAILABLE
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.is_aws = "amazonaws.com" in self.endpoint
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "HAKA-S3-Scanner/1.0"})
        self._stop = False

        # boto3 anonymous client
        self._s3_client = None
        if self.use_boto3:
            try:
                kwargs = {"config": BotoConfig(signature_version=UNSIGNED)}
                if not self.is_aws:
                    kwargs["endpoint_url"] = self.endpoint
                    kwargs["config"] = BotoConfig(
                        signature_version=UNSIGNED,
                        s3={"addressing_style": "path"},
                    )
                self._s3_client = boto3.client(
                    "s3",
                    aws_access_key_id="",
                    aws_secret_access_key="",
                    region_name="us-east-1",
                    **kwargs,
                )
            except Exception:
                self._s3_client = None

    # -- URL builders -------------------------------------------------------

    def _bucket_url(self, bucket: str) -> str:
        """Build the URL for a bucket depending on endpoint type."""
        if self.is_aws:
            # Virtual-hosted style
            return f"https://{bucket}.s3.amazonaws.com"
        # Path style (MinIO / custom)
        return f"{self.endpoint}/{bucket}"

    def _object_url(self, bucket: str, key: str) -> str:
        if self.is_aws:
            return f"https://{bucket}.s3.amazonaws.com/{key}"
        return f"{self.endpoint}/{bucket}/{key}"

    # -- Throttle -----------------------------------------------------------

    def _throttle(self) -> None:
        if self.rate_limit > 0:
            time.sleep(self.rate_limit)

    # -- Individual checks --------------------------------------------------

    def _check_exists(self, result: S3BucketResult) -> None:
        """HEAD request to see if bucket exists."""
        url = self._bucket_url(result.name)
        result.url = url
        try:
            resp = self.session.head(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True)
            if resp.status_code == 404:
                result.exists = False
            elif resp.status_code in (200, 301, 302, 307, 403):
                result.exists = True
                if resp.status_code == 403:
                    result.access_denied = True
            else:
                result.exists = False
        except requests.ConnectionError:
            result.exists = False
        except requests.RequestException as exc:
            result.errors.append(f"HEAD error: {exc}")
            result.exists = False

    def _check_listable(self, result: S3BucketResult) -> None:
        """GET bucket to see if contents are listable without auth."""
        url = self._bucket_url(result.name)
        try:
            resp = self.session.get(
                url,
                params={"list-type": "2", "max-keys": str(MAX_LIST_FILES)},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if resp.status_code == 200 and "<Contents>" in resp.text:
                result.is_listable = True
                self._parse_listing(result, resp.text)
            elif resp.status_code == 200 and ("<ListBucketResult" in resp.text or "<ListAllMyBucketsResult" in resp.text):
                # MinIO may return list-type-1 style
                result.is_listable = True
                self._parse_listing(result, resp.text)
            elif resp.status_code == 403:
                result.access_denied = True
        except requests.RequestException as exc:
            result.errors.append(f"LIST error: {exc}")

        # Fallback: try list-type 1 if list-type 2 failed
        if not result.is_listable and result.exists:
            try:
                resp = self.session.get(
                    url,
                    params={"max-keys": str(MAX_LIST_FILES)},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                if resp.status_code == 200 and "<Contents>" in resp.text:
                    result.is_listable = True
                    self._parse_listing(result, resp.text)
            except requests.RequestException:
                pass

    def _parse_listing(self, result: S3BucketResult, xml_text: str) -> None:
        """Parse S3 ListBucket XML response into result.files."""
        try:
            root = ElementTree.fromstring(xml_text)
            # Handle both namespaced and non-namespaced XML
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            contents = root.findall(f"{ns}Contents")
            for item in contents:
                key_el = item.find(f"{ns}Key")
                size_el = item.find(f"{ns}Size")
                modified_el = item.find(f"{ns}LastModified")
                if key_el is not None:
                    fsize = int(size_el.text) if size_el is not None and size_el.text else 0
                    result.files.append({
                        "key": key_el.text,
                        "size": fsize,
                        "size_human": human_size(fsize),
                        "last_modified": modified_el.text if modified_el is not None else "",
                    })
                    result.total_size += fsize
                    result.total_files += 1
        except ElementTree.ParseError as exc:
            result.errors.append(f"XML parse error: {exc}")

    def _check_readable(self, result: S3BucketResult) -> None:
        """Attempt to GET the first listed object to verify read access."""
        if not result.files:
            return
        key = result.files[0]["key"]
        url = self._object_url(result.name, key)
        try:
            resp = self.session.head(url, timeout=self.timeout, verify=self.verify_ssl)
            if resp.status_code == 200:
                result.is_readable = True
        except requests.RequestException:
            pass

    def _check_acl(self, result: S3BucketResult) -> None:
        """GET ?acl to check if bucket ACL is readable."""
        url = self._bucket_url(result.name)
        try:
            resp = self.session.get(
                url,
                params={"acl": ""},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if resp.status_code == 200 and "<Grant>" in resp.text:
                result.acl_readable = True
                self._parse_acl(result, resp.text)
        except requests.RequestException:
            pass

    def _parse_acl(self, result: S3BucketResult, xml_text: str) -> None:
        """Extract ACL grants from XML."""
        try:
            root = ElementTree.fromstring(xml_text)
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            for grant in root.iter(f"{ns}Grant"):
                grantee = grant.find(f"{ns}Grantee")
                perm = grant.find(f"{ns}Permission")
                entry = {"permission": perm.text if perm is not None else "UNKNOWN"}

                if grantee is not None:
                    uri = grantee.find(f"{ns}URI")
                    display = grantee.find(f"{ns}DisplayName")
                    grantee_id = grantee.find(f"{ns}ID")
                    if uri is not None:
                        entry["grantee"] = uri.text
                        if "AllUsers" in uri.text:
                            entry["public"] = True
                        elif "AuthenticatedUsers" in uri.text:
                            entry["authenticated_users"] = True
                    elif display is not None:
                        entry["grantee"] = display.text
                    elif grantee_id is not None:
                        entry["grantee"] = grantee_id.text
                result.acl_grants.append(entry)
        except ElementTree.ParseError:
            pass

    def _check_upload(self, result: S3BucketResult) -> None:
        """
        Detection-only upload check.

        Sends a PUT with Content-Length: 0 for a canary key.
        We use a clearly identifiable key name so it can be cleaned up.
        We abort / don't send a real body -- the goal is to see if we
        get 200/403/405 rather than actually writing data.
        """
        canary_key = f".haka-scan-canary-{hashlib.md5(result.name.encode()).hexdigest()[:8]}.txt"
        url = self._object_url(result.name, canary_key)
        try:
            resp = self.session.put(
                url,
                data=b"",
                headers={"Content-Length": "0"},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if resp.status_code in (200, 204):
                result.upload_allowed = True
                # Attempt to clean up the canary
                try:
                    self.session.delete(url, timeout=self.timeout, verify=self.verify_ssl)
                except requests.RequestException:
                    pass
        except requests.RequestException:
            pass

    # -- Risk scoring -------------------------------------------------------

    @staticmethod
    def _score_risk(result: S3BucketResult) -> None:
        """Assign risk level based on findings."""
        if not result.exists:
            result.risk = RISK_INFO
            return

        if result.is_readable or result.upload_allowed:
            result.risk = RISK_CRITICAL
        elif result.is_listable:
            result.risk = RISK_CRITICAL
        elif result.acl_readable:
            result.risk = RISK_HIGH
        elif result.access_denied:
            result.risk = RISK_LOW
        else:
            result.risk = RISK_INFO

    # -- boto3 enhanced check -----------------------------------------------

    def _boto3_check(self, result: S3BucketResult) -> None:
        """Supplement HTTP checks with boto3 calls when available."""
        if self._s3_client is None:
            return

        # List objects via boto3 (may succeed where HTTP failed due to redirects)
        if not result.is_listable:
            try:
                resp = self._s3_client.list_objects_v2(Bucket=result.name, MaxKeys=MAX_LIST_FILES)
                if "Contents" in resp:
                    result.is_listable = True
                    for obj in resp["Contents"]:
                        fsize = obj.get("Size", 0)
                        result.files.append({
                            "key": obj["Key"],
                            "size": fsize,
                            "size_human": human_size(fsize),
                            "last_modified": obj.get("LastModified", "").isoformat()
                            if hasattr(obj.get("LastModified", ""), "isoformat") else str(obj.get("LastModified", "")),
                        })
                        result.total_size += fsize
                        result.total_files += 1
            except ClientError:
                pass
            except (EndpointConnectionError, NoCredentialsError):
                pass
            except Exception:
                pass

        # ACL via boto3
        if not result.acl_readable:
            try:
                acl = self._s3_client.get_bucket_acl(Bucket=result.name)
                if "Grants" in acl:
                    result.acl_readable = True
                    for grant in acl["Grants"]:
                        entry = {"permission": grant.get("Permission", "UNKNOWN")}
                        grantee = grant.get("Grantee", {})
                        if "URI" in grantee:
                            entry["grantee"] = grantee["URI"]
                            if "AllUsers" in grantee["URI"]:
                                entry["public"] = True
                        elif "DisplayName" in grantee:
                            entry["grantee"] = grantee["DisplayName"]
                        result.acl_grants.append(entry)
            except Exception:
                pass

    # -- Full scan for one bucket -------------------------------------------

    def scan_bucket(self, bucket_name: str) -> Optional[S3BucketResult]:
        """Run all checks on a single bucket. Returns result or None if stopped."""
        if self._stop:
            return None

        result = S3BucketResult(bucket_name)

        # Step 1: existence
        self._check_exists(result)
        self._throttle()
        if not result.exists:
            return result

        # Step 2: listable
        self._check_listable(result)
        self._throttle()

        # Step 3: file readability
        self._check_readable(result)
        self._throttle()

        # Step 4: ACL
        self._check_acl(result)
        self._throttle()

        # Step 5: upload (only if bucket is listable/readable -- reduces noise)
        if result.is_listable or result.is_readable:
            self._check_upload(result)
            self._throttle()

        # Step 6: boto3 supplements
        if self.use_boto3:
            self._boto3_check(result)

        # Score
        self._score_risk(result)
        return result

    # -- Parallel scanning --------------------------------------------------

    def scan_all(self, bucket_names: list[str]) -> list[S3BucketResult]:
        """Scan a list of bucket names in parallel."""
        results: list[S3BucketResult] = []
        total = len(bucket_names)

        def _signal_handler(sig, frame):
            self._stop = True
            log_warn("Interrupt received -- stopping scan gracefully ...")

        old_handler = signal.signal(signal.SIGINT, _signal_handler)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self.scan_bucket, name): name for name in bucket_names}
            done_count = 0
            for future in as_completed(futures):
                if self._stop:
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                done_count += 1
                bucket = futures[future]
                try:
                    res = future.result()
                    if res is None:
                        continue
                    results.append(res)
                    # Live output
                    if res.exists:
                        if res.risk in (RISK_CRITICAL, RISK_HIGH):
                            log_crit(
                                f"[{done_count}/{total}] {risk_label(res.risk)} "
                                f"{Fore.WHITE}{res.name}{Style.RESET_ALL} -- "
                                f"listable={res.is_listable} readable={res.is_readable} "
                                f"acl={res.acl_readable} upload={res.upload_allowed}"
                            )
                        else:
                            log_ok(
                                f"[{done_count}/{total}] {risk_label(res.risk)} "
                                f"{Fore.WHITE}{res.name}{Style.RESET_ALL} -- exists (access denied)"
                            )
                    else:
                        log_fail(f"[{done_count}/{total}] {res.name} -- not found")
                except Exception as exc:
                    log_warn(f"[{done_count}/{total}] {bucket} -- scan error: {exc}")

        signal.signal(signal.SIGINT, old_handler)
        return results

    def stop(self) -> None:
        self._stop = True


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(
    results: list[S3BucketResult],
    org: str,
    endpoint: str,
    report_dir: Path,
) -> Path:
    """Write JSON report and return its path."""
    report_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    org_safe = org.replace(" ", "_").replace("/", "_").replace(".", "_")
    filename = f"s3_scan_{org_safe}_{timestamp}.json"
    report_path = report_dir / filename

    existing_buckets = [r for r in results if r.exists]
    critical = [r for r in results if r.risk == RISK_CRITICAL]
    high = [r for r in results if r.risk == RISK_HIGH]

    report = {
        "scan_metadata": {
            "tool": "HAKA AI - S3 Bucket Scanner",
            "version": "1.0.0",
            "mitre_technique": "T1530 - Data from Cloud Storage Object",
            "finding_id": "CRIT-CBE-09",
            "organization": org,
            "endpoint": endpoint,
            "scan_time_utc": timestamp,
            "total_candidates_checked": len(results),
            "buckets_found": len(existing_buckets),
            "critical_findings": len(critical),
            "high_findings": len(high),
        },
        "summary": {
            "total_exposed_files": sum(r.total_files for r in critical),
            "total_exposed_size_bytes": sum(r.total_size for r in critical),
            "total_exposed_size_human": human_size(sum(r.total_size for r in critical)),
        },
        "findings": [r.to_dict() for r in results if r.exists],
    }

    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    return report_path


# ---------------------------------------------------------------------------
# Pretty-print summary to terminal
# ---------------------------------------------------------------------------

def print_summary(results: list[S3BucketResult]) -> None:
    existing = [r for r in results if r.exists]
    if not existing:
        print(f"\n  {Fore.GREEN}No buckets found for this organization.{Style.RESET_ALL}\n")
        return

    print(f"\n{'=' * 72}")
    print(f"  {Fore.WHITE}SCAN RESULTS SUMMARY{Style.RESET_ALL}")
    print(f"{'=' * 72}")

    by_risk = {}
    for r in existing:
        by_risk.setdefault(r.risk, []).append(r)

    for level in (RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO):
        buckets = by_risk.get(level, [])
        if not buckets:
            continue
        color = RISK_COLORS.get(level, "")
        print(f"\n  {color}--- {level} ({len(buckets)}) ---{Style.RESET_ALL}")
        for b in buckets:
            flags = []
            if b.is_listable:
                flags.append(f"{Fore.RED}LISTABLE{Style.RESET_ALL}")
            if b.is_readable:
                flags.append(f"{Fore.RED}READABLE{Style.RESET_ALL}")
            if b.acl_readable:
                flags.append(f"{Fore.YELLOW}ACL_EXPOSED{Style.RESET_ALL}")
            if b.upload_allowed:
                flags.append(f"{Fore.RED}UPLOAD_ALLOWED{Style.RESET_ALL}")
            if b.access_denied and not flags:
                flags.append(f"{Fore.CYAN}ACCESS_DENIED{Style.RESET_ALL}")

            flag_str = " | ".join(flags) if flags else "exists"
            print(f"    {Fore.WHITE}{b.name}{Style.RESET_ALL}  [{flag_str}]")

            if b.files:
                print(f"      URL : {b.url}")
                print(f"      Files exposed: {b.total_files}  |  Size: {human_size(b.total_size)}")
                for f in b.files[:MAX_LIST_FILES]:
                    print(f"        {Fore.LIGHTBLACK_EX}{f['key']}{Style.RESET_ALL}  ({f['size_human']})")
                if b.total_files > MAX_LIST_FILES:
                    print(f"        ... and {b.total_files - MAX_LIST_FILES} more files")

            if b.acl_grants:
                print(f"      ACL Grants:")
                for g in b.acl_grants:
                    pub_tag = f" {Fore.RED}[PUBLIC]{Style.RESET_ALL}" if g.get("public") else ""
                    auth_tag = f" {Fore.YELLOW}[AUTH_USERS]{Style.RESET_ALL}" if g.get("authenticated_users") else ""
                    print(f"        {g.get('grantee', 'N/A')} -> {g['permission']}{pub_tag}{auth_tag}")

    # Totals
    total_exposed = sum(r.total_files for r in existing if r.risk == RISK_CRITICAL)
    total_size = sum(r.total_size for r in existing if r.risk == RISK_CRITICAL)

    print(f"\n{'=' * 72}")
    print(f"  {Fore.WHITE}DATA EXPOSURE ESTIMATE{Style.RESET_ALL}")
    print(f"    Buckets found       : {len(existing)}")
    print(f"    Critical findings   : {len(by_risk.get(RISK_CRITICAL, []))}")
    print(f"    High findings       : {len(by_risk.get(RISK_HIGH, []))}")
    print(f"    Files exposed       : {total_exposed}")
    print(f"    Total size exposed  : {human_size(total_size)}")
    print(f"{'=' * 72}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HAKA AI - S3 Bucket Scanner (T1530 / CRIT-CBE-09)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --org cbe
  %(prog)s --org cbe --endpoint http://192.168.122.50:9000
  %(prog)s --wordlist bucket_names.txt
  %(prog)s --org example.com --threads 20 --no-boto3
""",
    )

    input_group = parser.add_argument_group("target")
    input_group.add_argument(
        "--org",
        type=str,
        help="Organization name or domain to generate bucket names from",
    )
    input_group.add_argument(
        "--wordlist",
        type=str,
        help="Path to a file containing bucket names (one per line)",
    )

    scan_group = parser.add_argument_group("scanning")
    scan_group.add_argument(
        "--endpoint",
        type=str,
        default=AWS_S3_ENDPOINT,
        help=f"S3-compatible endpoint URL (default: {AWS_S3_ENDPOINT})",
    )
    scan_group.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})",
    )
    scan_group.add_argument(
        "--rate-limit",
        type=float,
        default=DEFAULT_RATE_LIMIT,
        help=f"Seconds between requests per thread (default: {DEFAULT_RATE_LIMIT})",
    )
    scan_group.add_argument(
        "--timeout",
        type=int,
        default=REQUEST_TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {REQUEST_TIMEOUT})",
    )
    scan_group.add_argument(
        "--no-boto3",
        action="store_true",
        help="Disable boto3, use HTTP requests only",
    )
    scan_group.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (for self-signed certs / lab use)",
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "--report-dir",
        type=str,
        default=str(DEFAULT_REPORT_DIR),
        help=f"Directory for JSON reports (default: {DEFAULT_REPORT_DIR})",
    )
    output_group.add_argument(
        "--json-only",
        action="store_true",
        help="Suppress terminal output, only write JSON report",
    )
    output_group.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal output (suppress per-bucket lines for non-findings)",
    )

    args = parser.parse_args()

    if not args.org and not args.wordlist:
        parser.error("Either --org or --wordlist is required")

    return args


def load_wordlist(path: str) -> list[str]:
    """Load bucket names from a wordlist file."""
    fpath = Path(path)
    if not fpath.exists():
        log_warn(f"Wordlist not found: {path}")
        sys.exit(1)
    names = []
    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                names.append(line)
    return names


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    if not args.json_only:
        print(BANNER)

    # Suppress SSL warnings if requested
    if args.no_ssl_verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Build bucket name list
    bucket_names: list[str] = []
    org_label = args.org or "wordlist"

    if args.wordlist:
        bucket_names.extend(load_wordlist(args.wordlist))
        if not args.json_only:
            log_info(f"Loaded {len(bucket_names)} names from wordlist: {args.wordlist}")

    if args.org:
        generated = generate_bucket_names(args.org)
        bucket_names.extend(generated)
        if not args.json_only:
            log_info(f"Generated {len(generated)} candidate names for org: {args.org}")

    # Deduplicate while preserving order
    seen = set()
    unique_names = []
    for name in bucket_names:
        if name not in seen:
            seen.add(name)
            unique_names.append(name)
    bucket_names = unique_names

    if not bucket_names:
        log_warn("No bucket names to scan.")
        sys.exit(1)

    if not args.json_only:
        log_info(f"Endpoint  : {args.endpoint}")
        log_info(f"Targets   : {len(bucket_names)} unique bucket names")
        log_info(f"Threads   : {args.threads}")
        log_info(f"Rate limit: {args.rate_limit}s per request/thread")
        log_info(f"boto3     : {'enabled' if (BOTO3_AVAILABLE and not args.no_boto3) else 'disabled (HTTP only)'}")
        print()

    # Create scanner
    scanner = S3Scanner(
        endpoint=args.endpoint,
        threads=args.threads,
        rate_limit=args.rate_limit,
        use_boto3=not args.no_boto3,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
    )

    # Run scan
    start_time = time.time()
    results = scanner.scan_all(bucket_names)
    elapsed = time.time() - start_time

    if not args.json_only:
        log_info(f"Scan completed in {elapsed:.1f}s")

    # Print summary
    if not args.json_only:
        print_summary(results)

    # Write report
    report_path = generate_report(
        results=results,
        org=org_label,
        endpoint=args.endpoint,
        report_dir=Path(args.report_dir),
    )

    if not args.json_only:
        log_ok(f"JSON report saved to: {Fore.WHITE}{report_path}{Style.RESET_ALL}")
    else:
        # In json-only mode, print the report path so callers can find it
        print(str(report_path))

    # Exit code: 2 if critical findings, 1 if any findings, 0 otherwise
    critical = any(r.risk == RISK_CRITICAL for r in results)
    found = any(r.exists for r in results)
    sys.exit(2 if critical else (1 if found else 0))


if __name__ == "__main__":
    main()
