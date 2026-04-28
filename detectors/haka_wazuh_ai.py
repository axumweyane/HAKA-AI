#!/usr/bin/env python3
"""
HAKA AI - Wazuh Rule Generator (Tool 12: AI-Powered Detection Rule Engine)

Generates Wazuh custom detection rules from HAKA scan results.
Maps findings to 24+ pre-built rule templates covering:
  Email, DNS, AD/NTLM, Exchange, Kerberos, Web, WordPress,
  cPanel, Cloud, VPN, TLS, Mattermost, and more.

Modes:
  --generate-all     Output all pre-built HAKA rules
  --from-scan FILE   Parse scan JSON and emit matching rules
  --custom TEXT      AI-style free-text rule generation
  --deploy PATH      Copy generated rules to Wazuh server

Author:  HAKA AI Framework
Version: 1.0.0
"""

import argparse
import copy
import json
import os
import re
import shutil
import sys
import textwrap
import xml.dom.minidom
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional, Tuple

try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    sys.exit(
        "[!] colorama is required.  Install it:\n"
        "    pip install colorama"
    )

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
REPORTS_DIR = Path("/home/kironix/HAKA-AI/reports")
RULES_SUBDIR = REPORTS_DIR / "wazuh_rules"
COMBINED_RULES_FILE = RULES_SUBDIR / "local_rules.xml"

BANNER = r"""
  _   _    _    _  __    _        __        ___    ____  _   _ _   _
 | | | |  / \  | |/ /   / \       \ \      / / \  |_  / | | | | | | |
 | |_| | / _ \ | ' /   / _ \  _____\ \ /\ / / _ \  / /  | | | | |_| |
 |  _  |/ ___ \| . \  / ___ \|______\ V  V / ___ \/ /__ | |_| |  _  |
 |_| |_/_/   \_\_|\_\/_/   \_\       \_/\_/_/   \_/____| \___/|_| |_|
        AI-Powered Wazuh Detection Rule Generator  v{ver}
"""

# ---------------------------------------------------------------------------
# All 24+ HAKA Rule Templates
# ---------------------------------------------------------------------------

HAKA_RULES: Dict[int, Dict[str, Any]] = {
    # -----------------------------------------------------------------------
    # A1 - Email Spoofing / SMTP
    # -----------------------------------------------------------------------
    100501: {
        "id": 100501,
        "level": 10,
        "description": "HAKA: Email spoofing attempt from external IP",
        "groups": ["haka", "email", "spoofing", "T1566"],
        "mitre_id": "T1566",
        "category": "email",
        "match_field": "data.srcip",
        "match_type": "regex",
        "match_pattern": r"\\S+",
        "decoded_as": "json",
        "rule_xml": textwrap.dedent("""\
            <rule id="100501" level="10">
              <if_sid>3601</if_sid>
              <field name="data.srcip">\\S+</field>
              <description>HAKA: Email spoofing attempt detected — external IP $(data.srcip) sending as internal domain</description>
              <group>haka,email,spoofing,T1566,</group>
              <options>no_full_log</options>
            </rule>"""),
    },
    100502: {
        "id": 100502,
        "level": 8,
        "description": "HAKA: SMTP VRFY/EXPN user enumeration detected",
        "groups": ["haka", "email", "enumeration", "T1589"],
        "mitre_id": "T1589",
        "category": "email",
        "rule_xml": textwrap.dedent("""\
            <rule id="100502" level="8">
              <if_sid>3601</if_sid>
              <match>VRFY|EXPN</match>
              <description>HAKA: SMTP VRFY/EXPN user enumeration attempt</description>
              <group>haka,email,enumeration,T1589,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A2 - DNS Reconnaissance
    # -----------------------------------------------------------------------
    100510: {
        "id": 100510,
        "level": 12,
        "description": "HAKA: DNS zone transfer attempt (AXFR)",
        "groups": ["haka", "dns", "recon", "T1590"],
        "mitre_id": "T1590",
        "category": "dns",
        "rule_xml": textwrap.dedent("""\
            <rule id="100510" level="12">
              <if_sid>12100</if_sid>
              <match>type AXFR</match>
              <description>HAKA: DNS zone transfer (AXFR) attempt detected</description>
              <group>haka,dns,recon,T1590,</group>
            </rule>"""),
    },
    100511: {
        "id": 100511,
        "level": 10,
        "description": "HAKA: DNS brute force — 50+ queries in 60 seconds",
        "groups": ["haka", "dns", "bruteforce", "T1595"],
        "mitre_id": "T1595",
        "category": "dns",
        "rule_xml": textwrap.dedent("""\
            <rule id="100511" level="10" frequency="50" timeframe="60">
              <if_matched_sid>12100</if_matched_sid>
              <same_source_ip />
              <description>HAKA: DNS brute force — 50+ queries from $(srcip) in 60s</description>
              <group>haka,dns,bruteforce,T1595,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A3 - AD / NTLM Relay
    # -----------------------------------------------------------------------
    100520: {
        "id": 100520,
        "level": 12,
        "description": "HAKA: NTLM relay — Network logon (EventID 4624, Type 3)",
        "groups": ["haka", "ad", "ntlm_relay", "T1557"],
        "mitre_id": "T1557",
        "category": "ad",
        "rule_xml": textwrap.dedent("""\
            <rule id="100520" level="12">
              <if_sid>60106</if_sid>
              <field name="win.system.eventID">^4624$</field>
              <field name="win.eventdata.logonType">^3$</field>
              <field name="win.eventdata.authenticationPackageName">NTLM</field>
              <description>HAKA: Potential NTLM relay — Network logon Type 3 via NTLM from $(win.eventdata.ipAddress)</description>
              <group>haka,ad,ntlm_relay,T1557,</group>
            </rule>"""),
    },
    100521: {
        "id": 100521,
        "level": 14,
        "description": "HAKA: Resource-Based Constrained Delegation (RBCD) modified",
        "groups": ["haka", "ad", "rbcd", "T1134"],
        "mitre_id": "T1134",
        "category": "ad",
        "rule_xml": textwrap.dedent("""\
            <rule id="100521" level="14">
              <if_sid>60106</if_sid>
              <field name="win.system.eventID">^5136$</field>
              <field name="win.eventdata.attributeLDAPDisplayName">msDS-AllowedToActOnBehalfOfOtherIdentity</field>
              <description>HAKA: RBCD delegation attribute modified on $(win.eventdata.objectDN)</description>
              <group>haka,ad,rbcd,privilege_escalation,T1134,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A4 - Password Spraying / OWA
    # -----------------------------------------------------------------------
    100530: {
        "id": 100530,
        "level": 10,
        "description": "HAKA: Password spraying pattern detected",
        "groups": ["haka", "auth", "password_spray", "T1110.003"],
        "mitre_id": "T1110.003",
        "category": "auth",
        "rule_xml": textwrap.dedent("""\
            <rule id="100530" level="10" frequency="10" timeframe="120">
              <if_matched_sid>60122</if_matched_sid>
              <same_source_ip />
              <different_target_user />
              <description>HAKA: Password spraying — 10+ failed logins to different accounts from $(srcip)</description>
              <group>haka,auth,password_spray,T1110.003,</group>
            </rule>"""),
    },
    100531: {
        "id": 100531,
        "level": 8,
        "description": "HAKA: OWA cleartext logon over HTTP",
        "groups": ["haka", "exchange", "owa", "cleartext", "T1078"],
        "mitre_id": "T1078",
        "category": "exchange",
        "rule_xml": textwrap.dedent("""\
            <rule id="100531" level="8">
              <if_sid>31100</if_sid>
              <url>/owa/auth|/owa/auth.owa</url>
              <match>POST</match>
              <field name="data.protocol">^HTTP$</field>
              <description>HAKA: OWA cleartext logon detected — credentials transmitted over HTTP</description>
              <group>haka,exchange,owa,cleartext,T1078,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A5 - Exchange / ProxyShell
    # -----------------------------------------------------------------------
    100540: {
        "id": 100540,
        "level": 15,
        "description": "HAKA: ProxyShell exploitation attempt (CVE-2021-34473)",
        "groups": ["haka", "exchange", "proxyshell", "exploit", "T1190"],
        "mitre_id": "T1190",
        "category": "exchange",
        "rule_xml": textwrap.dedent("""\
            <rule id="100540" level="15">
              <if_sid>31100</if_sid>
              <url>/autodiscover/autodiscover.json|/mapi/nspi|/mapi/emsmdb|/powershell</url>
              <match>Email=autodiscover|/autodiscover.json.*@.*</match>
              <description>HAKA: ProxyShell exploitation attempt on Exchange — $(url)</description>
              <group>haka,exchange,proxyshell,exploit,T1190,</group>
            </rule>"""),
    },
    100541: {
        "id": 100541,
        "level": 15,
        "description": "HAKA: Exchange webshell access detected",
        "groups": ["haka", "exchange", "webshell", "T1505.003"],
        "mitre_id": "T1505.003",
        "category": "exchange",
        "rule_xml": textwrap.dedent("""\
            <rule id="100541" level="15">
              <if_sid>31100</if_sid>
              <url>/aspnet_client/|/owa/auth/.*\\.aspx</url>
              <match>200</match>
              <description>HAKA: Potential Exchange webshell accessed — $(url)</description>
              <group>haka,exchange,webshell,T1505.003,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A6 - Kerberos Attacks
    # -----------------------------------------------------------------------
    100550: {
        "id": 100550,
        "level": 12,
        "description": "HAKA: Kerberoasting — TGS request with RC4 encryption",
        "groups": ["haka", "ad", "kerberoasting", "T1558.003"],
        "mitre_id": "T1558.003",
        "category": "ad",
        "rule_xml": textwrap.dedent("""\
            <rule id="100550" level="12">
              <if_sid>60106</if_sid>
              <field name="win.system.eventID">^4769$</field>
              <field name="win.eventdata.ticketEncryptionType">0x17</field>
              <description>HAKA: Kerberoasting — TGS-REQ with RC4 (0x17) for $(win.eventdata.serviceName)</description>
              <group>haka,ad,kerberoasting,T1558.003,</group>
            </rule>"""),
    },
    100551: {
        "id": 100551,
        "level": 14,
        "description": "HAKA: Mass Kerberoasting — multiple RC4 TGS requests",
        "groups": ["haka", "ad", "kerberoasting", "T1558.003"],
        "mitre_id": "T1558.003",
        "category": "ad",
        "rule_xml": textwrap.dedent("""\
            <rule id="100551" level="14" frequency="5" timeframe="30">
              <if_matched_sid>100550</if_matched_sid>
              <same_source_ip />
              <description>HAKA: Mass Kerberoasting — 5+ RC4 TGS requests from $(srcip) in 30s</description>
              <group>haka,ad,kerberoasting,mass,T1558.003,</group>
            </rule>"""),
    },
    100555: {
        "id": 100555,
        "level": 12,
        "description": "HAKA: AS-REP Roasting — pre-auth disabled account TGT request",
        "groups": ["haka", "ad", "asrep_roast", "T1558.004"],
        "mitre_id": "T1558.004",
        "category": "ad",
        "rule_xml": textwrap.dedent("""\
            <rule id="100555" level="12">
              <if_sid>60106</if_sid>
              <field name="win.system.eventID">^4768$</field>
              <field name="win.eventdata.preAuthType">^0$</field>
              <description>HAKA: AS-REP Roasting — TGT requested without pre-authentication for $(win.eventdata.targetUserName)</description>
              <group>haka,ad,asrep_roast,T1558.004,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A7 - Web Shells / Uploads
    # -----------------------------------------------------------------------
    100560: {
        "id": 100560,
        "level": 14,
        "description": "HAKA: Webshell command execution pattern",
        "groups": ["haka", "web", "webshell", "T1059"],
        "mitre_id": "T1059",
        "category": "web",
        "rule_xml": textwrap.dedent("""\
            <rule id="100560" level="14">
              <if_sid>31100</if_sid>
              <url>cmd=|exec=|command=|shell=|c=whoami|c=id|c=uname|c=cat+/etc</url>
              <description>HAKA: Webshell command execution pattern detected — $(url)</description>
              <group>haka,web,webshell,command_exec,T1059,</group>
            </rule>"""),
    },
    100561: {
        "id": 100561,
        "level": 12,
        "description": "HAKA: PHP file upload via PUT method",
        "groups": ["haka", "web", "upload", "T1505.003"],
        "mitre_id": "T1505.003",
        "category": "web",
        "rule_xml": textwrap.dedent("""\
            <rule id="100561" level="12">
              <if_sid>31100</if_sid>
              <match>PUT</match>
              <url>\\.php$|\\.phtml$|\\.phar$</url>
              <description>HAKA: PHP file upload via PUT — $(url)</description>
              <group>haka,web,upload,T1505.003,</group>
            </rule>"""),
    },
    100562: {
        "id": 100562,
        "level": 6,
        "description": "HAKA: phpinfo.php access — information disclosure",
        "groups": ["haka", "web", "info_disclosure", "T1592"],
        "mitre_id": "T1592",
        "category": "web",
        "rule_xml": textwrap.dedent("""\
            <rule id="100562" level="6">
              <if_sid>31100</if_sid>
              <url>phpinfo\\.php</url>
              <match>200</match>
              <description>HAKA: phpinfo.php accessed successfully — information disclosure</description>
              <group>haka,web,info_disclosure,T1592,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A8 - WordPress
    # -----------------------------------------------------------------------
    100570: {
        "id": 100570,
        "level": 12,
        "description": "HAKA: WordPress plugin exploitation attempt",
        "groups": ["haka", "web", "wordpress", "exploit", "T1190"],
        "mitre_id": "T1190",
        "category": "wordpress",
        "rule_xml": textwrap.dedent("""\
            <rule id="100570" level="12">
              <if_sid>31100</if_sid>
              <url>/wp-content/plugins/</url>
              <match>POST|PUT</match>
              <description>HAKA: WordPress plugin exploitation attempt — $(url)</description>
              <group>haka,web,wordpress,exploit,T1190,</group>
            </rule>"""),
    },
    100571: {
        "id": 100571,
        "level": 10,
        "description": "HAKA: WordPress XML-RPC brute force",
        "groups": ["haka", "web", "wordpress", "bruteforce", "T1110"],
        "mitre_id": "T1110",
        "category": "wordpress",
        "rule_xml": textwrap.dedent("""\
            <rule id="100571" level="10" frequency="15" timeframe="60">
              <if_matched_sid>31100</if_matched_sid>
              <url>/xmlrpc.php</url>
              <match>POST</match>
              <same_source_ip />
              <description>HAKA: WordPress XML-RPC brute force — 15+ POST requests in 60s from $(srcip)</description>
              <group>haka,web,wordpress,bruteforce,T1110,</group>
            </rule>"""),
    },
    100595: {
        "id": 100595,
        "level": 8,
        "description": "HAKA: WordPress user enumeration via REST/author",
        "groups": ["haka", "web", "wordpress", "enumeration", "T1589"],
        "mitre_id": "T1589",
        "category": "wordpress",
        "rule_xml": textwrap.dedent("""\
            <rule id="100595" level="8">
              <if_sid>31100</if_sid>
              <url>/wp-json/wp/v2/users|/?author=</url>
              <description>HAKA: WordPress user enumeration via REST API or author parameter</description>
              <group>haka,web,wordpress,enumeration,T1589,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A9 - cPanel / WHM
    # -----------------------------------------------------------------------
    100580: {
        "id": 100580,
        "level": 10,
        "description": "HAKA: cPanel/WHM brute force login attempts",
        "groups": ["haka", "web", "cpanel", "bruteforce", "T1110"],
        "mitre_id": "T1110",
        "category": "cpanel",
        "rule_xml": textwrap.dedent("""\
            <rule id="100580" level="10" frequency="10" timeframe="120">
              <if_matched_sid>31100</if_matched_sid>
              <url>/login/?login_only=1|:2087/login|:2083/login</url>
              <match>POST</match>
              <same_source_ip />
              <description>HAKA: cPanel/WHM brute force — 10+ login attempts from $(srcip) in 120s</description>
              <group>haka,web,cpanel,bruteforce,T1110,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A10 - Sensitive File Access
    # -----------------------------------------------------------------------
    100590: {
        "id": 100590,
        "level": 10,
        "description": "HAKA: Sensitive file access attempt",
        "groups": ["haka", "web", "sensitive_file", "T1083"],
        "mitre_id": "T1083",
        "category": "web",
        "rule_xml": textwrap.dedent("""\
            <rule id="100590" level="10">
              <if_sid>31100</if_sid>
              <url>\\.env$|\\.git/config|wp-config\\.php\\.bak|/etc/passwd|/etc/shadow|\\.htpasswd|web\\.config|\\.DS_Store</url>
              <description>HAKA: Sensitive file access attempt — $(url)</description>
              <group>haka,web,sensitive_file,T1083,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A11 - Cloud / S3
    # -----------------------------------------------------------------------
    100600: {
        "id": 100600,
        "level": 10,
        "description": "HAKA: S3 bucket external/anonymous access detected",
        "groups": ["haka", "cloud", "s3", "T1530"],
        "mitre_id": "T1530",
        "category": "cloud",
        "rule_xml": textwrap.dedent("""\
            <rule id="100600" level="10">
              <if_sid>80350</if_sid>
              <field name="aws.source">s3</field>
              <field name="aws.userIdentity.type">AWSAccount|Anonymous</field>
              <description>HAKA: S3 bucket accessed by external/anonymous identity — $(aws.s3.bucket)</description>
              <group>haka,cloud,s3,external_access,T1530,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A12 - Exchange Endpoint Scanning
    # -----------------------------------------------------------------------
    100610: {
        "id": 100610,
        "level": 8,
        "description": "HAKA: Exchange endpoint scanning/enumeration",
        "groups": ["haka", "exchange", "recon", "T1595"],
        "mitre_id": "T1595",
        "category": "exchange",
        "rule_xml": textwrap.dedent("""\
            <rule id="100610" level="8" frequency="5" timeframe="30">
              <if_matched_sid>31100</if_matched_sid>
              <url>/owa|/ecp|/ews|/oab|/autodiscover|/mapi|/rpc|/powershell|/Microsoft-Server-ActiveSync</url>
              <same_source_ip />
              <description>HAKA: Exchange endpoint scanning — 5+ Exchange URLs probed from $(srcip)</description>
              <group>haka,exchange,recon,T1595,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A13 - VPN Brute Force
    # -----------------------------------------------------------------------
    100620: {
        "id": 100620,
        "level": 10,
        "description": "HAKA: VPN brute force login attempts",
        "groups": ["haka", "vpn", "bruteforce", "T1110"],
        "mitre_id": "T1110",
        "category": "vpn",
        "rule_xml": textwrap.dedent("""\
            <rule id="100620" level="10" frequency="10" timeframe="120">
              <if_matched_sid>4716</if_matched_sid>
              <same_source_ip />
              <description>HAKA: VPN brute force — 10+ failed VPN logins from $(srcip) in 120s</description>
              <group>haka,vpn,bruteforce,T1110,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A14 - TLS Deprecation
    # -----------------------------------------------------------------------
    100630: {
        "id": 100630,
        "level": 8,
        "description": "HAKA: Deprecated TLS version in use (TLSv1.0/1.1/SSLv3)",
        "groups": ["haka", "tls", "crypto", "T1573"],
        "mitre_id": "T1573",
        "category": "tls",
        "rule_xml": textwrap.dedent("""\
            <rule id="100630" level="8">
              <if_sid>31100</if_sid>
              <field name="data.tls_version">TLSv1$|TLSv1\\.0|TLSv1\\.1|SSLv3</field>
              <description>HAKA: Deprecated TLS version $(data.tls_version) negotiated — weak cryptography</description>
              <group>haka,tls,crypto,deprecated,T1573,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A15 - Internal Hostname DNS Query
    # -----------------------------------------------------------------------
    100640: {
        "id": 100640,
        "level": 6,
        "description": "HAKA: Internal hostname leaked in external DNS query",
        "groups": ["haka", "dns", "info_leak", "T1590"],
        "mitre_id": "T1590",
        "category": "dns",
        "rule_xml": textwrap.dedent("""\
            <rule id="100640" level="6">
              <if_sid>12100</if_sid>
              <field name="data.query">\\.internal$|\\.local$|\\.corp$|\\.lan$|\\.home$</field>
              <description>HAKA: Internal hostname in DNS query — $(data.query) may leak internal topology</description>
              <group>haka,dns,info_leak,T1590,</group>
            </rule>"""),
    },

    # -----------------------------------------------------------------------
    # A16 - Mattermost
    # -----------------------------------------------------------------------
    100650: {
        "id": 100650,
        "level": 10,
        "description": "HAKA: Mattermost brute force login attempts",
        "groups": ["haka", "mattermost", "bruteforce", "T1110"],
        "mitre_id": "T1110",
        "category": "mattermost",
        "rule_xml": textwrap.dedent("""\
            <rule id="100650" level="10" frequency="10" timeframe="60">
              <if_matched_sid>31100</if_matched_sid>
              <url>/api/v4/users/login</url>
              <match>POST</match>
              <same_source_ip />
              <description>HAKA: Mattermost brute force — 10+ login attempts from $(srcip) in 60s</description>
              <group>haka,mattermost,bruteforce,T1110,</group>
            </rule>"""),
    },
    100651: {
        "id": 100651,
        "level": 12,
        "description": "HAKA: Mattermost config extraction attempt",
        "groups": ["haka", "mattermost", "config", "T1005"],
        "mitre_id": "T1005",
        "category": "mattermost",
        "rule_xml": textwrap.dedent("""\
            <rule id="100651" level="12">
              <if_sid>31100</if_sid>
              <url>/api/v4/config|/api/v4/config/client</url>
              <match>GET|200</match>
              <description>HAKA: Mattermost configuration extraction — $(url)</description>
              <group>haka,mattermost,config,T1005,</group>
            </rule>"""),
    },
    100652: {
        "id": 100652,
        "level": 8,
        "description": "HAKA: Mattermost sensitive keyword search",
        "groups": ["haka", "mattermost", "data_exfil", "T1213"],
        "mitre_id": "T1213",
        "category": "mattermost",
        "rule_xml": textwrap.dedent("""\
            <rule id="100652" level="8">
              <if_sid>31100</if_sid>
              <url>/api/v4/posts/search</url>
              <match>password|secret|token|credentials|api_key|private_key|ssh_key</match>
              <description>HAKA: Mattermost sensitive keyword search — possible data discovery</description>
              <group>haka,mattermost,data_exfil,T1213,</group>
            </rule>"""),
    },
}

# ---------------------------------------------------------------------------
# Category -> finding keyword mapping (for --from-scan)
# ---------------------------------------------------------------------------

FINDING_CATEGORY_MAP: Dict[str, List[int]] = {
    # keywords found in scan JSON -> rule IDs to generate
    "spf": [100501, 100502],
    "dmarc": [100501],
    "dkim": [100501],
    "email": [100501, 100502],
    "smtp": [100501, 100502],
    "vrfy": [100502],
    "expn": [100502],
    "dns": [100510, 100511, 100640],
    "axfr": [100510],
    "zone_transfer": [100510],
    "zone transfer": [100510],
    "ntlm": [100520],
    "relay": [100520],
    "rbcd": [100521],
    "delegation": [100521],
    "password_spray": [100530],
    "password spray": [100530],
    "spray": [100530],
    "owa": [100531, 100610],
    "exchange": [100540, 100541, 100610],
    "proxyshell": [100540],
    "proxy_shell": [100540],
    "webshell": [100541, 100560],
    "kerberoast": [100550, 100551],
    "kerberos": [100550, 100551, 100555],
    "asrep": [100555],
    "as-rep": [100555],
    "roast": [100550, 100551, 100555],
    "web": [100560, 100561, 100562, 100590],
    "upload": [100561],
    "phpinfo": [100562],
    "wordpress": [100570, 100571, 100595],
    "wp": [100570, 100571, 100595],
    "xmlrpc": [100571],
    "xml-rpc": [100571],
    "cpanel": [100580],
    "whm": [100580],
    "sensitive_file": [100590],
    "dotenv": [100590],
    ".env": [100590],
    "s3": [100600],
    "bucket": [100600],
    "cloud": [100600],
    "vpn": [100620],
    "tls": [100630],
    "ssl": [100630],
    "certificate": [100630],
    "mattermost": [100650, 100651, 100652],
    "user_enum": [100595],
    "enumeration": [100502, 100595],
}

# ---------------------------------------------------------------------------
# AI-mode pattern -> rule-generation templates
# ---------------------------------------------------------------------------

AI_PATTERNS: List[Dict[str, Any]] = [
    {
        "regex": re.compile(
            r"(\d+)\s+failed\s+(?:SSH|ssh)\s+login[s]?\s+.*?(\d+)\s*(?:second|minute|min|sec|s|m)",
            re.IGNORECASE,
        ),
        "extract": lambda m: {
            "frequency": int(m.group(1)),
            "timeframe": _parse_time(m.group(2), m.group(0)),
            "service": "ssh",
            "sid": "5710",
            "desc_prefix": "SSH brute force",
        },
    },
    {
        "regex": re.compile(
            r"(\d+)\s+failed\s+(?:RDP|rdp)\s+login[s]?\s+.*?(\d+)\s*(?:second|minute|min|sec|s|m)",
            re.IGNORECASE,
        ),
        "extract": lambda m: {
            "frequency": int(m.group(1)),
            "timeframe": _parse_time(m.group(2), m.group(0)),
            "service": "rdp",
            "sid": "60122",
            "desc_prefix": "RDP brute force",
        },
    },
    {
        "regex": re.compile(
            r"(\d+)\s+failed\s+(?:login|auth)[s]?\s+.*?(\d+)\s*(?:second|minute|min|sec|s|m)",
            re.IGNORECASE,
        ),
        "extract": lambda m: {
            "frequency": int(m.group(1)),
            "timeframe": _parse_time(m.group(2), m.group(0)),
            "service": "generic",
            "sid": "5503",
            "desc_prefix": "Authentication brute force",
        },
    },
    {
        "regex": re.compile(
            r"detect\s+(?:access|request)[s]?\s+to\s+(.+?)(?:\s+from|\s*$)",
            re.IGNORECASE,
        ),
        "extract": lambda m: {
            "url_match": m.group(1).strip().strip("\"'"),
            "service": "web_url",
            "sid": "31100",
            "desc_prefix": "Suspicious URL access",
        },
    },
    {
        "regex": re.compile(
            r"(\d+)\s+(?:request|connection|hit)[s]?\s+.*?(\d+)\s*(?:second|minute|min|sec|s|m)",
            re.IGNORECASE,
        ),
        "extract": lambda m: {
            "frequency": int(m.group(1)),
            "timeframe": _parse_time(m.group(2), m.group(0)),
            "service": "rate_limit",
            "sid": "31100",
            "desc_prefix": "Rate limit exceeded",
        },
    },
    {
        "regex": re.compile(
            r"detect\s+(.+)",
            re.IGNORECASE,
        ),
        "extract": lambda m: {
            "generic_match": m.group(1).strip(),
            "service": "generic_detect",
            "sid": "31100",
            "desc_prefix": "Custom detection",
        },
    },
]


def _parse_time(value: str, context: str) -> int:
    """Convert a time value + context to seconds."""
    val = int(value)
    ctx_lower = context.lower()
    if "minute" in ctx_lower or ctx_lower.rstrip().endswith("m"):
        return val * 60
    return val


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _color_init() -> None:
    colorama_init(autoreset=True)


def _banner() -> None:
    print(Fore.CYAN + BANNER.format(ver=VERSION) + Style.RESET_ALL)


def _info(msg: str) -> None:
    print(Fore.CYAN + "[*] " + Style.RESET_ALL + msg)


def _ok(msg: str) -> None:
    print(Fore.GREEN + "[+] " + Style.RESET_ALL + msg)


def _warn(msg: str) -> None:
    print(Fore.YELLOW + "[!] " + Style.RESET_ALL + msg)


def _err(msg: str) -> None:
    print(Fore.RED + "[-] " + Style.RESET_ALL + msg)


def _section(title: str) -> None:
    width = 70
    print()
    print(Fore.YELLOW + "=" * width)
    print(f"  {title}")
    print("=" * width + Style.RESET_ALL)


# ---------------------------------------------------------------------------
# XML generation / validation
# ---------------------------------------------------------------------------

def prettify_xml(xml_string: str) -> str:
    """Return a nicely indented XML string."""
    try:
        dom = xml.dom.minidom.parseString(xml_string)
        pretty = dom.toprettyxml(indent="  ", encoding=None)
        # Remove the XML declaration minidom adds
        lines = pretty.split("\n")
        if lines and lines[0].startswith("<?xml"):
            lines = lines[1:]
        return "\n".join(line for line in lines if line.strip())
    except Exception:
        return xml_string


def validate_rule_xml(xml_string: str) -> Tuple[bool, str]:
    """Validate that a rule XML fragment is well-formed."""
    wrapped = f"<group name='haka,'>{xml_string}</group>"
    try:
        ET.fromstring(wrapped)
        return True, "OK"
    except ET.ParseError as e:
        return False, str(e)


def build_combined_xml(rule_ids: List[int]) -> str:
    """Build a complete local_rules.xml from given rule IDs."""
    header = textwrap.dedent("""\
        <!-- HAKA AI - Wazuh Custom Detection Rules
             Generated: {ts}
             Rules: {count}
             Framework: HAKA AI v{ver}

             Deploy: cp local_rules.xml /var/ossec/etc/rules/
             Restart: systemctl restart wazuh-manager
        -->

        <group name="haka,">
        """).format(
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        count=len(rule_ids),
        ver=VERSION,
    )

    body_parts = []
    for rid in sorted(rule_ids):
        rule = HAKA_RULES.get(rid)
        if rule:
            body_parts.append(f"\n  <!-- Rule {rid}: {rule['description']} -->")
            # Indent rule_xml by 2 spaces for nesting inside <group>
            indented = "\n".join(
                "  " + line if line.strip() else line
                for line in rule["rule_xml"].split("\n")
            )
            body_parts.append(indented)

    footer = "\n</group>\n"
    return header + "\n".join(body_parts) + footer


def build_single_rule_xml(rule_id: int) -> str:
    """Wrap a single rule in a proper group element."""
    rule = HAKA_RULES.get(rule_id)
    if not rule:
        return ""
    return textwrap.dedent("""\
        <group name="haka,">
        {xml}
        </group>
        """).format(xml=rule["rule_xml"])


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def ensure_dirs() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    RULES_SUBDIR.mkdir(parents=True, exist_ok=True)


def write_rule_file(rule_id: int) -> Path:
    """Write a single rule to its own XML file. Returns the path."""
    path = RULES_SUBDIR / f"haka_rule_{rule_id}.xml"
    content = build_single_rule_xml(rule_id)
    valid, msg = validate_rule_xml(HAKA_RULES[rule_id]["rule_xml"])
    if not valid:
        _warn(f"Rule {rule_id} XML validation warning: {msg}")
    path.write_text(content, encoding="utf-8")
    return path


def write_combined_file(rule_ids: List[int]) -> Path:
    """Write the combined local_rules.xml. Returns the path."""
    content = build_combined_xml(rule_ids)
    COMBINED_RULES_FILE.write_text(content, encoding="utf-8")
    return COMBINED_RULES_FILE


def merge_with_existing(existing_path: Path, new_rule_ids: List[int]) -> str:
    """Merge new HAKA rules into an existing local_rules.xml.

    Strategy:
      - Parse existing file
      - Remove any existing HAKA rules (ids in our range)
      - Append new HAKA rules
      - Return merged XML string
    """
    if not existing_path.exists():
        return build_combined_xml(new_rule_ids)

    existing_content = existing_path.read_text(encoding="utf-8")

    # Extract non-HAKA content: remove our group block if present
    # We look for the HAKA group markers
    haka_start = re.compile(
        r'<group\s+name=["\']haka,?["\']>.*?</group>',
        re.DOTALL,
    )
    cleaned = haka_start.sub("", existing_content).strip()

    # Build new HAKA block
    haka_block = build_combined_xml(new_rule_ids)

    if cleaned:
        return cleaned + "\n\n" + haka_block
    return haka_block


# ---------------------------------------------------------------------------
# Documentation generator
# ---------------------------------------------------------------------------

def generate_documentation(rule_ids: List[int]) -> str:
    """Generate a text documentation block for the rules."""
    lines = [
        "=" * 72,
        "HAKA AI - Wazuh Detection Rules Documentation",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Total rules: {len(rule_ids)}",
        "=" * 72,
        "",
    ]

    for rid in sorted(rule_ids):
        rule = HAKA_RULES.get(rid)
        if not rule:
            continue
        lines.append(f"Rule ID:     {rule['id']}")
        lines.append(f"Level:       {rule['level']}")
        lines.append(f"Description: {rule['description']}")
        lines.append(f"MITRE ATT&CK: {rule.get('mitre_id', 'N/A')}")
        lines.append(f"Category:    {rule.get('category', 'N/A')}")
        lines.append(f"Groups:      {', '.join(rule['groups'])}")
        lines.append("-" * 50)
        lines.append("")

    lines.append("")
    lines.append("DEPLOYMENT INSTRUCTIONS")
    lines.append("-" * 50)
    lines.append("1. Copy local_rules.xml to the Wazuh manager:")
    lines.append("   cp local_rules.xml /var/ossec/etc/rules/local_rules.xml")
    lines.append("")
    lines.append("2. Validate the configuration:")
    lines.append("   /var/ossec/bin/wazuh-logtest")
    lines.append("")
    lines.append("3. Restart the Wazuh manager:")
    lines.append("   systemctl restart wazuh-manager")
    lines.append("")
    lines.append("4. Verify rules are loaded:")
    lines.append("   /var/ossec/bin/wazuh-logtest  (paste a test log)")
    lines.append("")
    lines.append("NOTE: Back up your existing local_rules.xml before deploying.")
    lines.append("      Use --deploy with an existing file to merge rules safely.")
    lines.append("=" * 72)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command: --generate-all
# ---------------------------------------------------------------------------

def cmd_generate_all(args: argparse.Namespace) -> None:
    """Generate all 24+ HAKA rules."""
    _section("GENERATING ALL HAKA WAZUH RULES")

    ensure_dirs()
    all_ids = sorted(HAKA_RULES.keys())

    _info(f"Generating {len(all_ids)} detection rules...")
    print()

    for rid in all_ids:
        rule = HAKA_RULES[rid]
        path = write_rule_file(rid)
        level_color = Fore.RED if rule["level"] >= 12 else (
            Fore.YELLOW if rule["level"] >= 8 else Fore.GREEN
        )
        print(
            f"  {Fore.WHITE}{rid}{Style.RESET_ALL}  "
            f"[{level_color}Level {rule['level']:>2}{Style.RESET_ALL}]  "
            f"{rule['description']}"
        )

    print()

    # Combined file
    combined_path = write_combined_file(all_ids)
    _ok(f"Combined rules: {combined_path}")

    # Individual files
    _ok(f"Individual rules: {RULES_SUBDIR}/haka_rule_*.xml")

    # Documentation
    doc = generate_documentation(all_ids)
    doc_path = RULES_SUBDIR / "RULES_DOCUMENTATION.txt"
    doc_path.write_text(doc, encoding="utf-8")
    _ok(f"Documentation: {doc_path}")

    # Summary
    _section("SUMMARY")
    print(f"  Total rules generated: {Fore.GREEN}{len(all_ids)}{Style.RESET_ALL}")
    print(f"  Output directory:      {RULES_SUBDIR}")
    print(f"  Combined file:         {combined_path}")
    print()
    print(f"  {Fore.YELLOW}Deploy:{Style.RESET_ALL}")
    print(f"    python {__file__} --deploy /var/ossec/etc/rules/")
    print(f"    {Fore.WHITE}or manually:{Style.RESET_ALL}")
    print(f"    cp {combined_path} /var/ossec/etc/rules/local_rules.xml")
    print(f"    systemctl restart wazuh-manager")
    print()

    # Severity breakdown
    crit = sum(1 for r in HAKA_RULES.values() if r["level"] >= 14)
    high = sum(1 for r in HAKA_RULES.values() if 10 <= r["level"] < 14)
    med = sum(1 for r in HAKA_RULES.values() if 6 <= r["level"] < 10)
    low = sum(1 for r in HAKA_RULES.values() if r["level"] < 6)
    print(f"  Severity breakdown:")
    print(f"    {Fore.RED}CRITICAL (14-15): {crit}{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}HIGH     (10-13): {high}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}MEDIUM   (6-9):   {med}{Style.RESET_ALL}")
    print(f"    {Fore.GREEN}LOW      (1-5):   {low}{Style.RESET_ALL}")
    print()


# ---------------------------------------------------------------------------
# Command: --from-scan
# ---------------------------------------------------------------------------

def cmd_from_scan(args: argparse.Namespace) -> None:
    """Generate rules from scan results JSON."""
    scan_path = Path(args.from_scan)
    if not scan_path.exists():
        _err(f"Scan file not found: {scan_path}")
        sys.exit(1)

    _section(f"GENERATING RULES FROM SCAN: {scan_path.name}")

    try:
        with open(scan_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    except json.JSONDecodeError as e:
        _err(f"Invalid JSON in {scan_path}: {e}")
        sys.exit(1)

    # Flatten scan data into a searchable text blob + structured findings
    matched_rule_ids: set = set()
    findings_text = json.dumps(scan_data).lower()

    # Strategy 1: keyword matching against the full JSON text
    for keyword, rule_ids in FINDING_CATEGORY_MAP.items():
        if keyword.lower() in findings_text:
            for rid in rule_ids:
                matched_rule_ids.add(rid)

    # Strategy 2: if the JSON has a "findings" or "results" list, inspect each
    findings_list = []
    if isinstance(scan_data, dict):
        for key in ("findings", "results", "vulnerabilities", "checks", "issues"):
            if key in scan_data and isinstance(scan_data[key], list):
                findings_list.extend(scan_data[key])
        # Also handle flat dict with "category" or "type"
        if "category" in scan_data:
            findings_list.append(scan_data)
    elif isinstance(scan_data, list):
        findings_list = scan_data

    for finding in findings_list:
        if not isinstance(finding, dict):
            continue
        finding_text = json.dumps(finding).lower()
        for keyword, rule_ids in FINDING_CATEGORY_MAP.items():
            if keyword.lower() in finding_text:
                for rid in rule_ids:
                    matched_rule_ids.add(rid)

        # Check severity to influence rule selection
        severity = str(finding.get("severity", finding.get("risk", ""))).upper()
        if severity in ("CRITICAL", "HIGH"):
            # For high-severity findings, also add related rules
            category = str(finding.get("category", finding.get("type", ""))).lower()
            for keyword, rule_ids in FINDING_CATEGORY_MAP.items():
                if keyword in category:
                    for rid in rule_ids:
                        matched_rule_ids.add(rid)

    if not matched_rule_ids:
        _warn("No matching HAKA rules found for this scan data.")
        _info("Generating all rules as a baseline...")
        matched_rule_ids = set(HAKA_RULES.keys())

    ensure_dirs()
    sorted_ids = sorted(matched_rule_ids)

    _info(f"Matched {len(sorted_ids)} rules from scan findings:")
    print()

    for rid in sorted_ids:
        rule = HAKA_RULES.get(rid)
        if not rule:
            continue
        write_rule_file(rid)
        level_color = Fore.RED if rule["level"] >= 12 else (
            Fore.YELLOW if rule["level"] >= 8 else Fore.GREEN
        )
        print(
            f"  {Fore.WHITE}{rid}{Style.RESET_ALL}  "
            f"[{level_color}Level {rule['level']:>2}{Style.RESET_ALL}]  "
            f"{rule['description']}"
        )

    print()
    combined_path = write_combined_file(sorted_ids)
    _ok(f"Combined rules: {combined_path}")
    _ok(f"Individual rules: {RULES_SUBDIR}/")

    # Documentation
    doc = generate_documentation(sorted_ids)
    doc_path = RULES_SUBDIR / "RULES_DOCUMENTATION.txt"
    doc_path.write_text(doc, encoding="utf-8")
    _ok(f"Documentation: {doc_path}")
    print()


# ---------------------------------------------------------------------------
# Command: --custom (AI mode)
# ---------------------------------------------------------------------------

def cmd_custom(args: argparse.Namespace) -> None:
    """Generate a custom rule from free-text description."""
    description = args.custom
    _section("AI-POWERED CUSTOM RULE GENERATION")
    _info(f'Input: "{description}"')
    print()

    generated = False
    next_id = 100700  # Custom rules start at 100700

    for pattern_def in AI_PATTERNS:
        match = pattern_def["regex"].search(description)
        if match:
            params = pattern_def["extract"](match)
            rule_xml = _build_custom_rule(next_id, params, description)
            if rule_xml:
                generated = True
                _ok("Generated custom Wazuh rule:")
                print()
                print(Fore.GREEN + rule_xml + Style.RESET_ALL)
                print()

                # Validate
                valid, msg = validate_rule_xml(rule_xml)
                if valid:
                    _ok("XML validation: PASSED")
                else:
                    _warn(f"XML validation warning: {msg}")

                # Save
                ensure_dirs()
                custom_path = RULES_SUBDIR / f"haka_custom_{next_id}.xml"
                wrapped = f'<group name="haka,custom,">\n{rule_xml}\n</group>\n'
                custom_path.write_text(wrapped, encoding="utf-8")
                _ok(f"Saved to: {custom_path}")
                print()
                break

    if not generated:
        _warn("Could not parse a specific pattern from the description.")
        _info("Generating a generic match rule...")
        print()

        # Fallback: generate a generic match rule
        # Extract key words from description
        keywords = _extract_keywords(description)
        rule_xml = textwrap.dedent(f"""\
            <rule id="{next_id}" level="8">
              <if_sid>31100</if_sid>
              <match>{"|".join(keywords)}</match>
              <description>HAKA Custom: {_sanitize_xml(description[:120])}</description>
              <group>haka,custom,</group>
            </rule>""")

        _ok("Generated generic Wazuh rule:")
        print()
        print(Fore.GREEN + rule_xml + Style.RESET_ALL)
        print()

        ensure_dirs()
        custom_path = RULES_SUBDIR / f"haka_custom_{next_id}.xml"
        wrapped = f'<group name="haka,custom,">\n{rule_xml}\n</group>\n'
        custom_path.write_text(wrapped, encoding="utf-8")
        _ok(f"Saved to: {custom_path}")
        print()


def _build_custom_rule(rule_id: int, params: Dict[str, Any], description: str) -> Optional[str]:
    """Build rule XML from extracted parameters."""
    service = params.get("service", "generic")

    if service in ("ssh", "rdp", "generic"):
        freq = params["frequency"]
        tf = params["timeframe"]
        sid = params["sid"]
        prefix = params["desc_prefix"]
        svc_upper = service.upper()

        return textwrap.dedent(f"""\
            <rule id="{rule_id}" level="10" frequency="{freq}" timeframe="{tf}">
              <if_matched_sid>{sid}</if_matched_sid>
              <same_source_ip />
              <description>HAKA Custom: {prefix} — {freq}+ failed {svc_upper} logins from $(srcip) in {tf}s</description>
              <group>haka,custom,{service},bruteforce,T1110,</group>
            </rule>""")

    elif service == "web_url":
        url = params["url_match"]
        sid = params["sid"]
        prefix = params["desc_prefix"]
        return textwrap.dedent(f"""\
            <rule id="{rule_id}" level="10">
              <if_sid>{sid}</if_sid>
              <url>{_sanitize_xml(url)}</url>
              <description>HAKA Custom: {prefix} — access to {_sanitize_xml(url)}</description>
              <group>haka,custom,web,access,</group>
            </rule>""")

    elif service == "rate_limit":
        freq = params["frequency"]
        tf = params["timeframe"]
        sid = params["sid"]
        prefix = params["desc_prefix"]
        return textwrap.dedent(f"""\
            <rule id="{rule_id}" level="10" frequency="{freq}" timeframe="{tf}">
              <if_matched_sid>{sid}</if_matched_sid>
              <same_source_ip />
              <description>HAKA Custom: {prefix} — {freq}+ hits from $(srcip) in {tf}s</description>
              <group>haka,custom,rate_limit,</group>
            </rule>""")

    elif service == "generic_detect":
        keywords = _extract_keywords(params.get("generic_match", description))
        return textwrap.dedent(f"""\
            <rule id="{rule_id}" level="8">
              <if_sid>31100</if_sid>
              <match>{"|".join(keywords)}</match>
              <description>HAKA Custom: {_sanitize_xml(description[:120])}</description>
              <group>haka,custom,</group>
            </rule>""")

    return None


def _extract_keywords(text: str) -> List[str]:
    """Extract meaningful keywords from free text for rule matching."""
    stop_words = {
        "detect", "the", "a", "an", "from", "same", "ip", "in",
        "and", "or", "to", "for", "with", "that", "this", "is",
        "are", "was", "be", "been", "being", "of", "at", "by",
        "on", "if", "when", "where", "who", "what", "which",
    }
    words = re.findall(r'[a-zA-Z0-9_/\\.]+', text.lower())
    keywords = [w for w in words if w not in stop_words and len(w) > 2]
    # Deduplicate while preserving order
    seen: set = set()
    unique = []
    for kw in keywords:
        if kw not in seen:
            seen.add(kw)
            unique.append(kw)
    return unique[:8] if unique else ["custom_match"]


def _sanitize_xml(text: str) -> str:
    """Escape XML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


# ---------------------------------------------------------------------------
# Command: --deploy
# ---------------------------------------------------------------------------

def cmd_deploy(args: argparse.Namespace) -> None:
    """Deploy generated rules to Wazuh rules directory."""
    deploy_dir = Path(args.deploy)
    _section("DEPLOYING HAKA RULES TO WAZUH")

    if not COMBINED_RULES_FILE.exists():
        _warn("No combined rules file found. Generating all rules first...")
        args_copy = copy.copy(args)
        cmd_generate_all(args_copy)

    if not deploy_dir.exists():
        _err(f"Deploy directory does not exist: {deploy_dir}")
        _info("Create it or specify a valid Wazuh rules directory.")
        sys.exit(1)

    target_file = deploy_dir / "local_rules.xml"

    # Check if existing file needs merging
    if target_file.exists():
        _warn(f"Existing local_rules.xml found at {target_file}")
        _info("Merging HAKA rules with existing rules...")

        merged_content = merge_with_existing(
            target_file, sorted(HAKA_RULES.keys())
        )

        # Backup existing
        backup_path = target_file.with_suffix(
            f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        shutil.copy2(target_file, backup_path)
        _ok(f"Backup created: {backup_path}")

        target_file.write_text(merged_content, encoding="utf-8")
        _ok(f"Merged rules written to: {target_file}")
    else:
        shutil.copy2(COMBINED_RULES_FILE, target_file)
        _ok(f"Rules deployed to: {target_file}")

    print()
    _info("Next steps:")
    print(f"  1. Validate: /var/ossec/bin/wazuh-logtest")
    print(f"  2. Restart:  systemctl restart wazuh-manager")
    print(f"  3. Verify:   tail -f /var/ossec/logs/alerts/alerts.json")
    print()


# ---------------------------------------------------------------------------
# Command: --list
# ---------------------------------------------------------------------------

def cmd_list_rules(args: argparse.Namespace) -> None:
    """List all available HAKA rules."""
    _section("HAKA WAZUH RULE CATALOG")

    # Group by category
    categories: Dict[str, List[Dict]] = {}
    for rule in HAKA_RULES.values():
        cat = rule.get("category", "other")
        categories.setdefault(cat, []).append(rule)

    cat_labels = {
        "email": "Email Security (A1)",
        "dns": "DNS Reconnaissance (A2)",
        "ad": "Active Directory / NTLM / Kerberos (A3/A6)",
        "auth": "Authentication Attacks (A4)",
        "exchange": "Exchange Server (A5/A12)",
        "web": "Web Application (A7/A10)",
        "wordpress": "WordPress (A8)",
        "cpanel": "cPanel / WHM (A9)",
        "cloud": "Cloud / S3 (A11)",
        "vpn": "VPN (A13)",
        "tls": "TLS / Cryptography (A14)",
        "mattermost": "Mattermost (A16)",
    }

    total = 0
    for cat in [
        "email", "dns", "ad", "auth", "exchange",
        "web", "wordpress", "cpanel", "cloud", "vpn",
        "tls", "mattermost",
    ]:
        rules = categories.get(cat, [])
        if not rules:
            continue

        label = cat_labels.get(cat, cat.title())
        print(f"\n  {Fore.CYAN}{label}{Style.RESET_ALL}")
        print(f"  {'-' * 60}")

        for rule in sorted(rules, key=lambda r: r["id"]):
            level_color = Fore.RED if rule["level"] >= 12 else (
                Fore.YELLOW if rule["level"] >= 8 else Fore.GREEN
            )
            mitre = rule.get("mitre_id", "")
            print(
                f"    {Fore.WHITE}{rule['id']}{Style.RESET_ALL}  "
                f"[{level_color}L{rule['level']:>2}{Style.RESET_ALL}]  "
                f"{rule['description']:<60}  "
                f"{Fore.MAGENTA}{mitre}{Style.RESET_ALL}"
            )
            total += 1

    print(f"\n  {Fore.GREEN}Total rules: {total}{Style.RESET_ALL}\n")


# ---------------------------------------------------------------------------
# Command: --show <rule_id>
# ---------------------------------------------------------------------------

def cmd_show_rule(args: argparse.Namespace) -> None:
    """Show detailed info and XML for a specific rule."""
    rule_id = args.show
    rule = HAKA_RULES.get(rule_id)

    if not rule:
        _err(f"Rule {rule_id} not found. Use --list to see available rules.")
        sys.exit(1)

    _section(f"RULE {rule_id} DETAILS")

    print(f"  ID:          {Fore.WHITE}{rule['id']}{Style.RESET_ALL}")
    print(f"  Level:       {rule['level']}")
    print(f"  Description: {rule['description']}")
    print(f"  MITRE:       {rule.get('mitre_id', 'N/A')}")
    print(f"  Category:    {rule.get('category', 'N/A')}")
    print(f"  Groups:      {', '.join(rule['groups'])}")
    print()

    print(f"  {Fore.CYAN}Rule XML:{Style.RESET_ALL}")
    print()
    for line in rule["rule_xml"].split("\n"):
        print(f"    {Fore.GREEN}{line}{Style.RESET_ALL}")
    print()

    # Validate
    valid, msg = validate_rule_xml(rule["rule_xml"])
    if valid:
        _ok("XML validation: PASSED")
    else:
        _warn(f"XML validation: {msg}")
    print()


# ---------------------------------------------------------------------------
# Command: --validate
# ---------------------------------------------------------------------------

def cmd_validate(args: argparse.Namespace) -> None:
    """Validate all rule templates."""
    _section("VALIDATING ALL HAKA RULE TEMPLATES")

    passed = 0
    failed = 0

    for rid in sorted(HAKA_RULES.keys()):
        rule = HAKA_RULES[rid]
        valid, msg = validate_rule_xml(rule["rule_xml"])
        if valid:
            print(
                f"  {Fore.GREEN}PASS{Style.RESET_ALL}  "
                f"{rid}  {rule['description'][:60]}"
            )
            passed += 1
        else:
            print(
                f"  {Fore.RED}FAIL{Style.RESET_ALL}  "
                f"{rid}  {rule['description'][:60]}"
            )
            print(f"         {Fore.RED}{msg}{Style.RESET_ALL}")
            failed += 1

    print()
    _ok(f"Passed: {passed}")
    if failed:
        _err(f"Failed: {failed}")
    else:
        _ok("All rules validated successfully.")
    print()


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="haka_wazuh_ai",
        description=(
            "HAKA AI - Wazuh Rule Generator (Tool 12)\n"
            "AI-powered detection rule engine for the HAKA framework.\n"
            "Generates Wazuh custom rules from scan results or free-text descriptions."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s --generate-all
              %(prog)s --from-scan email_scan.json
              %(prog)s --custom "Detect 5 failed RDP logins in 60 seconds from same IP"
              %(prog)s --deploy /var/ossec/etc/rules/
              %(prog)s --list
              %(prog)s --show 100540
              %(prog)s --validate
        """),
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--generate-all",
        action="store_true",
        help="Generate all pre-built HAKA detection rules",
    )
    group.add_argument(
        "--from-scan",
        metavar="FILE",
        help="Generate rules from HAKA scan results JSON",
    )
    group.add_argument(
        "--custom",
        metavar="TEXT",
        help='AI-mode: generate rule from free-text (e.g., "Detect 10 failed SSH logins in 2 minutes")',
    )
    group.add_argument(
        "--deploy",
        metavar="PATH",
        help="Deploy generated rules to Wazuh rules directory",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List all available HAKA rule templates",
    )
    group.add_argument(
        "--show",
        metavar="RULE_ID",
        type=int,
        help="Show detailed info for a specific rule ID",
    )
    group.add_argument(
        "--validate",
        action="store_true",
        help="Validate all rule template XML structures",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress banner output",
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    _color_init()
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        _banner()

    if args.generate_all:
        cmd_generate_all(args)
    elif args.from_scan:
        cmd_from_scan(args)
    elif args.custom:
        cmd_custom(args)
    elif args.deploy:
        cmd_deploy(args)
    elif args.list:
        cmd_list_rules(args)
    elif args.show is not None:
        cmd_show_rule(args)
    elif args.validate:
        cmd_validate(args)


if __name__ == "__main__":
    main()
