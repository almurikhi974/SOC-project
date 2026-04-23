"""
tools.py — SOC Analyst AI Agent: Investigative Tools
All tools are LangChain @tool-decorated functions with mock data.
Each tool is structured for easy replacement with real APIs.
"""

import json
import re
import base64
import hashlib
import html
from datetime import datetime, timezone
from urllib.parse import unquote_plus
from langchain_core.tools import tool


# ---------------------------------------------------------------------------
# Shared Mock Data
# ---------------------------------------------------------------------------

# Known malicious / high-risk IPs (shared across ip tools)
_KNOWN_IP_PROFILES = {
    "45.133.1.22":   {"risk_score": 92, "categories": ["scanner", "sql_injection"], "country": "Russia", "country_code": "RU", "city": "Moscow", "isp": "Frantech Solutions", "asn": "AS59642", "asn_type": "hosting", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "103.205.12.99": {"risk_score": 97, "categories": ["c2_server", "malware"], "country": "China", "country_code": "CN", "city": "Shenzhen", "isp": "Alibaba Cloud", "asn": "AS37963", "asn_type": "hosting", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "8.8.8.8":       {"risk_score": 0,  "categories": ["trusted"], "country": "United States", "country_code": "US", "city": "Mountain View", "isp": "Google LLC", "asn": "AS15169", "asn_type": "tech_giant", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "1.1.1.1":       {"risk_score": 0,  "categories": ["trusted"], "country": "Australia", "country_code": "AU", "city": "Sydney", "isp": "Cloudflare", "asn": "AS13335", "asn_type": "cdn", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "185.220.101.50":{"risk_score": 99, "categories": ["tor_exit", "scanner"], "country": "Germany", "country_code": "DE", "city": "Frankfurt", "isp": "Tor Project", "asn": "AS60729", "asn_type": "tor", "is_datacenter": False, "is_tor": True, "is_vpn": False},
    "198.51.100.55": {"risk_score": 85, "categories": ["brute_force", "credential_stuffing"], "country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "isp": "DigitalOcean", "asn": "AS14061", "asn_type": "hosting", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "91.108.4.0":    {"risk_score": 45, "categories": ["suspicious"], "country": "Seychelles", "country_code": "SC", "city": "Victoria", "isp": "Unknown VPN Provider", "asn": "AS62041", "asn_type": "vpn", "is_datacenter": False, "is_tor": False, "is_vpn": True},
    "archive.ubuntu.com": {"risk_score": 0, "categories": ["trusted", "package_repo"], "country": "United Kingdom", "country_code": "GB", "city": "London", "isp": "Canonical Ltd", "asn": "AS41231", "asn_type": "tech_company", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "45.77.65.200":       {"risk_score": 90, "categories": ["c2_server", "reverse_shell"], "country": "United States", "country_code": "US", "city": "Los Angeles", "isp": "Vultr Holdings", "asn": "AS20473", "asn_type": "hosting", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "172.217.14.99":      {"risk_score": 0,  "categories": ["trusted"], "country": "United States", "country_code": "US", "city": "Mountain View", "isp": "Google LLC", "asn": "AS15169", "asn_type": "tech_giant", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "198.51.100.44":      {"risk_score": 5,  "categories": ["residential_isp"], "country": "United States", "country_code": "US", "city": "Dallas", "isp": "Comcast Cable", "asn": "AS7922", "asn_type": "isp", "is_datacenter": False, "is_tor": False, "is_vpn": False},
    # Microsoft infrastructure IPs (Windows Update, Azure AD, M365)
    "52.14.88.200":       {"risk_score": 0,  "categories": ["trusted", "microsoft_cdn"], "country": "United States", "country_code": "US", "city": "Redmond", "isp": "Microsoft Corporation", "asn": "AS8075", "asn_type": "tech_giant", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "40.126.1.145":       {"risk_score": 0,  "categories": ["trusted", "microsoft_azure"], "country": "United States", "country_code": "US", "city": "Redmond", "isp": "Microsoft Corporation", "asn": "AS8075", "asn_type": "tech_giant", "is_datacenter": True, "is_tor": False, "is_vpn": False},
    "203.0.113.10":       {"risk_score": 0,  "categories": ["trusted", "documentation_range"], "country": "United States", "country_code": "US", "city": "Unknown", "isp": "Reserved Documentation Range", "asn": "AS0", "asn_type": "documentation", "is_datacenter": False, "is_tor": False, "is_vpn": False},
}

# RFC1918 private ranges
_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                     "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
                     "127.")

# 169.254.169.254 is the AWS/cloud metadata endpoint — NOT a safe internal IP
_SSRF_IPS = {"169.254.169.254"}

# Known C2 IPs (shared with traffic analysis)
_C2_IPS = {"103.205.12.99", "185.220.101.50", "45.142.212.100", "91.92.136.0",
            "194.165.16.78", "5.188.206.14"}

EXPECTED_REGIONS = {"US", "GB", "DE", "JP", "AU", "CA", "FR"}

# Attack pattern regexes for decode_payload
_ATTACK_PATTERNS = [
    ("SQL_INJECTION_BOOLEAN",   r"'\s*OR\s*'1'\s*=\s*'1|'\s*OR\s*1\s*=\s*1|--\s*$",                 "critical"),
    ("SQL_INJECTION_UNION",     r"UNION\s+(ALL\s+)?SELECT",                                             "critical"),
    ("SQL_INJECTION_SLEEP",     r"(SLEEP|WAITFOR\s+DELAY|BENCHMARK)\s*\(",                              "critical"),
    ("XSS_SCRIPT",              r"<script[\s>]|javascript\s*:|on\w+\s*=",                               "high"),
    ("XSS_EVENT_HANDLER",       r"onerror\s*=|onload\s*=|onclick\s*=",                                 "high"),
    ("PATH_TRAVERSAL",          r"\.\./|\.\.\\|%2e%2e",                                                "high"),
    ("COMMAND_INJECTION",       r";\s*(cat|ls|id|whoami|wget|curl|bash|sh)\s|&&\s*(cat|ls|id|whoami)", "critical"),
    ("LDAP_INJECTION",          r"\*\)\(|\)\(|\(\|",                                                   "medium"),
    ("SSRF_ATTEMPT",            r"(http|https|ftp|file|dict|gopher)://.*?(169\.254|127\.0|0\.0\.0\.0)","high"),
    ("LOG4SHELL",               r"\$\{jndi:",                                                           "critical"),
    ("POWERSHELL_CRADLE",       r"IEX\s*\(|Invoke-Expression|DownloadString|Net\.WebClient",           "critical"),
    ("BASE64_PAYLOAD",          r"[A-Za-z0-9+/]{40,}={0,2}",                                          "info"),
    ("CURL_PIPE_BASH",          r"curl\s+.*\|\s*(bash|sh)\b",                                          "critical"),
    ("BULK_DB_DUMP",            r"SELECT\s+\*\s+FROM\s+\w+\s*;?\s*(--|$)",                            "high"),
    ("PASSWORD_HASH_EXTRACT",   r"password_hash|security_answer|security_question",                    "critical"),
    ("WEB_PATH_SCAN",           r"wp-admin|phpmyadmin|manager/html|\.env|config\.php|/admin.*paths",  "high"),
    ("ICMP_SUBNET_SWEEP",       r"ICMP.*\d+\.\d+\.\d+\.\d+-\d+.*\d+\s*hosts|\d+\s*hosts\s*in\s*\d+\s*second", "high"),
    ("SSHD_WEAKENING",          r"PermitRootLogin.*yes|PasswordAuthentication.*yes|MaxAuthTries.*\b[5-9]\d\b", "critical"),
    ("BEACON_PATTERN",          r"every\s+\d+\s*s(econds?)?.*\d+\s*(hour|min)|constant.*\d+\s*byte", "high"),
    ("EXFIL_PASTE_SERVICE",     r"paste\.ee|pastebin\.com|hastebin|ghostbin|dpaste",                  "critical"),
    ("CREDENTIAL_IN_PATH",      r"/iam/security-credentials|meta-data.*credentials",                  "critical"),
    ("IMDSV2_TOKEN",            r"x-aws-ec2-metadata-token:\s*\w+",                                   "info"),
    ("SSH_PASSWORD_AUTH",       r"Accepted\s+password\s+for\s+\w+",                                   "medium"),
    ("HIDDEN_CLONE_PATH",       r"git.*clone.*(/tmp/\.|\.cache/[^/]*fonts|hidden)",                   "high"),
    ("JWT_ROLE_MISMATCH",       r"role.*user.*admin|/export|/admin.*role.*user",                      "high"),
    ("CERTUTIL_URLCACHE",       r"certutil.*-urlcache|-urlcache.*certutil",                            "critical"),
    ("CERTUTIL_LEGIT",          r"certutil.*-verifyctl|AuthRootCAUpdate",                              "info"),
    ("OFF_HOURS_PASSWORD_AUTH", r"Accepted\s+password.*\b(0[0-6]|23):\d\d|03:\d\d.*Accepted\s+password", "high"),
    ("BULK_ROW_EXTRACTION",     r"returned\s+[\d,]{6,}\s*rows|[\d,]{6,}\s*rows\s*returned",           "critical"),
    ("WDIGEST_ENABLE",          r"UseLogonCredential.*DWORD\(1\)|WDigest.*UseLogon",                   "critical"),
    ("SSHCONFIG_WEAKEN",        r"PermitRootLogin.*yes|MaxAuthTries.*\b[5-9]\d\b",                     "critical"),
    ("GIT_HIDDEN_STAGING",      r"git.*clone.*/tmp/\.|\.cache/fonts|infrastructure.*\.git.*/tmp",      "high"),
    ("JWT_PRIV_ESC",            r"role.*['\"]user['\"].*export|/api.*export.*role.*user|eyJ.*role.*user.*export", "high"),
    ("ADMIN_EXPORT_50K",        r"Records:\s*\d{4,}|export.*\d{4,}\s*records",                        "high"),
    ("APP_LOG_ROTATION",        r"LogName=Application.*LogArchive|svc_logrotate|log.*archived.*evtx", "info"),
    ("IMDSV2_LEGITIMATE",       r"X-aws-ec2-metadata-token:\s*\w+.*credential-refresher|credential-refresher.*IMDSv2", "info"),
    ("WWW_DATA_PRIVILEGE",      r"www-data.*authorized_keys|authorized_keys.*www-data|www-data.*nmap|nmap.*www-data|www-data.*apt|apt.*www-data", "critical"),
    ("SECURITY_LOG_CLEARED",    r"LogName=Security.*audit log.*cleared|EventID=1102.*LogName=Security|audit log was cleared.*Subject:\s*admin", "critical"),
    ("SERVICE_IN_PROGRAMDATA",  r"EventID=7045.*ProgramData|ImagePath=.*\\ProgramData\\|ServiceName=.*Helper.*ImagePath.*ProgramData", "critical"),
    ("SQL_ADMIN_EMAIL_HIJACK",  r"UPDATE\s+users\s+SET\s+email=.*WHERE\s+username=.*admin|migration_svc.*UPDATE.*admin", "critical"),
    ("ICMP_INTERNAL_SWEEP",     r"ICMP.*Echo.*Request.*\d+\.\d+\.\d+\.\d+.*-\s*254|\d{3,}\s*hosts\s*in\s*\d+\s*second", "high"),
    ("HIDDEN_STAGING_PATH",     r"clone.*(/tmp/\.|/tmp/\.\w+|\.cache/fonts)|infrastructure.*git.*/tmp\.", "high"),
    ("SMB_ADMIN_SHARE_WRITE",   r"\\\\[^\\]+\\[Cc]\$\\Windows\\Temp|\\\\[^\\]+\\ADMIN\$.*\.exe|Write Request.*\\[Cc]\$\\", "critical"),
    ("SC_DRIVER_DROP",          r"EventID=11.*System32\\drivers\\.*\.sys|TargetFilename.*System32\\drivers.*Process.*sc\.exe|FileCreate.*drivers\\.*\.sys.*sc\.exe", "critical"),
]

# Known attack signatures knowledge base
_ATTACK_SIGNATURES = {
    "sqlmap":            {"name": "sqlmap", "category": "automated_sql_injection_tool", "severity": "critical", "description": "sqlmap automates SQL injection exploitation.", "cve_refs": ["CVE-2019-7401"], "mitre": "T1190"},
    "nmap":              {"name": "Nmap", "category": "network_scanner", "severity": "medium", "description": "Network discovery and security auditing tool.", "cve_refs": [], "mitre": "T1046"},
    "nikto":             {"name": "Nikto", "category": "web_vulnerability_scanner", "severity": "high", "description": "Web server scanner for dangerous files and outdated software.", "cve_refs": [], "mitre": "T1595"},
    "masscan":           {"name": "Masscan", "category": "mass_port_scanner", "severity": "high", "description": "Internet-scale port scanner.", "cve_refs": [], "mitre": "T1046"},
    "metasploit":        {"name": "Metasploit", "category": "exploit_framework", "severity": "critical", "description": "Penetration testing framework used to develop and execute exploits.", "cve_refs": [], "mitre": "T1203"},
    "cobalt strike":     {"name": "Cobalt Strike", "category": "c2_framework", "severity": "critical", "description": "Commercial C2 framework commonly used by threat actors post-compromise.", "cve_refs": [], "mitre": "T1219"},
    "meterpreter":       {"name": "Meterpreter", "category": "c2_payload", "severity": "critical", "description": "Metasploit payload providing interactive shell with advanced capabilities.", "cve_refs": [], "mitre": "T1059"},
    "mimikatz":          {"name": "Mimikatz", "category": "credential_dumper", "severity": "critical", "description": "Tool for extracting credentials from Windows memory.", "cve_refs": [], "mitre": "T1003"},
    "hydra":             {"name": "Hydra", "category": "brute_force_tool", "severity": "high", "description": "Fast network login cracker.", "cve_refs": [], "mitre": "T1110"},
    "medusa":            {"name": "Medusa", "category": "brute_force_tool", "severity": "high", "description": "Speedy parallel network logon brute-forcer.", "cve_refs": [], "mitre": "T1110"},
    "burpsuite":         {"name": "Burp Suite", "category": "web_proxy_scanner", "severity": "medium", "description": "Web application security testing platform.", "cve_refs": [], "mitre": "T1595"},
    "cve-2021-44228":    {"name": "Log4Shell", "category": "rce_exploit", "severity": "critical", "description": "Remote code execution via JNDI lookup in Log4j 2.x.", "cve_refs": ["CVE-2021-44228"], "mitre": "T1190"},
    "cve-2021-41773":    {"name": "Apache Path Traversal", "category": "path_traversal_rce", "severity": "critical", "description": "Path traversal and RCE in Apache HTTP Server 2.4.49.", "cve_refs": ["CVE-2021-41773"], "mitre": "T1190"},
    "cve-2021-26855":    {"name": "ProxyLogon", "category": "rce_exploit", "severity": "critical", "description": "Microsoft Exchange Server SSRF leading to RCE.", "cve_refs": ["CVE-2021-26855"], "mitre": "T1190"},
    "cve-2017-0144":     {"name": "EternalBlue", "category": "rce_exploit", "severity": "critical", "description": "SMB vulnerability exploited by WannaCry and NotPetya.", "cve_refs": ["CVE-2017-0144"], "mitre": "T1210"},
    "iex":               {"name": "PowerShell Download Cradle", "category": "malicious_powershell", "severity": "critical", "description": "PowerShell IEX used to download and execute remote payloads in-memory.", "cve_refs": [], "mitre": "T1059.001"},
    "invoke-expression": {"name": "PowerShell Invoke-Expression", "category": "malicious_powershell", "severity": "high", "description": "PowerShell execution of arbitrary strings, often used for obfuscated payloads.", "cve_refs": [], "mitre": "T1059.001"},
    "net.webclient":     {"name": "PowerShell WebClient", "category": "malicious_powershell", "severity": "high", "description": "PowerShell download of remote content, commonly used in dropper chains.", "cve_refs": [], "mitre": "T1105"},
    "${jndi:":           {"name": "Log4Shell JNDI Trigger", "category": "rce_exploit", "severity": "critical", "description": "JNDI lookup string that triggers Log4Shell (CVE-2021-44228).", "cve_refs": ["CVE-2021-44228"], "mitre": "T1190"},
    "lsass":             {"name": "LSASS Memory Dump", "category": "credential_access", "severity": "critical", "description": "Access to LSASS process for credential extraction.", "cve_refs": [], "mitre": "T1003.001"},
    "whoami":            {"name": "Whoami Discovery", "category": "system_discovery", "severity": "medium", "description": "System enumeration command often run post-compromise.", "cve_refs": [], "mitre": "T1033"},
    "net user /add":     {"name": "Backdoor Account Creation", "category": "persistence", "severity": "critical", "description": "Creating a new local user account for persistence.", "cve_refs": [], "mitre": "T1136"},
    "reg add":           {"name": "Registry Run Key", "category": "persistence", "severity": "high", "description": "Adding registry run keys for startup persistence.", "cve_refs": [], "mitre": "T1547.001"},
    "schtasks":          {"name": "Scheduled Task", "category": "persistence", "severity": "high", "description": "Creating scheduled tasks for persistence or lateral movement.", "cve_refs": [], "mitre": "T1053.005"},

    # LOLBins (Living off the Land Binaries)
    "certutil -urlcache":{"name": "Certutil LOLBin Download", "category": "lolbin_download", "severity": "critical", "description": "certutil -urlcache -split -f downloads remote files while evading AV/EDR. Malicious use of certutil.", "cve_refs": [], "mitre": "T1105"},
    "certutil -verifyctl":{"name": "Certutil Root Cert Update (Legitimate)", "category": "legitimate_system_operation", "severity": "info", "description": "certutil -verifyctl updating Windows root certificate trust list. When spawned by svchost.exe, this is the legitimate Windows automatic root certificate update mechanism — NOT malicious.", "cve_refs": [], "mitre": None},
    "authrootcaupdate":  {"name": "Windows Root Certificate Update", "category": "legitimate_system_operation", "severity": "info", "description": "AuthRootCAUpdate.p7b is used by Windows for automatic root certificate updates. Benign when invoked by svchost.exe.", "cve_refs": [], "mitre": None},
    "msbuild":           {"name": "MSBuild LOLBin", "category": "lolbin_execution", "severity": "critical", "description": "MSBuild executing project files to run arbitrary C# — known AppWhitelisting bypass.", "cve_refs": [], "mitre": "T1127.001"},
    "mshta":             {"name": "MSHTA LOLBin", "category": "lolbin_execution", "severity": "critical", "description": "MSHTA executes HTA files — commonly used to run malicious scripts.", "cve_refs": [], "mitre": "T1218.005"},
    "regsvr32":          {"name": "Regsvr32 LOLBin", "category": "lolbin_execution", "severity": "critical", "description": "Regsvr32 /s /n /u /i: used for COM scriptlet execution — Squiblydoo technique.", "cve_refs": [], "mitre": "T1218.010"},
    "rundll32":          {"name": "Rundll32 Abuse", "category": "lolbin_execution", "severity": "high", "description": "Rundll32 executing DLLs — can be abused to run malicious code.", "cve_refs": [], "mitre": "T1218.011"},
    "comsvcs":           {"name": "LSASS Dump via Comsvcs", "category": "credential_access", "severity": "critical", "description": "rundll32+comsvcs.dll MiniDump is a known technique to dump LSASS memory without Mimikatz.", "cve_refs": [], "mitre": "T1003.001"},
    "minidump":          {"name": "LSASS MiniDump", "category": "credential_access", "severity": "critical", "description": "MiniDump function used to dump LSASS process memory for offline credential extraction.", "cve_refs": [], "mitre": "T1003.001"},
    "wmic":              {"name": "WMIC Remote Execution", "category": "lateral_movement", "severity": "high", "description": "WMIC process call create used for remote command execution — common lateral movement.", "cve_refs": [], "mitre": "T1047"},

    # Windows EventID signatures
    "eventid=7045":      {"name": "Suspicious Service Installation", "category": "persistence", "severity": "high", "description": "EventID 7045: New service installed. Services in ProgramData or with generic names are persistence indicators.", "cve_refs": [], "mitre": "T1543.003"},
    "eventid=4698":      {"name": "Scheduled Task Created", "category": "persistence", "severity": "high", "description": "EventID 4698: Scheduled task created. Tasks pointing to Public/Temp paths are suspicious.", "cve_refs": [], "mitre": "T1053.005"},
    "eventid=4702":      {"name": "Scheduled Task Modified", "category": "persistence", "severity": "critical", "description": "EventID 4702: Scheduled task modified. Hijacking legitimate tasks to add malicious payloads.", "cve_refs": [], "mitre": "T1053.005"},
    "eventid=1102":      {"name": "Security/Audit Log Cleared", "category": "defense_evasion", "severity": "critical", "description": "EventID 1102: SECURITY log cleared — classic anti-forensics to cover tracks post-compromise. EXCEPTION: If LogName=Application (not Security) AND immediately followed by EventID=104 archive event from a log rotation service account, this is routine log lifecycle management (BENIGN). Always check LogName and whether an archive event follows.", "cve_refs": [], "mitre": "T1070.001"},
    "eventid=4657":      {"name": "Registry Value Modified", "category": "persistence", "severity": "high", "description": "EventID 4657: Registry value modified. Run key or WDigest changes indicate persistence or credential harvesting.", "cve_refs": [], "mitre": "T1547.001"},
    "eventid=4769":      {"name": "Kerberos TGS Request", "category": "credential_access", "severity": "high", "description": "EventID 4769: Kerberos ticket request. RC4-HMAC (0x17) encryption for krbtgt indicates Kerberoasting or Golden Ticket attack.", "cve_refs": [], "mitre": "T1558.003"},

    # Specific attack techniques
    "readme_decrypt":    {"name": "Ransomware Note", "category": "ransomware", "severity": "critical", "description": "README_DECRYPT.txt or similar ransom notes dropped by ransomware families.", "cve_refs": [], "mitre": "T1486"},
    "readme":            {"name": "Possible Ransomware Note", "category": "ransomware", "severity": "high", "description": "File resembling a ransom note. Combined with unknown.exe, high confidence ransomware.", "cve_refs": [], "mitre": "T1486"},
    "syn flood":         {"name": "SYN Flood DDoS", "category": "denial_of_service", "severity": "critical", "description": "SYN flood attack exhausting server connection table — volumetric DDoS.", "cve_refs": [], "mitre": "T1498.001"},
    "icmp sweep":        {"name": "ICMP Host Discovery", "category": "reconnaissance", "severity": "medium", "description": "ICMP ping sweep to discover live hosts on a subnet — network reconnaissance.", "cve_refs": [], "mitre": "T1018"},
    "pam_permit":        {"name": "PAM Backdoor", "category": "persistence", "severity": "critical", "description": "pam_permit.so added to SSH PAM stack — allows any password to authenticate, creating a persistent backdoor.", "cve_refs": [], "mitre": "T1556"},
    "uselogoncredential":{"name": "WDigest Credential Caching", "category": "credential_access", "severity": "critical", "description": "Enabling WDigest forces Windows to cache plaintext credentials in memory, harvestable by Mimikatz.", "cve_refs": [], "mitre": "T1112"},
    "uselogoncredential; newvalue=dword(1)": {"name": "WDigest Enabled (Plaintext Passwords)", "category": "credential_access", "severity": "critical", "description": "UseLogonCredential set to DWORD(1) enables WDigest — Windows now caches plaintext passwords in LSASS, harvestable by Mimikatz. This was disabled by default since Windows 8.1/2012R2.", "cve_refs": [], "mitre": "T1112"},
    "wdigest":           {"name": "WDigest Credential Caching", "category": "credential_access", "severity": "critical", "description": "WDigest protocol enabled — stores cleartext passwords in LSASS memory.", "cve_refs": [], "mitre": "T1112"},
    "dword(1)":          {"name": "Registry Value Enabled", "category": "registry_modification", "severity": "medium", "description": "Registry value set to DWORD(1). Context determines severity — UseLogonCredential=1 enables plaintext credential caching.", "cve_refs": [], "mitre": "T1112"},
    "kerberoasting":     {"name": "Kerberoasting", "category": "credential_access", "severity": "critical", "description": "Requesting Kerberos service tickets to crack offline.", "cve_refs": [], "mitre": "T1558.003"},
    "rc4-hmac":          {"name": "RC4-HMAC Kerberos (Kerberoasting)", "category": "credential_access", "severity": "critical", "description": "RC4-HMAC (0x17) Kerberos encryption type for krbtgt — hallmark of Golden Ticket or Kerberoasting attack.", "cve_refs": [], "mitre": "T1558.003"},
    "0x17":              {"name": "RC4-HMAC Encryption (Kerberos)", "category": "credential_access", "severity": "high", "description": "RC4-HMAC encryption type in Kerberos ticket request. AES256 (0x12) is standard in modern environments.", "cve_refs": [], "mitre": "T1558.003"},
    "curl -s":           {"name": "Silent Curl Execution", "category": "execution", "severity": "medium", "description": "curl -s silently fetches remote content. Combined with | bash, enables remote code execution.", "cve_refs": [], "mitre": "T1059.004"},
    "curl.*|.*bash":     {"name": "Curl-Pipe-Bash RCE", "category": "execution", "severity": "critical", "description": "Piping curl output directly into bash — allows remote code execution without file write.", "cve_refs": [], "mitre": "T1059.004"},
    "ndis_monitor":      {"name": "Suspicious Kernel Driver", "category": "rootkit", "severity": "critical", "description": "Kernel driver dropped by sc.exe into System32 drivers — possible rootkit installation.", "cve_refs": [], "mitre": "T1014"},
    "ndis_monitor.sys":  {"name": "Rootkit Kernel Driver", "category": "rootkit", "severity": "critical", "description": "A kernel driver named ndis_monitor.sys dropped via sc.exe — legitimate drivers use Windows installer, not sc.exe file creation.", "cve_refs": [], "mitre": "T1014"},
    "filecreate":        {"name": "Suspicious File Creation", "category": "malware_staging", "severity": "medium", "description": "SYSMON EventID=11 FileCreate. Suspicious if targeting System32\\drivers (rootkit) or known malware staging paths.", "cve_refs": [], "mitre": "T1036"},
    "action changed from":{"name": "Scheduled Task Hijacked", "category": "persistence", "severity": "critical", "description": "Scheduled task action modified to chain a secondary payload — legitimate task preserved to avoid suspicion but malicious executable added.", "cve_refs": [], "mitre": "T1053.005"},
    "usoclient.exe":     {"name": "Windows Update Task Hijacked", "category": "persistence", "severity": "critical", "description": "UsoClient.exe (Windows Update Orchestrator) replaced or chained with attacker payload in scheduled task.", "cve_refs": [], "mitre": "T1053.005"},
    "usoclient":         {"name": "Windows Update Task Hijacked", "category": "persistence", "severity": "critical", "description": "UsoClient (Windows Update Orchestrator) action modified in scheduled task — attacker appended payload to legitimate Windows Update task.", "cve_refs": [], "mitre": "T1053.005"},
    "165.16.78":         {"name": "Known C2 IP", "category": "c2_server", "severity": "critical", "description": "IP associated with known C2 infrastructure.", "cve_refs": [], "mitre": "T1219"},
    "trojan":            {"name": "Trojan Detected", "category": "malware", "severity": "critical", "description": "Antivirus signature match for trojan malware.", "cve_refs": [], "mitre": "T1204"},
    "av alert":          {"name": "Antivirus Detection", "category": "malware", "severity": "critical", "description": "AV engine flagged a file as malicious.", "cve_refs": [], "mitre": "T1204"},
    "sha256":            {"name": "File Hash in Alert", "category": "malware_indicator", "severity": "high", "description": "File hash present in alert — check against known malware databases.", "cve_refs": [], "mitre": "T1204"},
    "permirootlogin":    {"name": "SSH Root Login Enabled", "category": "persistence", "severity": "critical", "description": "PermitRootLogin set to yes in sshd_config — allows direct root SSH access, common post-compromise persistence.", "cve_refs": [], "mitre": "T1098"},
    "passwordauthentication yes": {"name": "SSH Password Auth Enabled", "category": "persistence", "severity": "high", "description": "SSH password authentication re-enabled — weakens security, enables brute force.", "cve_refs": [], "mitre": "T1098"},
    "authorized_keys":   {"name": "SSH Authorized Key Added", "category": "persistence", "severity": "critical", "description": "SSH authorized key added — persistence mechanism granting permanent access.", "cve_refs": [], "mitre": "T1098.004"},
    "www-data":          {"name": "Web Process Privilege Abuse", "category": "privilege_escalation", "severity": "high", "description": "www-data (web server process) performing privileged actions — indicates web shell or RCE exploitation.", "cve_refs": [], "mitre": "T1078"},
    "base64":            {"name": "Base64 Exfiltration", "category": "exfiltration", "severity": "high", "description": "Base64 encoding of data before upload — common data exfiltration technique to bypass DLP.", "cve_refs": [], "mitre": "T1048"},
    "pastebin":          {"name": "Exfiltration via Paste Service", "category": "exfiltration", "severity": "critical", "description": "Uploading encoded data to public paste service — technique to exfiltrate data while evading DLP.", "cve_refs": [], "mitre": "T1567"},
    "adminshare":        {"name": "Admin Share Access", "category": "lateral_movement", "severity": "high", "description": "Writing executables to remote admin shares (C$) — common lateral movement technique.", "cve_refs": [], "mitre": "T1021.002"},
    "c$":                {"name": "Admin Share Write", "category": "lateral_movement", "severity": "high", "description": "File written to C$ admin share on a remote host — lateral movement indicator.", "cve_refs": [], "mitre": "T1021.002"},
    "windows\\temp":     {"name": "Executable in Windows Temp", "category": "malware_staging", "severity": "high", "description": "Executable dropped in Windows\\Temp — common malware staging location.", "cve_refs": [], "mitre": "T1036"},
    "programdata":       {"name": "Executable in ProgramData", "category": "malware_staging", "severity": "high", "description": "Executable or service in ProgramData path — suspicious location for malware persistence.", "cve_refs": [], "mitre": "T1036"},
    "users\\public":     {"name": "File in Public Directory", "category": "malware_staging", "severity": "high", "description": "Executable or script in Users\\Public — world-writable directory commonly used by malware.", "cve_refs": [], "mitre": "T1036"},
    "migration_svc":     {"name": "Suspicious DB Modification via Migration Service", "category": "account_manipulation", "severity": "critical", "description": "Migration service modifying admin account email — enables password reset account takeover. Attacker changes recovery email, then triggers 'forgot password' to gain admin access.", "cve_refs": [], "mitre": "T1098"},
    "update users set email":  {"name": "Admin Email Hijack", "category": "account_manipulation", "severity": "critical", "description": "UPDATE users SET email for admin account — attacker modifies recovery email to enable password reset account takeover.", "cve_refs": [], "mitre": "T1098"},
    "net localgroup":    {"name": "Local Admin Enumeration", "category": "discovery", "severity": "high", "description": "Enumerating local administrator group members — post-compromise reconnaissance.", "cve_refs": [], "mitre": "T1069"},
    "/tmp/.cache":       {"name": "Hidden Temp Directory", "category": "defense_evasion", "severity": "high", "description": "Files hidden in disguised temp directories — evasion technique.", "cve_refs": [], "mitre": "T1564"},
    "169.254.169.254":   {"name": "Cloud Metadata SSRF", "category": "credential_access", "severity": "critical", "description": "Access to cloud instance metadata API (169.254.169.254) — retrieves IAM credentials, tokens, and user data.", "cve_refs": [], "mitre": "T1552.005"},
    "iam/security-credentials": {"name": "AWS IAM Credential Theft", "category": "credential_access", "severity": "critical", "description": "Direct access to AWS IAM role credentials via instance metadata endpoint — credential theft.", "cve_refs": [], "mitre": "T1552.005"},
    "where 1=1":         {"name": "SQL Tautology / Full Table Dump", "category": "data_exfiltration", "severity": "critical", "description": "WHERE 1=1 returns all rows — used to bulk-extract entire tables.", "cve_refs": [], "mitre": "T1213"},
    "password_hash":     {"name": "Password Hash Extraction", "category": "credential_access", "severity": "critical", "description": "Query selecting password_hash column — targeted credential extraction from database.", "cve_refs": [], "mitre": "T1555"},

    # Authorized vulnerability scanners (enterprise tools — benign when from scanner appliance)
    "qualys":            {"name": "Qualys Vulnerability Scanner", "category": "authorized_vulnerability_scanner", "severity": "info", "description": "Qualys is an authorized enterprise vulnerability management platform. Qualys/Scanner user-agent from a designated scanner appliance performing scheduled scans is BENIGN. If the source IP is the registered Qualys scanner and the scan targets known port ranges, this is a compliance activity.", "cve_refs": [], "mitre": None},
    "qualys/scanner":    {"name": "Qualys Scanner Agent", "category": "authorized_vulnerability_scanner", "severity": "info", "description": "Qualys enterprise scanner performing authorized port scan. Verify that the source IP is the registered scanner appliance. This is BENIGN if part of scheduled vulnerability assessment.", "cve_refs": [], "mitre": None},
    "nessus":            {"name": "Tenable Nessus Scanner", "category": "authorized_vulnerability_scanner", "severity": "info", "description": "Nessus is an authorized enterprise vulnerability scanner. Port scans from Nessus scanners are part of scheduled compliance assessments and are BENIGN.", "cve_refs": [], "mitre": None},
    "openvas":           {"name": "OpenVAS Vulnerability Scanner", "category": "authorized_vulnerability_scanner", "severity": "info", "description": "OpenVAS is an authorized open-source vulnerability scanner. Scheduled scans from OpenVAS are BENIGN compliance activity.", "cve_refs": [], "mitre": None},

    # Benign IT automation (standard security hygiene operations)
    "get-storedcredential": {"name": "Stored Credential Retrieval (IT Automation)", "category": "legitimate_it_automation", "severity": "info", "description": "Get-StoredCredential retrieves securely stored service account credentials. When used in IT automation scripts (combined with Get-ADUser / Disable-ADAccount), this is standard secure credential management for security hygiene tasks, NOT credential theft.", "cve_refs": [], "mitre": None},
    "disable-adaccount": {"name": "AD Account Deactivation (IT Automation)", "category": "legitimate_it_automation", "severity": "info", "description": "Disable-ADAccount disabling stale Active Directory accounts. When combined with Get-ADUser filtering on PasswordLastSet, this is standard IT security hygiene automation — disabling inactive accounts to reduce attack surface. BENIGN.", "cve_refs": [], "mitre": None},
    "get-aduser":        {"name": "AD User Query (IT Automation)", "category": "legitimate_it_automation", "severity": "info", "description": "Get-ADUser querying Active Directory user accounts. Standard PowerShell cmdlet used in IT automation for account lifecycle management. Context: combined with Disable-ADAccount for inactive accounts = BENIGN security hygiene.", "cve_refs": [], "mitre": None},
    "new-pssession":     {"name": "PowerShell Remote Session", "category": "remote_administration", "severity": "low", "description": "New-PSSession creates a remote PowerShell session. While this can be used for lateral movement, it is also standard IT administration (e.g., remote deployment, AD management scripts). Context determines severity — combined with Get-ADUser/Disable-ADAccount = BENIGN IT automation.", "cve_refs": [], "mitre": "T1021.006"},
}

# CVE knowledge base
_CVE_DATABASE = {
    "CVE-2021-44228": {"cvss": 10.0, "severity": "critical", "service": "log4j", "versions": ["2.0-beta9", "2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13", "2.14"], "description": "Log4Shell: Remote code execution via JNDI injection in Apache Log4j2.", "exploited_wild": True, "patch": True},
    "CVE-2021-41773": {"cvss": 9.8, "severity": "critical", "service": "apache", "versions": ["2.4.49"], "description": "Path traversal and RCE in Apache HTTP Server 2.4.49.", "exploited_wild": True, "patch": True},
    "CVE-2021-42013": {"cvss": 9.8, "severity": "critical", "service": "apache", "versions": ["2.4.49", "2.4.50"], "description": "Path traversal bypass in Apache HTTP Server (follow-up to CVE-2021-41773).", "exploited_wild": True, "patch": True},
    "CVE-2021-26855": {"cvss": 9.8, "severity": "critical", "service": "exchange", "versions": ["2013", "2016", "2019"], "description": "ProxyLogon: SSRF in Microsoft Exchange leading to RCE.", "exploited_wild": True, "patch": True},
    "CVE-2017-0144":  {"cvss": 9.3, "severity": "critical", "service": "smb", "versions": ["windows_7", "windows_server_2008"], "description": "EternalBlue: SMBv1 buffer overflow exploited by WannaCry and NotPetya.", "exploited_wild": True, "patch": True},
    "CVE-2019-19781": {"cvss": 9.8, "severity": "critical", "service": "citrix", "versions": ["adc", "gateway"], "description": "Citrix ADC/Gateway path traversal allowing RCE without authentication.", "exploited_wild": True, "patch": True},
    "CVE-2020-1472":  {"cvss": 10.0, "severity": "critical", "service": "netlogon", "versions": ["windows_server"], "description": "Zerologon: Privilege escalation in Netlogon allowing domain controller takeover.", "exploited_wild": True, "patch": True},
    "CVE-2022-26134": {"cvss": 9.8, "severity": "critical", "service": "confluence", "versions": ["all"], "description": "Atlassian Confluence OGNL injection RCE (zero-day at disclosure).", "exploited_wild": True, "patch": True},
    "CVE-2023-44487": {"cvss": 7.5, "severity": "high", "service": "http2", "versions": ["all"], "description": "HTTP/2 Rapid Reset Attack enabling large-scale DDoS.", "exploited_wild": True, "patch": True},
    "CVE-2019-7401":  {"cvss": 9.8, "severity": "critical", "service": "sqlmap", "versions": ["<1.3.8"], "description": "SQL injection automation tool vulnerability.", "exploited_wild": False, "patch": True},
    "CVE-2023-23397": {"cvss": 9.8, "severity": "critical", "service": "outlook", "versions": ["2013", "2016", "2019", "2021"], "description": "Microsoft Outlook zero-click privilege escalation via NTLM hash theft.", "exploited_wild": True, "patch": True},
    "CVE-2022-30190": {"cvss": 7.8, "severity": "high", "service": "msdt", "versions": ["windows"], "description": "Follina: Microsoft Support Diagnostic Tool RCE via malicious Office documents.", "exploited_wild": True, "patch": True},
}

# Service to CVE mapping for version-based lookups
_SERVICE_CVE_MAP = {
    "apache":     ["CVE-2021-41773", "CVE-2021-42013"],
    "log4j":      ["CVE-2021-44228"],
    "log4j2":     ["CVE-2021-44228"],
    "exchange":   ["CVE-2021-26855"],
    "smb":        ["CVE-2017-0144"],
    "confluence": ["CVE-2022-26134"],
    "netlogon":   ["CVE-2020-1472"],
    "citrix":     ["CVE-2019-19781"],
    "outlook":    ["CVE-2023-23397"],
    "msdt":       ["CVE-2022-30190"],
    "http2":      ["CVE-2023-44487"],
}

# Mock user activity database
_USER_ACTIVITY_DB = {
    "sarah.j": {
        "events": [
            {"timestamp_offset_sec": -30, "type": "login_failed", "source_ip": "192.168.1.102", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -20, "type": "login_failed", "source_ip": "192.168.1.102", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": 30,  "type": "login_success", "source_ip": "192.168.1.102", "reason": None},
        ],
        "baseline_hours": "08:00-18:00",
        "account_locked": False,
        "role": "standard_user",
        "department": "Finance",
    },
    "admin": {
        "events": [
            {"timestamp_offset_sec": -3600, "type": "login_success", "source_ip": "192.168.1.5", "reason": "publickey"},
            {"timestamp_offset_sec": -7200, "type": "login_success", "source_ip": "192.168.1.5", "reason": "publickey"},
        ],
        "baseline_hours": "07:00-23:00",
        "account_locked": False,
        "role": "administrator",
        "department": "IT",
        "standard_auth_method": "publickey",
        "note": "Standard auth is publickey. If the current alert shows 'Accepted password' (successful login) at off-hours = compromised credentials = Malicious. If the current alert shows 'Failed password' (failed attempt) during business hours from internal IP with few attempts = likely user error = Benign.",
    },
    "root_user": {
        "events": [
            {"timestamp_offset_sec": 0, "type": "command_executed", "source_ip": "192.168.1.5", "reason": "sudo apt-get update"},
        ],
        "baseline_hours": "00:00-23:59",
        "account_locked": False,
        "role": "system_service",
        "department": "IT",
    },
    "j.smith": {
        "events": [
            {"timestamp_offset_sec": -60,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -55,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -50,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -45,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -40,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -35,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -30,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -25,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -20,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
            {"timestamp_offset_sec": -15,  "type": "login_failed",  "source_ip": "198.51.100.55", "reason": "Invalid Credentials"},
        ],
        "baseline_hours": "08:00-17:00",
        "account_locked": True,
        "role": "standard_user",
        "department": "Sales",
    },
}


# ---------------------------------------------------------------------------
# Helper: IP classification
# ---------------------------------------------------------------------------

def _is_private_ip(ip: str) -> bool:
    clean = ip.split(" ")[0].split("(")[0]
    return any(clean.startswith(p) for p in _PRIVATE_PREFIXES)


def _deterministic_ip_profile(ip: str) -> dict:
    """Generate a deterministic (but plausible) profile for unknown IPs using a hash."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    countries = [
        ("China", "CN"), ("Russia", "RU"), ("Brazil", "BR"), ("India", "IN"),
        ("Vietnam", "VN"), ("Ukraine", "UA"), ("Romania", "RO"), ("Nigeria", "NG"),
        ("Iran", "IR"), ("North Korea", "KP"),
    ]
    isps = ["Choopa LLC", "Frantech Solutions", "M247 Ltd", "Serverius",
            "Selectel", "HostKey BV", "Sharktech", "Psychz Networks"]
    asn_types = ["hosting", "hosting", "vpn", "hosting", "residential", "hosting"]
    country, code = countries[h % len(countries)]
    risk = 40 + (h % 50)  # 40–89 range for "unknown" externals
    return {
        "risk_score": risk,
        "categories": ["scanner"] if risk > 70 else ["suspicious"],
        "country": country,
        "country_code": code,
        "city": "Unknown",
        "isp": isps[h % len(isps)],
        "asn": f"AS{10000 + (h % 50000)}",
        "asn_type": asn_types[h % len(asn_types)],
        "is_datacenter": (h % 3) != 0,
        "is_tor": False,
        "is_vpn": (h % 5) == 0,
    }


# ---------------------------------------------------------------------------
# Tool 1: verify_ip_reputation
# ---------------------------------------------------------------------------

@tool
def verify_ip_reputation(ip: str) -> dict:
    """
    Query the reputation of an IP address against threat intelligence databases.
    Returns risk score (0-100), threat categories, geolocation, and ISP info.
    Use this to determine if a source or destination IP is malicious or suspicious.
    Always call this for any external (non-private) IP address in the alert.
    Real API replacement: AbuseIPDB or VirusTotal.
    """
    clean_ip = ip.strip().split(" ")[0].split("(")[0]

    if clean_ip in _SSRF_IPS:
        return {
            "ip": clean_ip,
            "risk_score": 80,
            "categories": ["cloud_metadata_endpoint"],
            "country": "Internal",
            "country_code": "INTERNAL",
            "isp": "AWS/Cloud Metadata Endpoint",
            "is_datacenter": False,
            "is_tor": False,
            "is_vpn": False,
            "warning": (
                "169.254.169.254 is the cloud instance metadata API. "
                "CRITICAL if accessed via IMDSv1 (no token) or from unexpected process/user — retrieves IAM credentials. "
                "BENIGN if accessed via IMDSv2 (X-aws-ec2-metadata-token present) by a dedicated credential-refresher process."
            ),
            "source": "internal_classification",
        }

    if _is_private_ip(clean_ip):
        return {
            "ip": clean_ip,
            "risk_score": 0,
            "categories": ["internal_network"],
            "country": "Internal",
            "country_code": "INTERNAL",
            "isp": "Internal Network",
            "is_datacenter": False,
            "is_tor": False,
            "is_vpn": False,
            "source": "internal_classification",
        }

    profile = _KNOWN_IP_PROFILES.get(clean_ip) or _deterministic_ip_profile(clean_ip)
    return {
        "ip": clean_ip,
        "risk_score": profile["risk_score"],
        "categories": profile["categories"],
        "country": profile["country"],
        "country_code": profile["country_code"],
        "isp": profile["isp"],
        "is_datacenter": profile["is_datacenter"],
        "is_tor": profile["is_tor"],
        "is_vpn": profile["is_vpn"],
        "source": "mock_threat_intel_db",
    }


# ---------------------------------------------------------------------------
# Tool 2: decode_payload
# ---------------------------------------------------------------------------

@tool
def decode_payload(payload: str) -> dict:
    """
    Decode and analyze a potentially obfuscated log payload.
    Handles URL percent-encoding, Base64, HTML entities, and Unicode escapes.
    Returns the decoded string, detected encoding types, and any matched attack patterns.
    Always call this first when the log_payload contains percent-encoded characters (%XX),
    base64 strings, or any other encoded or obfuscated content.
    """
    original = payload
    decoded = payload
    encodings_detected = []
    layers = 0

    # Layer 1: URL percent-decoding (run up to 3 times for double-encoding)
    for _ in range(3):
        candidate = unquote_plus(decoded)
        if candidate != decoded:
            decoded = candidate
            if "url_percent_encoding" not in encodings_detected:
                encodings_detected.append("url_percent_encoding")
            layers += 1
        else:
            break

    # Layer 2: HTML entity decoding
    candidate = html.unescape(decoded)
    if candidate != decoded:
        decoded = candidate
        encodings_detected.append("html_entities")
        layers += 1

    # Layer 3: Base64 (only attempt on suspicious standalone blobs)
    b64_match = re.search(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/])', decoded)
    if b64_match:
        try:
            b64_candidate = base64.b64decode(b64_match.group(1) + "==").decode("utf-8", errors="ignore")
            if len(b64_candidate) > 5 and b64_candidate.isprintable():
                decoded = decoded.replace(b64_match.group(1), f"[BASE64_DECODED: {b64_candidate}]")
                encodings_detected.append("base64")
                layers += 1
        except Exception:
            pass

    # Layer 4: Unicode escapes (\uXXXX or \xXX)
    candidate = decoded.encode("utf-8").decode("unicode_escape", errors="ignore")
    if candidate != decoded and len(candidate) > 2:
        try:
            candidate.encode("utf-8")
            decoded = candidate
            encodings_detected.append("unicode_escape")
            layers += 1
        except Exception:
            pass

    # Pattern matching on the decoded string
    patterns_found = []
    for pattern_name, regex, severity in _ATTACK_PATTERNS:
        if re.search(regex, decoded, re.IGNORECASE):
            match_obj = re.search(regex, decoded, re.IGNORECASE)
            patterns_found.append({
                "pattern": pattern_name,
                "matched_snippet": match_obj.group(0)[:80] if match_obj else "",
                "severity": severity,
            })

    return {
        "original": original[:200],
        "decoded": decoded[:500],
        "encoding_detected": encodings_detected,
        "additional_layers": layers,
        "patterns_found": patterns_found,
        "is_suspicious": len(patterns_found) > 0,
    }


# ---------------------------------------------------------------------------
# Tool 3: lookup_known_attack_signature
# ---------------------------------------------------------------------------

@tool
def lookup_known_attack_signature(indicator: str, indicator_type: str) -> dict:
    """
    Look up a known attack signature, tool, or indicator in the threat intelligence knowledge base.
    indicator_type must be one of: 'user_agent', 'cve', 'process_name', 'command', 'url_pattern', 'file_hash'.
    Use this when you spot a suspicious tool name (e.g., 'sqlmap'), CVE ID, command, or process name.
    Returns match details, severity, MITRE ATT&CK technique, and CVE references.
    """
    normalized = indicator.strip().lower()

    # Direct key lookup
    result = _ATTACK_SIGNATURES.get(normalized)

    # Partial / substring match
    if not result:
        for key, val in _ATTACK_SIGNATURES.items():
            if key in normalized or normalized in key:
                result = val
                break

    if result:
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "match_found": True,
            "name": result["name"],
            "category": result["category"],
            "severity": result["severity"],
            "description": result["description"],
            "cve_references": result["cve_refs"],
            "mitre_technique": result["mitre"],
        }

    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "match_found": False,
        "name": None,
        "category": None,
        "severity": "unknown",
        "description": "No match found in threat intelligence database.",
        "cve_references": [],
        "mitre_technique": None,
    }


# ---------------------------------------------------------------------------
# Tool 4: get_user_activity_history
# ---------------------------------------------------------------------------

@tool
def get_user_activity_history(username: str, hours_back: int = 24) -> dict:
    """
    Retrieve the recent activity history for a specific user account.
    Returns login events (successes and failures), distinct source IPs, account lock status,
    and anomaly flags. Use this for any authentication-related alert to distinguish
    brute-force attacks from legitimate users making mistakes.
    """
    normalized = username.strip().lower()
    profile = _USER_ACTIVITY_DB.get(normalized) or _USER_ACTIVITY_DB.get(username.strip())

    if not profile:
        return {
            "username": username,
            "events": [],
            "summary": {
                "total_failures_24h": 0,
                "total_successes_24h": 0,
                "distinct_source_ips": 0,
                "account_locked": False,
                "baseline_login_hours": "08:00-18:00",
                "role": "unknown",
                "department": "unknown",
            },
            "anomaly_flags": ["USER_NOT_FOUND_IN_DIRECTORY"],
        }

    # Build events with relative timestamps
    now = datetime.now(timezone.utc)
    events = []
    failures = 0
    successes = 0
    ips = set()

    for ev in profile["events"]:
        ts = now.timestamp() + ev["timestamp_offset_sec"]
        ts_str = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append({
            "timestamp": ts_str,
            "type": ev["type"],
            "source_ip": ev["source_ip"],
            "reason": ev.get("reason"),
        })
        if ev["type"] == "login_failed":
            failures += 1
        elif ev["type"] == "login_success":
            successes += 1
        ips.add(ev["source_ip"])

    anomaly_flags = []
    if failures >= 10:
        anomaly_flags.append("HIGH_FAILURE_COUNT_POSSIBLE_BRUTE_FORCE")
    if len(ips) > 3:
        anomaly_flags.append("MULTIPLE_SOURCE_IPS")
    if profile["account_locked"]:
        anomaly_flags.append("ACCOUNT_CURRENTLY_LOCKED")

    # Surface standard auth method if known (only flag for SUCCESSFUL password auth, not failed attempts)
    standard_auth = profile.get("standard_auth_method")
    if standard_auth:
        anomaly_flags.append(
            f"STANDARD_AUTH_METHOD_IS_{standard_auth.upper()}: "
            f"SUCCESSFUL password authentication for this account is a compromised credential indicator. "
            f"A small number of FAILED password attempts during business hours from internal IP is likely user error (Benign)."
        )

    result = {
        "username": username,
        "events": events,
        "summary": {
            "total_failures_24h": failures,
            "total_successes_24h": successes,
            "distinct_source_ips": len(ips),
            "account_locked": profile["account_locked"],
            "baseline_login_hours": profile["baseline_hours"],
            "role": profile["role"],
            "department": profile["department"],
        },
        "anomaly_flags": anomaly_flags,
    }
    if profile.get("note"):
        result["security_note"] = profile["note"]
    return result


# ---------------------------------------------------------------------------
# Tool 5: analyze_network_traffic_context
# ---------------------------------------------------------------------------

@tool
def analyze_network_traffic_context(
    source_ip: str,
    destination_ip: str,
    port: int,
    protocol: str,
    bytes_transferred: int = 0,
    duration_seconds: int = 0,
) -> dict:
    """
    Analyze a network connection for anomalous behavior by comparing against baseline traffic patterns.
    Checks: port/protocol appropriateness, traffic volume baselines, time-of-day anomalies,
    and whether the destination is a known C2 server.
    Use this for firewall egress logs, large data transfers, or unusual outbound connections.
    Provide bytes_transferred in bytes (e.g., 4.5GB = 4831838208).
    """
    anomalies = []
    risk_level = "low"

    # C2 destination check
    clean_dst = destination_ip.strip().split(" ")[0]
    if clean_dst in _C2_IPS:
        anomalies.append({"type": "KNOWN_C2_DESTINATION", "detail": f"{clean_dst} is flagged as a known C2/malware server."})
        risk_level = "critical"

    # Destination IP reputation (quick check)
    dst_profile = _KNOWN_IP_PROFILES.get(clean_dst)
    if dst_profile and dst_profile["risk_score"] >= 80:
        anomalies.append({"type": "HIGH_RISK_DESTINATION", "detail": f"Destination IP risk score: {dst_profile['risk_score']}/100."})
        if risk_level == "low":
            risk_level = "high"

    # Volume analysis — use context-appropriate baseline
    dst_is_internal = _is_private_ip(clean_dst)
    src_is_internal = _is_private_ip(source_ip.strip().split(" ")[0].split("(")[0])
    if dst_is_internal and src_is_internal:
        if port == 22:
            # SSH between internal servers: 1GB max — SSH is for commands/keys, not bulk transfers
            BASELINE_MAX_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB
        else:
            BASELINE_MAX_BYTES = 50 * 1024 * 1024 * 1024  # 50 GB — internal backups are large
    else:
        BASELINE_MAX_BYTES = 50 * 1024 * 1024  # 50 MB — external egress baseline
    if bytes_transferred > BASELINE_MAX_BYTES:
        gb = bytes_transferred / (1024 ** 3)
        deviation = bytes_transferred / BASELINE_MAX_BYTES
        anomalies.append({
            "type": "HIGH_EGRESS_VOLUME",
            "detail": f"Transferred {gb:.2f}GB; baseline max is 50MB. Deviation factor: {deviation:.0f}x.",
        })
        if risk_level in ("low", "medium"):
            risk_level = "high"

    # Time-of-day analysis — only flag for external connections
    now = datetime.now(timezone.utc)
    hour = now.hour
    if (not dst_is_internal) and (hour < 7 or hour >= 19):
        anomalies.append({
            "type": "OFF_HOURS_CONNECTION",
            "detail": f"Connection at {now.strftime('%H:%M')} UTC is outside business hours (07:00–19:00).",
        })

    # Port/protocol appropriateness
    SUSPICIOUS_PORTS = {4444: "Metasploit default", 1337: "common malware", 31337: "classic backdoor",
                        8080: "common proxy/C2", 6667: "IRC (botnet C2)", 22: "SSH (flag if unusual egress)"}
    EXPECTED_PORTS = {80, 443, 53, 25, 587, 465, 143, 993, 21, 22, 3389}
    if port in SUSPICIOUS_PORTS:
        anomalies.append({"type": "SUSPICIOUS_PORT", "detail": f"Port {port} associated with: {SUSPICIOUS_PORTS[port]}."})
        if risk_level == "low":
            risk_level = "medium"

    # Duration anomaly: only flag for external connections (internal backups are long by nature)
    if (not dst_is_internal) and duration_seconds > 300 and bytes_transferred > BASELINE_MAX_BYTES:
        anomalies.append({"type": "LONG_DURATION_HIGH_VOLUME", "detail": f"Connection lasted {duration_seconds}s with high volume — possible data tunneling."})

    if not anomalies:
        anomalies.append({"type": "NONE", "detail": "No anomalies detected. Traffic appears consistent with baseline."})

    # Final risk escalation logic
    if len([a for a in anomalies if a["type"] != "NONE"]) >= 3:
        risk_level = "critical"
    elif len([a for a in anomalies if a["type"] != "NONE"]) == 2 and risk_level == "high":
        risk_level = "critical"

    return {
        "connection_summary": {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "port": port,
            "protocol": protocol.upper(),
            "bytes_transferred": bytes_transferred,
            "bytes_transferred_human": f"{bytes_transferred / (1024**3):.2f}GB" if bytes_transferred > 1024**3 else f"{bytes_transferred / (1024**2):.1f}MB",
            "duration_seconds": duration_seconds,
        },
        "anomalies": anomalies,
        "risk_level": risk_level,
        "baseline_comparison": {
            "normal_max_egress_bytes": BASELINE_MAX_BYTES,
            "observed_bytes": bytes_transferred,
            "deviation_factor": round(bytes_transferred / BASELINE_MAX_BYTES, 1) if bytes_transferred > 0 else 0,
        },
    }


# ---------------------------------------------------------------------------
# Tool 6: cve_lookup
# ---------------------------------------------------------------------------

@tool
def cve_lookup(cve_id: str = "", service_name: str = "", service_version: str = "") -> dict:
    """
    Look up CVE vulnerability information. Provide either:
    - cve_id: a specific CVE identifier (e.g., 'CVE-2021-44228'), OR
    - service_name + service_version: to find all known CVEs for that service version.
    Returns CVSS score, severity, whether it is exploited in the wild, and patch availability.
    Use this when a log mentions a specific software version or when investigating CVE references.
    Real API replacement: NVD API (services.nvd.nist.gov).
    """
    results = []

    if cve_id:
        normalized = cve_id.strip().upper()
        entry = _CVE_DATABASE.get(normalized)
        if entry:
            results.append({
                "cve_id": normalized,
                "cvss_score": entry["cvss"],
                "severity": entry["severity"],
                "description": entry["description"],
                "exploited_in_wild": entry["exploited_wild"],
                "patch_available": entry["patch"],
                "affected_versions": entry["versions"],
            })

    elif service_name:
        svc = service_name.strip().lower()
        cve_ids = _SERVICE_CVE_MAP.get(svc, [])
        for cid in cve_ids:
            entry = _CVE_DATABASE.get(cid)
            if not entry:
                continue
            # Version filter (loose match)
            if service_version:
                ver = service_version.strip()
                if ver not in entry["versions"] and "all" not in entry["versions"]:
                    # Check partial version match
                    if not any(ver.startswith(v) or v.startswith(ver) for v in entry["versions"]):
                        continue
            results.append({
                "cve_id": cid,
                "cvss_score": entry["cvss"],
                "severity": entry["severity"],
                "description": entry["description"],
                "exploited_in_wild": entry["exploited_wild"],
                "patch_available": entry["patch"],
                "affected_versions": entry["versions"],
            })

    return {
        "query": {"cve_id": cve_id, "service_name": service_name, "service_version": service_version},
        "vulnerabilities": results,
        "total_found": len(results),
        "source": "mock_cve_database",
    }


# ---------------------------------------------------------------------------
# Tool 7: get_geolocation_and_asn
# ---------------------------------------------------------------------------

@tool
def get_geolocation_and_asn(ip: str) -> dict:
    """
    Get geolocation and ASN (Autonomous System Number) information for an IP address.
    Returns country, city, ASN owner, infrastructure type (hosting/residential/vpn/tor),
    and whether the IP originates from an expected geographic region.
    Use this to assess whether traffic originates from expected regions or suspicious infrastructure.
    Pairs well with verify_ip_reputation for a complete external IP assessment.
    Real API replacement: MaxMind GeoLite2 or ip-api.com.
    """
    clean_ip = ip.strip().split(" ")[0].split("(")[0]

    if _is_private_ip(clean_ip) or clean_ip == "localhost":
        return {
            "ip": clean_ip,
            "country": "Internal Network",
            "country_code": "INTERNAL",
            "city": "N/A",
            "latitude": None,
            "longitude": None,
            "asn": "N/A",
            "asn_name": "Internal Network",
            "asn_type": "internal",
            "is_hosting_provider": False,
            "is_residential": False,
            "is_mobile": False,
            "geofence_violation": False,
            "expected_regions": list(EXPECTED_REGIONS),
        }

    profile = _KNOWN_IP_PROFILES.get(clean_ip) or _deterministic_ip_profile(clean_ip)
    geo_violation = profile["country_code"] not in EXPECTED_REGIONS and profile["country_code"] != "INTERNAL"

    return {
        "ip": clean_ip,
        "country": profile["country"],
        "country_code": profile["country_code"],
        "city": profile.get("city", "Unknown"),
        "asn": profile["asn"],
        "asn_name": profile["isp"],
        "asn_type": profile["asn_type"],
        "is_hosting_provider": profile["is_datacenter"],
        "is_residential": profile["asn_type"] == "residential",
        "is_mobile": False,
        "geofence_violation": geo_violation,
        "expected_regions": list(EXPECTED_REGIONS),
        "source": "mock_geo_db",
    }


# ---------------------------------------------------------------------------
# Tool registry (used by agent.py)
# ---------------------------------------------------------------------------

ALL_TOOLS = [
    verify_ip_reputation,
    decode_payload,
    lookup_known_attack_signature,
    get_user_activity_history,
    analyze_network_traffic_context,
    cve_lookup,
    get_geolocation_and_asn,
]

TOOL_MAP = {t.name: t for t in ALL_TOOLS}
