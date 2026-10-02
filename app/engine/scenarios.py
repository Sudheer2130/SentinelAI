from typing import List, Dict, Any

SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "scenario-cobalt-strike",
        "title": "Cobalt Strike C2 Beaconing & Sysmon Process Injection",
        "category": "APT & Memory Injection",
        "description": "Correlated attack scenario where Suricata detects malleable C2 HTTP beacons to a Russian bulletproof server, while Sysmon captures PowerShell launching shellcode injection into explorer.exe.",
        "difficulty": "Critical",
        "primary_log": {
            "alert_id": "alert-cs-beacon-8443",
            "timestamp": "2026-10-02T11:15:32.482Z",
            "log_source": "SURICATA_NIDS",
            "signature": "ET TROJAN Cobalt Strike Malleable C2 Beaconing Over TLS",
            "severity": "CRITICAL",
            "src_ip": "10.0.4.15",
            "src_port": 49832,
            "dest_ip": "194.26.29.112",
            "dest_port": 8443,
            "proto": "TCP",
            "http_host": "c2-telemetry-cdn.net",
            "http_url": "/api/v2/telemetry/heartbeat",
            "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "hostname": "FIN-WORKSTATION-44",
            "user": "CORP\\jsmith",
            "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process_id": 4892,
            "parent_process": "C:\\Windows\\explorer.exe",
            "command_line": "powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBt...",
            "file_hashes": {
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "alert": {
                "category": "A Network Trojan was detected",
                "signature": "ET TROJAN Cobalt Strike Malleable C2 Beaconing Over TLS",
                "severity": 1
            }
        },
        "correlated_events": [
            {
                "timestamp": "2026-10-02T11:14:02.120Z",
                "stage": "Initial Execution",
                "description": "User jsmith opened malicious phishing invoice document causing WINWORD.EXE to spawn PowerShell.",
                "source": "Windows Sysmon Event 1",
                "severity": "HIGH"
            },
            {
                "timestamp": "2026-10-02T11:14:45.310Z",
                "stage": "Defense Evasion & Injection",
                "description": "Sysmon Event ID 8: CreateRemoteThread detected from powershell.exe (PID 4892) into explorer.exe (PID 2110).",
                "source": "Windows Sysmon Event 8",
                "severity": "CRITICAL"
            },
            {
                "timestamp": "2026-10-02T11:15:32.482Z",
                "stage": "Command and Control",
                "description": "Suricata Alert: Periodic HTTP POST beacons to C2 server 194.26.29.112:8443 matching Cobalt Strike profile.",
                "source": "Suricata NIDS",
                "severity": "CRITICAL"
            }
        ]
    },
    {
        "id": "scenario-lockbit-ransomware",
        "title": "LockBit 3.0 Ransomware Execution & Shadow Copy Deletion",
        "category": "Ransomware / Extortion",
        "description": "Endpoint disaster scenario where LockBit 3.0 executable attempts to inhibit system recovery by deleting volume shadow copies and initiates rapid file encryption with .lockbit extensions.",
        "difficulty": "Critical",
        "primary_log": {
            "alert_id": "alert-lockbit-vss-01",
            "timestamp": "2026-10-02T03:22:18.910Z",
            "log_source": "WINDOWS_SYSMON",
            "EventID": 1,
            "event_id": "1",
            "signature": "Sysmon Event ID 1: Suspicious vssadmin Command Line Execution",
            "severity": "CRITICAL",
            "Computer": "FILE-SERVER-02",
            "hostname": "FILE-SERVER-02",
            "User": "NT AUTHORITY\\SYSTEM",
            "user": "NT AUTHORITY\\SYSTEM",
            "Image": "C:\\Windows\\System32\\vssadmin.exe",
            "process_name": "C:\\Windows\\System32\\vssadmin.exe",
            "process_id": 8120,
            "ParentImage": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\lb3_runner.exe",
            "parent_process": "C:\\Users\\Administrator\\AppData\\Local\\Temp\\lb3_runner.exe",
            "CommandLine": "vssadmin.exe delete shadows /all /quiet",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "target_filename": "C:\\Shares\\Confidential\\Financials_2026.xlsx.lockbit",
            "Hashes": "SHA256=5d41402abc4b2a76b9719d911017c5928a6f3b0e51ff6a7a59e19d7008d519b5",
            "file_hashes": {
                "sha256": "5d41402abc4b2a76b9719d911017c5928a6f3b0e51ff6a7a59e19d7008d519b5"
            }
        },
        "correlated_events": [
            {
                "timestamp": "2026-10-02T03:20:11.000Z",
                "stage": "Execution",
                "description": "Staging executable lb3_runner.exe dropped in Temp folder and executed with elevated privileges.",
                "source": "Sysmon Event 11",
                "severity": "HIGH"
            },
            {
                "timestamp": "2026-10-02T03:22:18.910Z",
                "stage": "Inhibit System Recovery",
                "description": "vssadmin.exe delete shadows /all /quiet executed to prevent shadow copy volume recovery.",
                "source": "Sysmon Event 1",
                "severity": "CRITICAL"
            },
            {
                "timestamp": "2026-10-02T03:23:05.412Z",
                "stage": "Impact: Data Encryption",
                "description": "Sysmon Event 11: Rapid file creation stream of .lockbit extension files and README_RESTORE.txt.",
                "source": "Sysmon Event 11",
                "severity": "CRITICAL"
            }
        ]
    },
    {
        "id": "scenario-portscan-bruteforce",
        "title": "Suricata Network Reconnaissance & RDP Password Spraying",
        "category": "External Threat / Brute Force",
        "description": "Perimeter network attack where an external Tor exit node conducts aggressive TCP SYN port scanning followed by targeted RDP credential spraying.",
        "difficulty": "High",
        "primary_log": {
            "alert_id": "alert-suricata-scan-3389",
            "timestamp": "2026-10-02T08:44:12.100Z",
            "log_source": "SURICATA_NIDS",
            "signature": "ET SCAN Suspicious Rapid SYN Port Sweep Followed by RDP Handshake",
            "severity": "HIGH",
            "src_ip": "185.220.101.5",
            "src_port": 54122,
            "dest_ip": "203.0.113.88",
            "dest_port": 3389,
            "proto": "TCP",
            "hostname": "EDGE-GATEWAY-EXT",
            "alert": {
                "category": "Attempted Information Leak / Reconnaissance",
                "signature": "ET SCAN Suspicious Rapid SYN Port Sweep Followed by RDP Handshake",
                "severity": 2
            }
        },
        "correlated_events": [
            {
                "timestamp": "2026-10-02T08:41:00.000Z",
                "stage": "Reconnaissance",
                "description": "SYN packets probing ports 22, 80, 443, 3389, 8080 from single IP 185.220.101.5 across 30 seconds.",
                "source": "Suricata Flow Engine",
                "severity": "MEDIUM"
            },
            {
                "timestamp": "2026-10-02T08:44:12.100Z",
                "stage": "Credential Access",
                "description": "Over 120 failed RDP authentication handshakes on port 3389 targeting admin, administrator, root.",
                "source": "Suricata NIDS",
                "severity": "HIGH"
            }
        ]
    },
    {
        "id": "scenario-false-positive-sccm",
        "title": "False Positive Triage: Microsoft Endpoint SCCM Inventory",
        "category": "Benign Automation / False Positive",
        "description": "Routine IT Systems Management script executing WMI queries to collect operating system version and disk capacity. Correctly classified as False Positive by AI.",
        "difficulty": "Low / Benign",
        "primary_log": {
            "alert_id": "alert-fp-sccm-04",
            "timestamp": "2026-10-02T10:00:05.120Z",
            "log_source": "WINDOWS_SYSMON",
            "EventID": 1,
            "event_id": "1",
            "signature": "Sysmon Event ID 1: PowerShell Command Line WMI Query Execution",
            "severity": "LOW",
            "Computer": "DEV-WORKSTATION-12",
            "hostname": "DEV-WORKSTATION-12",
            "User": "CORP\\svc_sccm_mgmt",
            "user": "CORP\\svc_sccm_mgmt",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "process_id": 3108,
            "ParentImage": "C:\\Program Files\\Microsoft Configuration Manager\\CcmExec.exe",
            "parent_process": "C:\\Program Files\\Microsoft Configuration Manager\\CcmExec.exe",
            "CommandLine": "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture\"",
            "command_line": "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,OSArchitecture\"",
            "Hashes": "SHA256=a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
            "file_hashes": {
                "sha256": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
            }
        },
        "correlated_events": [
            {
                "timestamp": "2026-10-02T10:00:00.000Z",
                "stage": "Legitimate Management",
                "description": "Microsoft Configuration Manager service (CcmExec.exe) triggered scheduled endpoint hardware telemetry scan.",
                "source": "Windows Service Control Manager",
                "severity": "INFORMATIONAL"
            },
            {
                "timestamp": "2026-10-02T10:00:05.120Z",
                "stage": "Execution",
                "description": "Non-interactive PowerShell execution querying standard WMI Win32_OperatingSystem class.",
                "source": "Sysmon Event 1",
                "severity": "LOW"
            }
        ]
    }
]
