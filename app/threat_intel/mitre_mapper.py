import re
from typing import List, Dict, Any, Optional
from ..models.schemas import MitreTTP, NormalizedAlert

class MitreMapper:
    """
    Automated MITRE ATT&CK Framework (v14) TTP Classifier
    Correlates endpoint telemetry (Sysmon) and network telemetry (Suricata)
    to tactics, techniques, and sub-techniques.
    """
    
    PATTERNS = [
        {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "regex": r"(powershell(\.exe)?|pwsh(\.exe)?).*(-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden|iex|invoke-expression|downloadstring)",
            "description": "Adversary utilized obfuscated or non-interactive PowerShell commands to execute payloads.",
            "confidence": 0.95
        },
        {
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1055.001",
            "technique_name": "Process Injection: Dynamic-link Library Injection",
            "regex": r"(createremotethread|virtualallocex|writeprocessmemory|inject|shellcode)",
            "description": "Process injection detected via CreateRemoteThread or direct memory manipulation.",
            "confidence": 0.92
        },
        {
            "tactic_id": "TA0011",
            "tactic_name": "Command and Control",
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "regex": r"(cobalt strike|malleable c2|beacon|c2 traffic|reverse shell|meterpreter|teamserver)",
            "description": "Traffic matched known Command and Control application layer communication profiles.",
            "confidence": 0.94
        },
        {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1486",
            "technique_name": "Data Encrypted for Impact",
            "regex": r"(\.lockbit|\.blackcat|\.phobos|\.ryuk|\.locked|ransom|encrypt(ion)?\s+routine)",
            "description": "Filesystem modifications or extensions indicative of ransomware data encryption.",
            "confidence": 0.96
        },
        {
            "tactic_id": "TA0040",
            "tactic_name": "Impact",
            "technique_id": "T1490",
            "technique_name": "Inhibit System Recovery",
            "regex": r"(vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*bootstatuspolicy\s+ignoreallfailures)",
            "description": "Attempts to delete Volume Shadow Copies to prevent system restoration after attack.",
            "confidence": 0.98
        },
        {
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "technique_id": "T1046",
            "technique_name": "Network Service Discovery",
            "regex": r"(port\s*scan|syn\s*flood|nmap|masscan|service\s*sweep|reconnaissance)",
            "description": "Automated port scanning or external reconnaissance targeting perimeter services.",
            "confidence": 0.88
        },
        {
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "regex": r"(brute\s*force|failed\s*login|password\s*spraying|authentication\s*failure)",
            "description": "Rapid succession of authentication failures indicating dictionary or brute force attempt.",
            "confidence": 0.90
        },
        {
            "tactic_id": "TA0006",
            "tactic_name": "Credential Access",
            "technique_id": "T1003.001",
            "technique_name": "OS Credential Dumping: LSASS Memory",
            "regex": r"(mimikatz|sekurlsa|lsass\.exe|procdump.*lsass|comsvcs\.dll.*minidump)",
            "description": "Adversary attempted memory extraction of Local Security Authority Subsystem Service (LSASS).",
            "confidence": 0.97
        },
        {
            "tactic_id": "TA0005",
            "tactic_name": "Defense Evasion",
            "technique_id": "T1562.001",
            "technique_name": "Impair Defenses: Disable or Modify Tools",
            "regex": r"(set-mppreference.*disablerealtimemonitoring|wevtutil(\.exe)?\s+cl|net\s+stop\s+(windefend|sense))",
            "description": "Tampering with security controls, stopping antivirus services, or clearing event logs.",
            "confidence": 0.95
        },
        {
            "tactic_id": "TA0008",
            "tactic_name": "Lateral Movement",
            "technique_id": "T1021.002",
            "technique_name": "Remote Services: SMB/Windows Admin Shares",
            "regex": r"(psexec|admin\$|c\$|ipc\$|winexe|wmic.*process\s+call\s+create)",
            "description": "Adversary moving laterally across internal network using administrative shares or WMI.",
            "confidence": 0.91
        }
    ]

    def map_alert(self, alert: NormalizedAlert) -> List[MitreTTP]:
        matched_ttps: List[MitreTTP] = []
        seen_techniques = set()
        
        # Aggregate all text elements from alert to analyze
        haystack = " ".join([
            alert.signature or "",
            alert.command_line or "",
            alert.process_name or "",
            alert.parent_process or "",
            alert.target_filename or "",
            str(alert.event_id or ""),
            str(alert.raw_payload)
        ]).lower()
        
        # Specific Sysmon Event ID rules
        if alert.event_id == "8":
            ttp = MitreTTP(
                tactic_id="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055.001",
                technique_name="Process Injection: Dynamic-link Library Injection",
                confidence=0.96,
                matched_pattern="Sysmon Event ID 8 (CreateRemoteThread)",
                description="Sysmon Event 8 specifically records remote thread creation in a target process."
            )
            matched_ttps.append(ttp)
            seen_techniques.add(ttp.technique_id)
            
        elif alert.event_id == "11" and any(ext in (alert.target_filename or "").lower() for ext in [".lockbit", ".locked", ".crypto", ".pay"]):
            ttp = MitreTTP(
                tactic_id="TA0040",
                tactic_name="Impact",
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                confidence=0.98,
                matched_pattern="Sysmon Event ID 11 (FileCreate with ransomware extension)",
                description="Mass file creation with ransomware extension detected on host filesystem."
            )
            matched_ttps.append(ttp)
            seen_techniques.add(ttp.technique_id)

        # Regex heuristic rules
        for p in self.PATTERNS:
            if p["technique_id"] in seen_techniques:
                continue
            match = re.search(p["regex"], haystack, re.IGNORECASE)
            if match:
                matched_ttps.append(
                    MitreTTP(
                        tactic_id=p["tactic_id"],
                        tactic_name=p["tactic_name"],
                        technique_id=p["technique_id"],
                        technique_name=p["technique_name"],
                        confidence=p["confidence"],
                        matched_pattern=match.group(0),
                        description=p["description"]
                    )
                )
                seen_techniques.add(p["technique_id"])
                
        return matched_ttps

mitre_mapper = MitreMapper()
