from typing import List, Optional
from ..models.schemas import NormalizedAlert, PlaybookAction, IOCType

class PlaybookGenerator:
    """
    Generates tailored defensive remediation scripts, containment commands,
    Sigma detection rules, and YARA signatures for detected security incidents.
    """

    def generate_playbook(self, alert: NormalizedAlert, malicious_ips: List[str], file_hashes: List[str]) -> List[PlaybookAction]:
        actions: List[PlaybookAction] = []
        hostname = alert.hostname or "TARGET-HOST"
        
        # 1. Host Isolation Playbook
        actions.append(
            PlaybookAction(
                id="act-isolate-host",
                title=f"Isolate Endpoint ({hostname}) from Network",
                action_type="host_isolate",
                command=f"powershell.exe -Command \"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; New-NetFirewallRule -DisplayName 'SOC-Emergency-Containment' -Direction Outbound -Action Block -RemoteAddress Any\"",
                target=hostname,
                risk_level="HIGH",
                explanation="Immediately prevents attacker lateral movement and C2 beaconing while preserving local forensic memory."
            )
        )

        # 2. Terminate Malicious Process
        if alert.process_name or alert.process_id:
            proc = alert.process_name or "suspicious.exe"
            pid = str(alert.process_id) if alert.process_id else "$proc.Id"
            actions.append(
                PlaybookAction(
                    id="act-kill-proc",
                    title=f"Terminate Malicious Process ({proc})",
                    action_type="kill_process",
                    command=f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue",
                    target=f"PID {pid} on {hostname}",
                    risk_level="MEDIUM",
                    explanation="Halts active shellcode injection and terminates attacker command execution."
                )
            )

        # 3. Perimeter Network Block
        for ip in malicious_ips:
            actions.append(
                PlaybookAction(
                    id=f"act-block-ip-{ip.replace('.', '-')}",
                    title=f"Block C2 IP ({ip}) at Perimeter Firewall",
                    action_type="network_block",
                    command=f"iptables -I FORWARD 1 -s {ip} -j DROP; iptables -I INPUT 1 -s {ip} -j DROP",
                    target=f"Edge Gateway / Firewall -> {ip}",
                    risk_level="LOW",
                    explanation=f"Drops all ingress and egress packets associated with confirmed malicious IP {ip}."
                )
            )

        return actions

    def generate_sigma_rule(self, alert: NormalizedAlert) -> str:
        """
        Generates production-standard Sigma detection YAML rule.
        """
        title = alert.signature or "Suspicious Process Execution"
        proc = alert.process_name or "powershell.exe"
        cli = alert.command_line or "encodedcommand"
        
        rule = f"""title: Detection - {title}
id: soc-auto-{abs(hash(title)) % 10000000}
status: experimental
description: Automatically generated Sigma rule from SentinelAI Autonomous SOC incident triage.
references:
    - https://attack.mitre.org
author: SentinelAI Autonomous SOC Agent
date: 2026/10/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '{proc.split(chr(92))[-1]}'
        CommandLine|contains:
            - '{cli[:40] if cli else "bypass"}'
    condition: selection
falsepositives:
    - Administrative automation scripts
level: high
tags:
    - attack.execution
    - attack.defense_evasion
"""
        return rule

    def generate_yara_rule(self, alert: NormalizedAlert) -> str:
        """
        Generates YARA signature for memory / disk scanning.
        """
        proc_clean = alert.process_name.split("\\")[-1] if alert.process_name else "malware"
        rule_name = f"APT_Suspicious_{abs(hash(alert.signature or 'rule')) % 1000000}"
        
        yara = f"""rule {rule_name}
{{
    meta:
        description = "Automated YARA rule generated for {alert.signature}"
        author = "SentinelAI Threat Engine"
        date = "2026-10-02"
        severity = "{alert.severity.value}"
    strings:
        $str1 = "VirtualAllocEx" ascii wide nocase
        $str2 = "CreateRemoteThread" ascii wide nocase
        $str3 = "{proc_clean}" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($str*))
}}"""
        return yara

    def generate_firewall_script(self, malicious_ips: List[str]) -> str:
        if not malicious_ips:
            return "# No external malicious IPs required containment for this incident."
        
        lines = [
            "# ===========================================",
            "# SentinelAI Emergency Perimeter Containment",
            "# PowerShell Host & Windows Defender Firewall",
            "# ==========================================="
        ]
        for ip in malicious_ips:
            lines.append(f"New-NetFirewallRule -DisplayName 'SOC-Block-{ip}' -Direction Outbound -Action Block -RemoteAddress '{ip}'")
            lines.append(f"New-NetFirewallRule -DisplayName 'SOC-Block-{ip}-In' -Direction Inbound -Action Block -RemoteAddress '{ip}'")
            
        lines.append("\n# Linux iptables rules:")
        for ip in malicious_ips:
            lines.append(f"iptables -A INPUT -s {ip} -j DROP")
            lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")
            
        return "\n".join(lines)

playbook_generator = PlaybookGenerator()
