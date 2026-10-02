import re
from typing import Dict, Any, Optional
from datetime import datetime
from ..models.schemas import NormalizedAlert, LogSource, SeverityLevel

class SysmonParser:
    """
    Parses Windows Sysmon events into standardized NormalizedAlert format.
    Handles Event ID 1 (Process Create), Event ID 3 (Network Connect),
    Event ID 8 (CreateRemoteThread), Event ID 11 (File Create).
    """

    def parse(self, raw_data: Dict[str, Any]) -> NormalizedAlert:
        event_id = str(raw_data.get("EventID") or raw_data.get("event_id") or "1")
        timestamp = raw_data.get("UtcTime") or raw_data.get("timestamp") or datetime.utcnow().isoformat()
        computer = raw_data.get("Computer") or raw_data.get("hostname") or "WIN-ENDPOINT-01"
        user = raw_data.get("User") or raw_data.get("user") or "SYSTEM"
        
        # Process and Parent details
        image = raw_data.get("Image") or raw_data.get("image") or ""
        command_line = raw_data.get("CommandLine") or raw_data.get("command_line") or ""
        parent_image = raw_data.get("ParentImage") or raw_data.get("parent_image") or ""
        process_id = raw_data.get("ProcessId") or raw_data.get("process_id")
        
        # Hashes (Sysmon format: "SHA256=...,MD5=...")
        raw_hashes = raw_data.get("Hashes") or raw_data.get("hashes") or ""
        hash_dict = self._parse_hashes(raw_hashes)

        # Network details
        dest_ip = raw_data.get("DestinationIp") or raw_data.get("dest_ip")
        dest_port = raw_data.get("DestinationPort") or raw_data.get("dest_port")
        src_ip = raw_data.get("SourceIp") or raw_data.get("src_ip")
        src_port = raw_data.get("SourcePort") or raw_data.get("src_port")
        protocol = raw_data.get("Protocol") or raw_data.get("protocol")
        
        # File operations
        target_filename = raw_data.get("TargetFilename") or raw_data.get("target_filename")

        # Determine signature and initial severity
        signature = f"Sysmon Event ID {event_id}: "
        severity = SeverityLevel.MEDIUM
        
        if event_id == "1":
            proc_basename = image.split("\\")[-1] if image else "Unknown"
            signature += f"Process Creation ({proc_basename})"
            if any(term in command_line.lower() for term in ["-enc", "downloadstring", "iex", "bypass", "vssadmin delete"]):
                severity = SeverityLevel.HIGH
        elif event_id == "3":
            signature += f"Network Connection to {dest_ip}:{dest_port}"
            severity = SeverityLevel.LOW
        elif event_id == "8":
            target_image = raw_data.get("TargetImage") or "Unknown"
            signature += f"CreateRemoteThread (Injection into {target_image.split(chr(92))[-1]})"
            severity = SeverityLevel.CRITICAL
        elif event_id == "11":
            signature += f"File Created ({target_filename})"
            if target_filename and any(ext in target_filename.lower() for ext in [".lockbit", ".locked", ".readme.txt"]):
                severity = SeverityLevel.CRITICAL
        else:
            signature += f"Activity on {computer}"

        return NormalizedAlert(
            alert_id=raw_data.get("alert_id") or f"sysmon-{event_id}-{int(datetime.utcnow().timestamp())}",
            timestamp=timestamp,
            log_source=LogSource.WINDOWS_SYSMON,
            event_id=event_id,
            signature=signature,
            severity=severity,
            src_ip=src_ip,
            src_port=int(src_port) if src_port else None,
            dest_ip=dest_ip,
            dest_port=int(dest_port) if dest_port else None,
            protocol=protocol,
            hostname=computer,
            user=user,
            process_name=image,
            process_id=int(process_id) if process_id else None,
            parent_process=parent_image,
            command_line=command_line,
            file_hashes=hash_dict,
            target_filename=target_filename,
            raw_payload=raw_data
        )

    def _parse_hashes(self, hash_str: Any) -> Dict[str, str]:
        if isinstance(hash_str, dict):
            return hash_str
        if not isinstance(hash_str, str):
            return {}
        
        result = {}
        for part in hash_str.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                result[k.strip().lower()] = v.strip().lower()
        return result

sysmon_parser = SysmonParser()
