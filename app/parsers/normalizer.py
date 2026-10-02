import re
from typing import Dict, Any, List, Set
from ..models.schemas import NormalizedAlert, LogSource, SeverityLevel, IOCItem, IOCType
from .sysmon_parser import sysmon_parser
from .suricata_parser import suricata_parser

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

class LogNormalizer:
    """
    Automated log classification and IOC extraction pipeline.
    Identifies log format, converts to unified NormalizedAlert,
    and extracts candidate Indicators of Compromise.
    """

    def normalize(self, raw_input: Dict[str, Any]) -> NormalizedAlert:
        # Check if it's Sysmon
        if "EventID" in raw_input or "event_id" in raw_input or raw_input.get("log_source") == LogSource.WINDOWS_SYSMON.value:
            return sysmon_parser.parse(raw_input)
        
        # Check if it's Suricata
        if "alert" in raw_input or raw_input.get("event_type") in ["alert", "flow", "dns", "http"] or raw_input.get("log_source") == LogSource.SURICATA_NIDS.value:
            return suricata_parser.parse(raw_input)

        # Fallback generic normalizer
        return NormalizedAlert(
            alert_id=raw_input.get("alert_id") or "alert-generic-01",
            timestamp=raw_input.get("timestamp") or "",
            log_source=LogSource.GENERIC_SYSLOG,
            signature=raw_input.get("message") or raw_input.get("signature") or "Generic Security Event",
            severity=SeverityLevel(raw_input.get("severity", "MEDIUM").upper()) if raw_input.get("severity") else SeverityLevel.MEDIUM,
            src_ip=raw_input.get("src_ip"),
            dest_ip=raw_input.get("dest_ip"),
            hostname=raw_input.get("hostname"),
            command_line=raw_input.get("command_line"),
            raw_payload=raw_input
        )

    def extract_iocs(self, alert: NormalizedAlert) -> List[Dict[str, Any]]:
        """
        Extracts all IP addresses, domains, and hashes found across alert fields.
        """
        found_iocs: List[Dict[str, Any]] = []
        seen_values: Set[str] = set()

        def add_ioc(ioc_type: IOCType, value: str, context: str):
            val_clean = value.strip().strip("'\"")
            if val_clean and val_clean not in seen_values:
                seen_values.add(val_clean)
                found_iocs.append({
                    "type": ioc_type,
                    "value": val_clean,
                    "context": context
                })

        # Explicit fields
        if alert.dest_ip:
            add_ioc(IOCType.IP, alert.dest_ip, "Destination IP")
        if alert.src_ip:
            add_ioc(IOCType.IP, alert.src_ip, "Source IP")
        if alert.http_host:
            add_ioc(IOCType.DOMAIN, alert.http_host, "HTTP Host header")
        if alert.http_url:
            add_ioc(IOCType.URL, alert.http_url, "HTTP Request URL")

        # Hashes in Sysmon
        for h_type, h_val in alert.file_hashes.items():
            if len(h_val) == 64:
                add_ioc(IOCType.SHA256, h_val, f"Process File Hash ({h_type.upper()})")
            elif len(h_val) == 32:
                add_ioc(IOCType.MD5, h_val, f"Process File Hash ({h_type.upper()})")

        # Scan command line and raw payload for regex matches
        search_blob = f"{alert.command_line or ''} {alert.signature or ''} {str(alert.raw_payload)}"
        
        for ip in IP_REGEX.findall(search_blob):
            if ip not in ["127.0.0.1", "0.0.0.0", "255.255.255.255"]:
                add_ioc(IOCType.IP, ip, "Discovered in payload / CLI")

        for sha in SHA256_REGEX.findall(search_blob):
            add_ioc(IOCType.SHA256, sha, "Discovered in command arguments")

        return found_iocs

log_normalizer = LogNormalizer()
