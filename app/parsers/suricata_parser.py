from typing import Dict, Any, Optional
from datetime import datetime
from ..models.schemas import NormalizedAlert, LogSource, SeverityLevel

class SuricataParser:
    """
    Parses Suricata EVE (Extensible Event Format) JSON records.
    Handles network intrusion alerts, C2 signatures, and protocol anomalies.
    """

    def parse(self, raw_data: Dict[str, Any]) -> NormalizedAlert:
        timestamp = raw_data.get("timestamp") or datetime.utcnow().isoformat()
        
        # Alert sub-object
        alert_info = raw_data.get("alert", {})
        signature = alert_info.get("signature") or raw_data.get("signature") or "Suricata Network Anomaly Detected"
        category = alert_info.get("category", "")
        raw_sev = alert_info.get("severity", 2)
        
        # Suricata severity: 1=High, 2=Medium, 3=Low, 4=Info
        severity_map = {
            1: SeverityLevel.CRITICAL if "cobalt strike" in signature.lower() or "c2" in signature.lower() else SeverityLevel.HIGH,
            2: SeverityLevel.MEDIUM,
            3: SeverityLevel.LOW,
            4: SeverityLevel.INFORMATIONAL
        }
        severity = severity_map.get(raw_sev, SeverityLevel.MEDIUM)

        # Network flow
        src_ip = raw_data.get("src_ip")
        src_port = raw_data.get("src_port")
        dest_ip = raw_data.get("dest_ip")
        dest_port = raw_data.get("dest_port")
        proto = raw_data.get("proto", "TCP")

        # HTTP layer metadata
        http_info = raw_data.get("http", {})
        http_host = http_info.get("hostname")
        http_url = http_info.get("url")
        http_ua = http_info.get("http_user_agent")

        # TLS layer metadata
        tls_info = raw_data.get("tls", {})
        if not http_host and tls_info.get("sni"):
            http_host = tls_info.get("sni")

        alert_id = raw_data.get("alert_id") or f"suricata-{int(datetime.utcnow().timestamp())}"

        return NormalizedAlert(
            alert_id=alert_id,
            timestamp=timestamp,
            log_source=LogSource.SURICATA_NIDS,
            signature=f"[{category}] {signature}" if category else signature,
            severity=severity,
            src_ip=src_ip,
            src_port=int(src_port) if src_port else None,
            dest_ip=dest_ip,
            dest_port=int(dest_port) if dest_port else None,
            protocol=proto,
            http_host=http_host,
            http_url=http_url,
            http_user_agent=http_ua,
            raw_payload=raw_data
        )

suricata_parser = SuricataParser()
