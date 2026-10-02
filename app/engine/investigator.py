import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..models.schemas import (
    NormalizedAlert,
    InvestigationReport,
    IncidentVerdict,
    IncidentStatus,
    IOCItem,
    IOCType,
    MitreTTP,
    TimelineEvent
)
from ..parsers.normalizer import log_normalizer
from ..threat_intel.abuseipdb import abuse_client
from ..threat_intel.virustotal import virustotal_client
from ..threat_intel.mitre_mapper import mitre_mapper
from .llm_client import llm_client
from .playbook_generator import playbook_generator
from .scenarios import SCENARIOS

logger = logging.getLogger("SentinelAI.Investigator")

class SOCInvestigator:
    """
    Main Autonomous SOC Analyst Investigation Pipeline.
    Orchestrates alert normalization, threat intel enrichment,
    MITRE ATT&CK classification, LLM reasoning, and defense automation.
    """

    def __init__(self):
        # In-memory store for investigated incidents
        self.incidents: Dict[str, InvestigationReport] = {}
        self._init_default_scenarios()

    def _init_default_scenarios(self):
        """Pre-loads default demo incidents asynchronously upon startup if needed."""
        pass

    async def investigate_alert(
        self,
        raw_log: Dict[str, Any],
        correlated_events: Optional[List[Dict[str, Any]]] = None
    ) -> InvestigationReport:
        # 1. Normalize alert
        normalized = log_normalizer.normalize(raw_log)

        # 2. Extract IOCs
        raw_iocs = log_normalizer.extract_iocs(normalized)

        # 3. Enrich IOCs via Threat Intelligence
        enriched_iocs: List[IOCItem] = []
        for ioc in raw_iocs:
            ioc_type = ioc["type"]
            val = ioc["value"]
            if ioc_type == IOCType.IP:
                item = await abuse_client.check_ip(val)
                enriched_iocs.append(item)
            elif ioc_type in [IOCType.SHA256, IOCType.MD5]:
                item = await virustotal_client.check_hash(val)
                enriched_iocs.append(item)
            elif ioc_type == IOCType.DOMAIN:
                item = await virustotal_client.check_domain(val)
                enriched_iocs.append(item)

        # 4. Map to MITRE ATT&CK Framework
        ttps: List[MitreTTP] = mitre_mapper.map_alert(normalized)

        # 5. Build Timeline
        timeline: List[TimelineEvent] = []
        if correlated_events:
            for ev in correlated_events:
                timeline.append(TimelineEvent(**ev))
        else:
            # Generate baseline event from alert itself
            timeline.append(
                TimelineEvent(
                    timestamp=normalized.timestamp or datetime.utcnow().isoformat(),
                    stage="Detection",
                    description=f"Alert triggered: {normalized.signature}",
                    source=normalized.log_source.value,
                    severity=normalized.severity
                )
            )

        # 6. Run AI Reasoning & Investigation Agent
        ai_res = await llm_client.generate_investigation(normalized, enriched_iocs, ttps, timeline)

        verdict_str = ai_res.get("verdict", "SUSPICIOUS")
        try:
            verdict = IncidentVerdict(verdict_str)
        except ValueError:
            verdict = IncidentVerdict.SUSPICIOUS

        # 7. Generate Defensive Playbooks & Rules
        malicious_ips = [
            i.value for i in enriched_iocs
            if i.ioc_type == IOCType.IP and (i.is_malicious or i.reputation_score >= 60)
        ]
        file_hashes = [
            i.value for i in enriched_iocs
            if i.ioc_type in [IOCType.SHA256, IOCType.MD5]
        ]
        
        playbooks = playbook_generator.generate_playbook(normalized, malicious_ips, file_hashes)
        sigma_rule = playbook_generator.generate_sigma_rule(normalized)
        yara_rule = playbook_generator.generate_yara_rule(normalized)
        firewall_script = playbook_generator.generate_firewall_script(malicious_ips)

        # 8. Assemble Full Investigation Report
        incident_id = f"INC-{int(datetime.utcnow().timestamp()) % 100000:05d}"
        
        report = InvestigationReport(
            incident_id=incident_id,
            alert_id=normalized.alert_id,
            title=f"Incident {incident_id}: {normalized.signature}",
            timestamp=normalized.timestamp or datetime.utcnow().isoformat(),
            log_source=normalized.log_source,
            severity=normalized.severity,
            status=IncidentStatus.TRIAGED,
            verdict=verdict,
            confidence_score=float(ai_res.get("confidence_score", 0.9)),
            ai_provider_used=ai_res.get("ai_provider_used", "SentinelAI Engine"),
            executive_summary=ai_res.get("executive_summary", ""),
            root_cause_analysis=ai_res.get("root_cause_analysis", ""),
            attack_killchain_phase=ai_res.get("attack_killchain_phase", "Initial Execution"),
            blast_radius=ai_res.get("blast_radius", "Local Host"),
            timeline=timeline,
            extracted_iocs=enriched_iocs,
            mitre_ttps=ttps,
            playbook_actions=playbooks,
            sigma_rule=sigma_rule,
            yara_rule=yara_rule,
            firewall_script=firewall_script,
            normalized_alert=normalized
        )

        self.incidents[incident_id] = report
        return report

    async def load_preset_scenario(self, scenario_id: str) -> Optional[InvestigationReport]:
        target = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
        if not target:
            return None
        return await self.investigate_alert(
            raw_log=target["primary_log"],
            correlated_events=target.get("correlated_events")
        )

    def get_incident(self, incident_id: str) -> Optional[InvestigationReport]:
        return self.incidents.get(incident_id)

    def list_incidents(self) -> List[InvestigationReport]:
        return list(self.incidents.values())

soc_investigator = SOCInvestigator()
