from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class SeverityLevel(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LogSource(str, Enum):
    WINDOWS_SYSMON = "WINDOWS_SYSMON"
    SURICATA_NIDS = "SURICATA_NIDS"
    AWS_CLOUDTRAIL = "AWS_CLOUDTRAIL"
    GENERIC_SYSLOG = "GENERIC_SYSLOG"

class IncidentVerdict(str, Enum):
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"

class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA256 = "sha256"
    FILE_PATH = "file_path"
    CVE = "cve"

class IOCItem(BaseModel):
    ioc_type: IOCType
    value: str
    source_context: Optional[str] = None
    reputation_score: int = Field(default=0, ge=0, le=100, description="0=Safe, 100=Confirmed Malicious")
    is_malicious: bool = False
    provider: str = "Internal Heuristic"
    tags: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

class MitreTTP(BaseModel):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str] = None
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)
    matched_pattern: Optional[str] = None
    description: str

class PlaybookAction(BaseModel):
    id: str
    title: str
    action_type: str = Field(description="e.g. host_quarantine, network_block, kill_process, yara_rule")
    command: str
    target: str
    risk_level: str = "HIGH"
    explanation: str

class TimelineEvent(BaseModel):
    timestamp: str
    stage: str
    description: str
    source: str
    severity: SeverityLevel

class NormalizedAlert(BaseModel):
    alert_id: str
    timestamp: str
    log_source: LogSource
    event_id: Optional[str] = None
    signature: str
    severity: SeverityLevel
    
    # Network indicators
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    http_host: Optional[str] = None
    http_url: Optional[str] = None
    http_user_agent: Optional[str] = None
    
    # Endpoint indicators
    hostname: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    file_hashes: Dict[str, str] = Field(default_factory=dict)
    target_filename: Optional[str] = None
    
    raw_payload: Dict[str, Any] = Field(default_factory=dict)

class InvestigationReport(BaseModel):
    incident_id: str
    alert_id: str
    title: str
    timestamp: str
    log_source: LogSource
    severity: SeverityLevel
    status: IncidentStatus = IncidentStatus.TRIAGED
    
    # AI Verdict & Confidence
    verdict: IncidentVerdict
    confidence_score: float = Field(ge=0.0, le=1.0)
    ai_provider_used: str = "SentinelAI Autonomous Reasoner"
    
    # Deep Analysis
    executive_summary: str
    root_cause_analysis: str
    attack_killchain_phase: str
    blast_radius: str
    
    # Chronology & Telemetry
    timeline: List[TimelineEvent] = Field(default_factory=list)
    extracted_iocs: List[IOCItem] = Field(default_factory=list)
    mitre_ttps: List[MitreTTP] = Field(default_factory=list)
    
    # Defensive Artifacts
    playbook_actions: List[PlaybookAction] = Field(default_factory=list)
    sigma_rule: Optional[str] = None
    yara_rule: Optional[str] = None
    firewall_script: Optional[str] = None
    
    normalized_alert: NormalizedAlert

class ChatMessage(BaseModel):
    role: str # user, assistant, system
    content: str
    timestamp: Optional[str] = None

class ChatRequest(BaseModel):
    incident_id: str
    message: str
    history: List[ChatMessage] = Field(default_factory=list)

class ChatResponse(BaseModel):
    response: str
    suggested_commands: List[str] = Field(default_factory=list)
