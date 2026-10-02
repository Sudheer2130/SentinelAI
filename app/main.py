import os
import logging
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .config import settings
from .models.schemas import (
    InvestigationReport,
    IncidentStatus,
    ChatRequest,
    ChatResponse
)
from .engine.investigator import soc_investigator
from .engine.scenarios import SCENARIOS
from .engine.llm_client import llm_client

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("SentinelAI.Main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-seed initial incidents on startup so UI is immediately active
    logger.info("Initializing SentinelAI Autonomous SOC Platform...")
    try:
        await soc_investigator.load_preset_scenario("scenario-cobalt-strike")
        await soc_investigator.load_preset_scenario("scenario-lockbit-ransomware")
        await soc_investigator.load_preset_scenario("scenario-false-positive-sccm")
        logger.info(f"Loaded {len(soc_investigator.incidents)} baseline attack scenarios.")
    except Exception as e:
        logger.error(f"Error loading initial scenarios: {e}")
    yield
    logger.info("Shutting down SentinelAI...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous AI SOC Analyst for SIEM Log Correlation, Threat Intel Hunting, and Incident Response",
    lifespan=lifespan
)

# Enable CORS for local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static folder
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/", response_class=FileResponse)
async def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "SentinelAI SOC Platform API is active. UI file not found."}

@app.get("/api/scenarios")
async def list_scenarios():
    """Returns available pre-configured attack simulation scenarios."""
    return SCENARIOS

@app.post("/api/scenarios/{scenario_id}/run", response_model=InvestigationReport)
async def run_scenario(scenario_id: str):
    """Triggers autonomous AI investigation of a preset attack scenario."""
    report = await soc_investigator.load_preset_scenario(scenario_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return report

@app.post("/api/investigate", response_model=InvestigationReport)
async def ingest_and_investigate(raw_payload: Dict[str, Any] = Body(...)):
    """Ingests custom raw Sysmon, Suricata, or generic log and runs full AI SOC triage."""
    try:
        report = await soc_investigator.investigate_alert(raw_payload)
        return report
    except Exception as e:
        logger.error(f"Investigation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents", response_model=List[InvestigationReport])
async def list_incidents():
    """Returns all triaged and investigated incidents."""
    return soc_investigator.list_incidents()

@app.get("/api/incidents/{incident_id}", response_model=InvestigationReport)
async def get_incident(incident_id: str):
    """Retrieves deep-dive investigation report for a specific incident."""
    inc = soc_investigator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc

@app.patch("/api/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, status: IncidentStatus = Body(..., embed=True)):
    """Updates the status of an incident (TRIAGED, INVESTIGATING, CONTAINED, RESOLVED)."""
    inc = soc_investigator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.status = status
    return {"status": inc.status.value, "incident_id": incident_id}

@app.post("/api/chat", response_model=ChatResponse)
async def chat_with_copilot(req: ChatRequest):
    """Conversational SOC Analyst Copilot grounded in active incident context."""
    inc = soc_investigator.get_incident(req.incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    result = await llm_client.chat_investigation(inc, req.message, req.history)
    return ChatResponse(
        response=result.get("response", "No response generated"),
        suggested_commands=result.get("suggested_commands", [])
    )

@app.get("/api/stats")
async def get_soc_metrics():
    """Aggregates SOC performance metrics, MTTR reduction, and MITRE distributions."""
    incidents = soc_investigator.list_incidents()
    total = len(incidents)
    critical_count = sum(1 for i in incidents if i.severity.value == "CRITICAL")
    high_count = sum(1 for i in incidents if i.severity.value == "HIGH")
    fp_count = sum(1 for i in incidents if i.verdict.value == "FALSE_POSITIVE")
    tp_count = sum(1 for i in incidents if i.verdict.value == "TRUE_POSITIVE")

    # Extract top MITRE tactics
    tactic_counts: Dict[str, int] = {}
    for inc in incidents:
        for ttp in inc.mitre_ttps:
            tactic_counts[ttp.tactic_name] = tactic_counts.get(ttp.tactic_name, 0) + 1

    return {
        "total_alerts_analyzed": total,
        "critical_incidents": critical_count,
        "high_incidents": high_count,
        "true_positives": tp_count,
        "false_positive_rate": f"{(fp_count / total * 100):.1f}%" if total > 0 else "0%",
        "estimated_hours_saved": total * 1.5,
        "active_mitre_tactics": tactic_counts,
        "llm_engine_status": "ONLINE (Gemini/Groq/Ollama/Heuristic Hybrid)"
    }

@app.get("/api/incidents/{incident_id}/export/markdown", response_class=PlainTextResponse)
async def export_markdown_report(incident_id: str):
    """Exports a professional incident audit report in Markdown format."""
    inc = soc_investigator.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    md = f"""# SentinelAI Incident Audit Report
**Incident ID**: {inc.incident_id}  
**Timestamp**: {inc.timestamp}  
**Verdict**: {inc.verdict.value} (Confidence: {int(inc.confidence_score * 100)}%)  
**Severity**: {inc.severity.value}  
**Status**: {inc.status.value}  
**AI Analysis Provider**: {inc.ai_provider_used}  

---

## 1. Executive Summary
{inc.executive_summary}

## 2. Root Cause Analysis & Kill-Chain
- **Attack Phase**: {inc.attack_killchain_phase}
- **Technical Analysis**: {inc.root_cause_analysis}
- **Estimated Blast Radius**: {inc.blast_radius}

## 3. Targeted Assets & Network Context
- **Target Hostname**: `{inc.normalized_alert.hostname or 'N/A'}`
- **User Account**: `{inc.normalized_alert.user or 'N/A'}`
- **Process Executed**: `{inc.normalized_alert.process_name or 'N/A'}`
- **Command Line**: `{inc.normalized_alert.command_line or 'N/A'}`
- **Network Traffic**: `{inc.normalized_alert.src_ip}:{inc.normalized_alert.src_port} -> {inc.normalized_alert.dest_ip}:{inc.normalized_alert.dest_port}`

## 4. Threat Intelligence & Extracted IOCs
| Type | Indicator | Reputation Score | Malicious | Tags |
| :--- | :--- | :--- | :--- | :--- |
"""
    for ioc in inc.extracted_iocs:
        md += f"| {ioc.ioc_type.value} | `{ioc.value}` | {ioc.reputation_score}/100 | {'YES' if ioc.is_malicious else 'NO'} | {', '.join(ioc.tags)} |\n"

    md += """
## 5. MITRE ATT&CK Classification
| Tactic | Technique ID | Technique Name | Confidence |
| :--- | :--- | :--- | :--- |
"""
    for ttp in inc.mitre_ttps:
        md += f"| {ttp.tactic_name} | `{ttp.technique_id}` | {ttp.technique_name} | {int(ttp.confidence * 100)}% |\n"

    md += """
## 6. Containment Playbook Actions Executed / Recommended
"""
    for action in inc.playbook_actions:
        md += f"### {action.title} (Risk: {action.risk_level})\n"
        md += f"- **Target**: `{action.target}`\n"
        md += f"- **Reason**: {action.explanation}\n"
        md += f"```powershell\n{action.command}\n```\n\n"

    if inc.sigma_rule:
        md += f"## 7. Generated Sigma Detection Rule\n```yaml\n{inc.sigma_rule}\n```\n"

    if inc.yara_rule:
        md += f"## 8. Generated YARA Hunting Signature\n```c\n{inc.yara_rule}\n```\n"

    return md
