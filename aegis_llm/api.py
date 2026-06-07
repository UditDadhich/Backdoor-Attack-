import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List

from aegis_llm.core.ensemble_verifier import EnsembleVerifier
from aegis_llm.core.session_manager import StatefulSessionManager
from aegis_llm.detection.rag_verifier import RAGVerifier
from aegis_llm.utils.logger import AegisLogger

app = FastAPI(
    title="Aegis-LLM Security Gateway API",
    description="State-of-the-Art LLM Backdoor & Prompt Injection Defense Framework REST API",
    version="1.0.0"
)

# Initialize Aegis-LLM modules
verifier = EnsembleVerifier()
session_manager = StatefulSessionManager()
rag_verifier = RAGVerifier()
logger = AegisLogger()

# Pydantic models for request bodies
class ScanRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = "default_session"

class DocumentChunk(BaseModel):
    id: str
    content: str
    signature: Optional[str] = ""

class RAGVerifyRequest(BaseModel):
    query: str
    documents: List[DocumentChunk]

@app.post("/scan")
async def scan_prompt(req: ScanRequest):
    """
    Scans an input prompt through the multi-agent sanitization, injection, and trigger detectors.
    Tracks session history for multi-turn adversarial drifts.
    """
    try:
        # Run prompt through verification pipeline
        analysis = verifier.process_prompt(req.prompt)
        
        # Log session turn and compute cumulative risk EWMA
        session_id = req.session_id or "default_session"
        session_status = session_manager.register_turn(
            session_id=session_id,
            prompt=req.prompt,
            turn_risk=analysis["aggregate_risk_score"]
        )
        
        # Log to cryptographic ledger
        logger.log_event(request_id=f"REQ-{len(logger.get_audit_trail())+1:03d}", prompt_analysis=analysis)
        
        # Update verdict if session manager flags a multi-turn jailbreak
        if session_status["multi_turn_flagged"]:
            analysis["verdict"] = "BLOCK"
            analysis["breakdown"]["session_drift_triggered"] = session_status["flagged_reason"]
            
        return {
            "status": "success",
            "verdict": analysis["verdict"],
            "risk_score": analysis["aggregate_risk_score"],
            "sanitized_prompt": analysis["sanitized_prompt"],
            "session_status": session_status,
            "components": analysis["breakdown"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify_rag")
async def verify_rag(req: RAGVerifyRequest):
    """
    Scans context document chunks before injection into the LLM context workspace.
    Checks cryptographic document signature validation, indirect injections, and semantic drift.
    """
    try:
        # Convert Pydantic model array to list of dictionaries
        chunks = [{"id": doc.id, "content": doc.content, "signature": doc.signature} for doc in req.documents]
        report = rag_verifier.verify_context(req.query, chunks)
        return {"status": "success", "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/audit_trail")
async def get_audit_trail():
    """
    Retrieves the chronological cryptographic log ledger.
    """
    return {"status": "success", "trail": logger.get_audit_trail()}

@app.get("/verify_logs")
async def verify_logs():
    """
    Triggers an integrity check verifying that historical log chains have not been tampered with.
    """
    is_valid = logger.verify_log_integrity()
    return {
        "status": "success",
        "ledger_intact": is_valid,
        "total_records": len(logger.get_audit_trail())
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    """
    Serves the Aegis-LLM security dashboard HTML page.
    """
    # Locate templates folder relative to this file
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    if not os.path.exists(template_path):
        raise HTTPException(status_code=404, detail="Dashboard template not found")
        
    with open(template_path, "r", encoding="utf-8") as f:
        html_content = f.read()
        
    return HTMLResponse(content=html_content, status_code=200)

@app.get("/")
async def redirect_to_docs():
    """
    Root endpoint redirect instructions.
    """
    return {
        "message": "Aegis-LLM Security API Gateway active.",
        "dashboard_url": "/dashboard",
        "docs_url": "/docs"
    }
