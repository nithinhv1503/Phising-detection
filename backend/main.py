"""
FastAPI Backend Service for AI-Powered Phishing Website Detection.
Provides real-time scoring, DOM parsing, Threat Intel management, and metric feeds.
"""

import os
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.predictor import predictor
from backend.threat_intel import threat_intel

# Initialize FastAPI
app = FastAPI(
    title="AI-Powered Intelligent Phishing Detection API",
    description="Real-time URL risk scoring, feature explainability, and browser security service.",
    version="1.0.0"
)

# Enable CORS for Chrome Extensions and Web Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request & Response Schemas
class PredictRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze for phishing risks", example="http://paypal.com.account-update.xyz/login")
    html: Optional[str] = Field(None, description="Optional raw HTML content for DOM inspection")


class DOMAnalyzeRequest(BaseModel):
    url: str
    html: str


class ReportRequest(BaseModel):
    url: str = Field(..., description="The reported URL")
    report_type: str = Field(..., description="'phishing' or 'false_positive'")
    comments: Optional[str] = Field("", description="User notes or context")


class WhitelistBlocklistRequest(BaseModel):
    entry: str = Field(..., description="Domain or URL to add")


# --- API Routes ---

@app.get("/api/v1/health")
async def health_check():
    """Service liveness and model status check."""
    return {
        "status": "healthy",
        "model_loaded": predictor.model is not None,
        "champion_model": predictor.metrics.get("champion_model", "Random Forest Ensemble"),
        "version": "1.0.0"
    }


@app.post("/api/v1/predict")
async def predict_url_risk(payload: PredictRequest):
    """
    Score a URL in real time. Returns risk score (0-100), verdict, confidence,
    risk factors, and lexical/structural feature breakdown.
    """
    if not payload.url or not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    
    result = predictor.predict(url=payload.url, html=payload.html)
    return result


@app.post("/api/v1/analyze-dom")
async def analyze_page_dom(payload: DOMAnalyzeRequest):
    """Perform in-depth DOM and structural analysis on client-rendered HTML."""
    result = predictor.predict(url=payload.url, html=payload.html)
    return result


@app.post("/api/v1/report")
async def submit_user_report(payload: ReportRequest):
    """Ingest user feedback for retraining and immediate blocklist/whitelist adjustment."""
    record = threat_intel.log_user_report(
        url=payload.url,
        report_type=payload.report_type,
        comments=payload.comments
    )
    return {
        "status": "success",
        "message": f"Report submitted for {payload.url} as {payload.report_type}",
        "record": record
    }


@app.get("/api/v1/metrics")
async def get_model_metrics():
    """Retrieve full evaluation metrics, confusion matrix, ROC-AUC curve, and feature importances."""
    if not predictor.metrics:
        predictor.load_model()
    return predictor.metrics


@app.get("/api/v1/threat-intel")
async def get_threat_intel_summary():
    """Retrieve overview of Whitelist, Blocklist, and recent user telemetry."""
    return {
        "whitelist_count": len(threat_intel.whitelist),
        "blocklist_count": len(threat_intel.blocklist),
        "user_reports_count": len(threat_intel.user_reports),
        "sample_whitelisted": list(threat_intel.whitelist)[:15],
        "sample_blacklisted": list(threat_intel.blocklist)[:15],
        "recent_reports": threat_intel.user_reports[-10:]
    }


@app.post("/api/v1/threat-intel/whitelist")
async def add_whitelist_entry(payload: WhitelistBlocklistRequest):
    """Add a domain to custom whitelist."""
    threat_intel.add_to_whitelist(payload.entry)
    return {"status": "success", "message": f"Added '{payload.entry}' to Whitelist."}


@app.post("/api/v1/threat-intel/blocklist")
async def add_blocklist_entry(payload: WhitelistBlocklistRequest):
    """Add a domain or URL to custom blocklist."""
    threat_intel.add_to_blocklist(payload.entry)
    return {"status": "success", "message": f"Added '{payload.entry}' to Blocklist."}


# Mount Web Management Dashboard static files if directory exists
DASHBOARD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
if os.path.exists(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

    @app.get("/")
    async def serve_dashboard():
        index_file = os.path.join(DASHBOARD_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "AI Phishing Detection API is Running. Dashboard not found."}
