from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from codebot.auditor import run_full_audit

app = FastAPI(title="CodeBot API", version="3.3")

class ScanRequest(BaseModel):
    github_url: str
    min_confidence: float = 0.60

@app.post("/scan")
def scan_repo(payload: ScanRequest):
    try:
        findings = run_full_audit(payload.github_url, min_confidence=payload.min_confidence)
        has_critical = any(f.severity == "Critical" for f in findings)
        return {
            "status": "DANGER" if has_critical else "SAFE",
            "target": payload.github_url,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
