import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from analyzer import analyse_text

app = FastAPI(title="JCTC CyberGuard API", version="0.1.0")

allowed = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in allowed if x.strip()],
    allow_credentials=False,
    allow_methods=["POST","GET"],
    allow_headers=["Content-Type"],
)

class AnalysisRequest(BaseModel):
    text: str = Field(max_length=20000)
    reply_mismatch: bool = False
    minor_involved: bool = False

@app.get("/health")
def health():
    return {"status":"ok","service":"JCTC CyberGuard API"}

@app.post("/analyze")
def analyze(req: AnalysisRequest):
    # Privacy-first: input is analysed in memory and is not persisted by this application.
    return analyse_text(req.text,{"reply_mismatch":req.reply_mismatch,"minor_involved":req.minor_involved})
