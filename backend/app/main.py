from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from .detector import analyze_content
from .schemas import AnalyzeRequest, AnalysisResponse

app = FastAPI(title="AgentShield API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "AgentShield"}


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze(request: AnalyzeRequest) -> AnalysisResponse:
    try:
        result = analyze_content(url=request.url, text=request.text, links=[link.model_dump() for link in request.links])
        return AnalysisResponse(**result)
    except ValidationError as exc:  # pragma: no cover - defensive programming
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except Exception as exc:  # pragma: no cover - defensive programming
        raise HTTPException(status_code=500, detail={"message": "Analysis failed", "error": str(exc)}) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
