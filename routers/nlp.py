# Endpoints d'analyse NLP pour les SMS et messages

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from services.nlp_analyzer import nlp_analyzer

router = APIRouter(prefix="/nlp", tags=["Analyse NLP"])


class TextAnalysisRequest(BaseModel):
    text: str
    source: Optional[str] = None  # "sms", "whatsapp", "facebook"


class BatchAnalysisRequest(BaseModel):
    messages: List[str]


@router.post("/analyze")
async def analyze_text(request: TextAnalysisRequest):
    """
    Analyse un SMS ou message pour détecter le phishing.
    Appelé par l'app Flutter pour chaque SMS reçu.
    """
    if not request.text or len(request.text.strip()) < 2:
        raise HTTPException(status_code=400, detail="Texte trop court")

    result = nlp_analyzer.analyze_text(request.text)
    result["source"] = request.source
    return result


@router.post("/analyze-batch")
async def analyze_batch(request: BatchAnalysisRequest):
    """
    Analyse plusieurs messages en une seule requête.
    Utilisé pour le scan initial de la boîte SMS complète.
    """
    if not request.messages:
        raise HTTPException(status_code=400, detail="Liste de messages vide")

    if len(request.messages) > 100:
        raise HTTPException(
            status_code=400,
            detail="Maximum 100 messages par requête"
        )

    results = nlp_analyzer.analyze_batch(request.messages)

    # Résumé global
    dangerous = sum(1 for r in results if r["level"] == "danger")
    suspect = sum(1 for r in results if r["level"] == "suspect")

    return {
        "total_analyzed": len(results),
        "dangerous": dangerous,
        "suspect": suspect,
        "safe": len(results) - dangerous - suspect,
        "results": results
    }