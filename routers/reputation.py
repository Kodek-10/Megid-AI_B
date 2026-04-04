
# routers/reputation.py
# Endpoints FastAPI pour l'analyse d'URLs et la réputation communautaire

from fastapi import APIRouter, HTTPException, BackgroundTasks
from datetime import datetime
from models.report import ScanRequest, ScanResult, URLReport
from services.url_analyzer import url_analyzer

# APIRouter = groupe de routes liées entre elles
# prefix = préfixe ajouté à toutes les routes de ce fichier
# tags = regroupement dans la documentation automatique FastAPI
router = APIRouter(prefix="/reputation", tags=["Réputation & Analyse"])


@router.post("/scan", response_model=dict)
async def scan_url(request: ScanRequest):
    """
    Analyse une URL et retourne le score de risque Megidai.
    Appelé par l'app Flutter lors de l'Intent Interceptor.

    - Score 0-40  → VERT  (safe)
    - Score 41-70 → ORANGE (suspect)
    - Score 71-100 → ROUGE (danger)
    """
    try:
        result = await url_analyzer.analyze(
            url=request.url,
            context=request.context or ""
        )
        return result

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de l'analyse : {str(e)}"
        )


@router.post("/report")
async def report_url(report: URLReport, background_tasks: BackgroundTasks):
    """
    Reçoit le signalement d'une URL par un utilisateur.
    'malicious' = arnaque confirmée
    'safe'      = faux positif (site légitime mal détecté)

    BackgroundTasks = traitement en arrière-plan sans bloquer la réponse
    """
    # Traiter le signalement en arrière-plan
    background_tasks.add_task(_process_report, report)

    return {
        "status": "received",
        "message": "Signalement reçu. Merci de contribuer à la sécurité de la communauté Megidai.",
        "report_id": f"RPT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    }


@router.get("/whitelist/check")
async def check_whitelist(url: str):
    """
    Vérifie si une URL est dans la liste blanche officielle Megidai.
    Utilisé par l'app Flutter pour les vérifications rapides.
    """
    from services.url_analyzer import GLOBAL_WHITELIST
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        is_whitelisted = domain in GLOBAL_WHITELIST

        return {
            "url": url,
            "domain": domain,
            "is_whitelisted": is_whitelisted,
        }
    except Exception:
        return {"url": url, "is_whitelisted": False}


async def _process_report(report: URLReport):
    """
    Traitement en arrière-plan d'un signalement.
    À connecter à la base de données dans une prochaine étape.
    """
    print(f"[SIGNALEMENT] {report.report_type.upper()} — {report.url} — Source: {report.source}")
    # TODO : sauvegarder en base de données
    # TODO : si > 5 signalements malveillants → ajouter à la liste noire automatiquement
