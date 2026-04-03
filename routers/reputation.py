# routers/reputation.py — version complète avec base de données
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
from models.report import ScanRequest, URLReport
from services.url_analyzer import url_analyzer
from services.db_service import db_service
from database import get_db

router = APIRouter(prefix="/reputation", tags=["Réputation & Analyse"])


@router.post("/scan")
async def scan_url(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db)  # Injection de la session DB
):
    """
    Analyse une URL et retourne le score de risque Megidai.
    Depends(get_db) = FastAPI injecte automatiquement une session DB.
    """
    try:
        # ── Vérifier d'abord la réputation communautaire ──────────────
        community_data = await db_service.get_url_reputation(db, request.url)

        # Si l'URL est dans la liste noire → bloquer directement
        if community_data and community_data.get("is_blacklisted"):
            return {
                "url": request.url,
                "risk_score": 95,
                "level": "danger",
                "reasons": [{
                    "icon": "🚨",
                    "text": f"URL bloquée — signalée {community_data['malicious_reports']} fois par la communauté Megidai",
                    "points": 95,
                    "positive": False
                }],
                "community_reports": community_data["malicious_reports"],
                "is_blacklisted": True,
                "analysis_time_ms": 1,
            }

        # ── Analyse complète ──────────────────────────────────────────
        result = await url_analyzer.analyze(
            url=request.url,
            context=request.context or ""
        )

        # Enrichir avec les données communautaires
        if community_data:
            result["community_reports"] = community_data["malicious_reports"]
            result["is_whitelisted"] = community_data["is_whitelisted"]

            # Si signalée comme sûre plusieurs fois → réduire le score
            if community_data["safe_reports"] >= 3:
                result["risk_score"] = max(0, result["risk_score"] - 20)
                result["reasons"].append({
                    "icon": "✅",
                    "text": f"Signalée comme sûre par {community_data['safe_reports']} utilisateurs",
                    "points": -20,
                    "positive": True
                })

        # ── Logger l'analyse en arrière-plan ──────────────────────────
        await db_service.log_scan(
            db=db,
            url=request.url,
            risk_score=result["risk_score"],
            level=result["level"],
            source=request.source,
            analysis_time_ms=result.get("analysis_time_ms", 0)
        )

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report")
async def report_url(
    report: URLReport,
    db: AsyncSession = Depends(get_db)
):
    """Enregistre un signalement communautaire."""
    result = await db_service.save_report(
        db=db,
        url=report.url,
        report_type=report.report_type,
        category=report.category,
        device_id=report.device_id,
        source=report.source,
    )
    return {
        "status": "received",
        "message": "Merci de contribuer à la sécurité de la communauté Megidai.",
        "result": result
    }


@router.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Retourne les statistiques globales de la plateforme."""
    return await db_service.get_stats(db)


@router.get("/check/{domain}")
async def check_domain(domain: str, db: AsyncSession = Depends(get_db)):
    """Vérifie la réputation d'un domaine."""
    result = await db_service.get_domain_reputation(db, domain)
    if not result:
        return {"domain": domain, "status": "unknown", "risk_score": 0}
    return result