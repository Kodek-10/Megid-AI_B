# routers/guardian.py
# Endpoints du Mode Ange Gardien

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from services.notification import notification_service
from services.db_service import db_service
from database import get_db

router = APIRouter(prefix="/guardian", tags=["Mode Ange Gardien"])


# ── Modèles de requêtes ───────────────────────────────────────────────────────

class RegisterPairRequest(BaseModel):
    """Créer une relation Protégé ↔ Ange Gardien."""
    protected_device_id: str
    guardian_device_id: str
    guardian_fcm_token: str
    protected_name: Optional[str] = "Proche protégé"
    sensitivity_mode: Optional[str] = "balanced"


class AlertRequest(BaseModel):
    """Déclencher une alerte vers l'Ange Gardien."""
    protected_device_id: str
    threat_type: str         # "phishing_sms", "malicious_url", "data_breach"
    threat_level: str        # "suspect" ou "danger"
    risk_score: int
    threat_description: Optional[str] = ""


class DeviceRegistration(BaseModel):
    """Enregistrer le token FCM d'un appareil."""
    device_id: str
    fcm_token: str


class WeeklyReportRequest(BaseModel):
    """Déclencher l'envoi d'un rapport hebdomadaire."""
    guardian_fcm_token: str
    protected_name: str
    threats_blocked: int
    resilience_score: int


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register-device")
async def register_device(request: DeviceRegistration):
    """
    Enregistre le token FCM d'un appareil.
    Appelé par l'app Flutter au démarrage pour permettre
    la réception de notifications.
    """
    result = await notification_service.register_device(
        device_id=request.device_id,
        fcm_token=request.fcm_token,
    )
    return result


@router.post("/pair")
async def create_guardian_pair(
    request: RegisterPairRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Crée une relation Protégé ↔ Ange Gardien.
    
    Exemple : Kader (guardian) protège Marcel (protected).
    Kader recevra des alertes si Marcel est en danger.
    
    La personne protégée doit avoir accepté cette relation
    dans son application Megidai (consentement explicite).
    """
    result = await db_service.create_guardian_pair(
        db=db,
        protected_device_id=request.protected_device_id,
        guardian_device_id=request.guardian_device_id,
        guardian_fcm_token=request.guardian_fcm_token,
        protected_name=request.protected_name,
    )

    return {
        "status": "success",
        "message": f"Relation créée : {request.protected_name} est maintenant protégé(e).",
        "pair": result,
        "sensitivity_mode": request.sensitivity_mode,
    }


@router.post("/alert")
async def send_guardian_alert(
    request: AlertRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Déclenche une alerte vers tous les Anges Gardiens d'un utilisateur.
    
    Appelé automatiquement par l'app Flutter quand :
    - Un SMS de phishing est détecté (score > 85)
    - Un lien dangereux est bloqué (score > 85)
    - Une fuite de données critique est trouvée
    
    GARANTIE : aucune donnée personnelle de la personne protégée
    n'est transmise aux Anges Gardiens.
    """

    # ── Récupérer les Anges Gardiens de cette personne ────────────────
    guardians = await db_service.get_guardians(
        db=db,
        protected_device_id=request.protected_device_id
    )

    if not guardians:
        return {
            "status": "no_guardians",
            "message": "Aucun Ange Gardien configuré pour cet utilisateur.",
            "alerts_sent": 0,
        }

    # ── Envoyer une alerte à chaque Ange Gardien ──────────────────────
    alerts_sent = 0
    results = []

    for guardian in guardians:
        fcm_token = guardian.get("guardian_fcm_token")

        if not fcm_token:
            continue

        # Envoyer la notification
        notif_result = await notification_service.send_guardian_alert(
            guardian_fcm_token=fcm_token,
            protected_name="Proche protégé",  # Nom anonymisé par défaut
            threat_type=request.threat_type,
            threat_level=request.threat_level,
            risk_score=request.risk_score,
            threat_description=request.threat_description,
        )

        # Enregistrer l'alerte dans la base de données
        await db_service.log_alert(
            db=db,
            protected_device_id=request.protected_device_id,
            guardian_device_id=guardian["guardian_device_id"],
            threat_type=request.threat_type,
            threat_level=request.threat_level,
            risk_score=request.risk_score,
            notification_sent=notif_result.get("status") in ["sent", "simulated"],
        )

        alerts_sent += 1
        results.append({
            "guardian": guardian["guardian_device_id"][:8] + "...",
            "status": notif_result.get("status"),
        })

    return {
        "status": "success",
        "alerts_sent": alerts_sent,
        "total_guardians": len(guardians),
        "results": results,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/guardians/{protected_device_id}")
async def get_my_guardians(
    protected_device_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retourne la liste des Anges Gardiens d'un utilisateur.
    Appelé par l'app Flutter pour afficher l'écran Ange Gardien.
    """
    guardians = await db_service.get_guardians(
        db=db,
        protected_device_id=protected_device_id
    )

    return {
        "protected_device_id": protected_device_id[:8] + "...",
        "guardians_count": len(guardians),
        "guardians": [
            {
                "guardian_id": g["guardian_device_id"][:8] + "...",
                "sensitivity_mode": g["sensitivity_mode"],
                "has_fcm_token": bool(g.get("guardian_fcm_token")),
            }
            for g in guardians
        ],
    }


@router.post("/weekly-report")
async def send_weekly_report(request: WeeklyReportRequest):
    """
    Envoie le rapport hebdomadaire à un Ange Gardien.
    En production : appelé automatiquement chaque dimanche à 9h.
    Pour le hackathon : appelé manuellement pour la démo.
    """
    result = await notification_service.send_weekly_report(
        guardian_fcm_token=request.guardian_fcm_token,
        protected_name=request.protected_name,
        threats_blocked=request.threats_blocked,
        resilience_score=request.resilience_score,
    )
    return result


@router.get("/test-notification/{fcm_token}")
async def test_notification(fcm_token: str):
    """
    Envoie une notification de test.
    Utile pour vérifier que Firebase est bien configuré
    et que le token FCM est valide.
    """
    result = await notification_service.send_guardian_alert(
        guardian_fcm_token=fcm_token,
        protected_name="Utilisateur Test",
        threat_type="test",
        threat_level="suspect",
        risk_score=55,
        threat_description="Ceci est une notification de test Megidai.",
    )
    return result