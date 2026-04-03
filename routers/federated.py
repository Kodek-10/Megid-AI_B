# routers/federated.py
# Endpoints du Federated Learning

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from models.gradient import GradientModel
from services.fed_averaging import fed_service
from database import get_db

router = APIRouter(prefix="/federated", tags=["Federated Learning"])


@router.post("/gradients")
async def receive_gradients(gradient: GradientModel):
    """
    Reçoit les gradients d'un appareil Flutter.
    
    Les gradients sont des vecteurs mathématiques abstraits —
    ils ne contiennent AUCUNE donnée personnelle.
    
    Après réception :
    - Ajout au buffer
    - Si buffer >= min_clients → agrégation automatique FedAvg
    """
    try:
        # Appliquer la Differential Privacy avant stockage
        private_gradients = fed_service.apply_differential_privacy(
            gradient.gradients,
            epsilon=1.0  # Bon équilibre vie privée / précision
        )

        result = fed_service.receive_gradients(
            device_id=gradient.device_id,
            gradients=private_gradients,
            num_samples=gradient.num_samples,
            model_version=gradient.model_version,
        )
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_federated_status():
    """
    Retourne l'état actuel du Federated Learning.
    Utile pour le monitoring et le dashboard.
    """
    return fed_service.get_status()


@router.get("/model/latest")
async def get_latest_model():
    """
    Retourne les infos du modèle global actuel.
    L'app Flutter appelle cet endpoint au démarrage pour vérifier
    si une mise à jour du modèle est disponible.
    """
    return fed_service.get_latest_model_info()


@router.post("/aggregate/force")
async def force_aggregation():
    """
    Force une agrégation même si le buffer n'est pas plein.
    Utile pour les tests pendant le hackathon.
    ATTENTION : en production, cet endpoint doit être protégé
    par une authentification admin.
    """
    if not fed_service._gradient_buffer:
        raise HTTPException(
            status_code=400,
            detail="Buffer vide — aucun gradient à agréger"
        )

    result = fed_service._aggregate()
    return result


@router.delete("/buffer/clear")
async def clear_buffer():
    """
    Vide le buffer des gradients.
    Pour les tests uniquement.
    """
    count = len(fed_service._gradient_buffer)
    fed_service._gradient_buffer.clear()
    return {
        "status": "cleared",
        "gradients_removed": count
    }