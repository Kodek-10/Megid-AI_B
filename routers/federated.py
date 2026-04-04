
from fastapi import APIRouter
from models.gradient import GradientModel

router = APIRouter(prefix="/federated", tags=["Federated Learning"])

@router.post("/gradients")
async def receive_gradients(gradient: GradientModel):
    """Reçoit les gradients d'un appareil pour le Federated Learning."""
    print(f"[FL] Gradients reçus — device: {gradient.device_id[:8]}... samples: {gradient.num_samples}")
    return {"status": "received", "message": "Gradients intégrés. Merci pour votre contribution."}

@router.get("/model/latest")
async def get_latest_model():
    """Retourne la version du modèle global actuel."""
    return {"model_version": "1.0.0", "updated_at": "2026-03-01T00:00:00Z"}
