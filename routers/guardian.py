
from fastapi import APIRouter
router = APIRouter(prefix="/guardian", tags=["Ange Gardien"])

@router.post("/alert")
async def send_alert(device_id: str, threat_level: str, threat_type: str):
    """Envoie une alerte à l'Ange Gardien d'un utilisateur."""
    print(f"[GUARDIAN] Alerte {threat_level} — device: {device_id[:8]}...")
    return {"status": "sent", "message": "Ange Gardien notifié"}
