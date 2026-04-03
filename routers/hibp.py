# Endpoints de vérification des fuites de données

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from services.hibp_service import hibp_service

router = APIRouter(prefix="/hibp", tags=["Fuites de Données"])


class EmailCheckRequest(BaseModel):
    email: str


class PasswordCheckRequest(BaseModel):
    password: str


@router.post("/check-email")
async def check_email(request: EmailCheckRequest):
    """
    Vérifie si un email a été compromis dans une fuite de données.
    Utilise k-Anonymity — l'email complet ne quitte jamais le serveur.
    """
    if not request.email or "@" not in request.email:
        raise HTTPException(status_code=400, detail="Email invalide")

    result = await hibp_service.check_email_breach(request.email)
    return result


@router.post("/check-password")
async def check_password(request: PasswordCheckRequest):
    """
    Vérifie si un mot de passe a été compromis.
    Le mot de passe n'est JAMAIS transmis en clair — uniquement un hash partiel.
    """
    if not request.password or len(request.password) < 4:
        raise HTTPException(status_code=400, detail="Mot de passe trop court")

    result = await hibp_service.check_password_breach(request.password)
    return result