
# models/report.py
# Structures de données pour les signalements communautaires

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Literal, List
from datetime import datetime

class URLReport(BaseModel):
    """
    Signalement d'une URL malveillante ou sûre par un utilisateur.
    Alimente la base communautaire Megidai.
    """

    # L'URL signalée
    url: str = Field(..., description="URL signalée")

    # Type de signalement
    report_type: Literal["malicious", "safe"] = Field(
        ...,
        description="'malicious' = arnaque confirmée, 'safe' = faux positif"
    )

    # Catégorie d'arnaque (optionnel)
    category: Optional[Literal[
        "phishing",
        "fake_commerce",
        "romance_scam",
        "fake_support",
        "malware",
        "other"
    ]] = None

    # Identifiant anonyme du signaleur
    device_id: str = Field(..., min_length=32, max_length=64)

    # Contexte optionnel (depuis quel type de message le lien a été reçu)
    source: Optional[Literal["sms", "whatsapp", "facebook", "email", "other"]] = None

    timestamp: datetime = Field(default_factory=datetime.utcnow)


class URLReputation(BaseModel):
    """
    Réputation d'une URL dans la base communautaire.
    Retournée à l'app Flutter lors d'une vérification.
    """
    url: str
    risk_score: int = Field(..., ge=0, le=100)
    malicious_reports: int = Field(default=0)
    safe_reports: int = Field(default=0)
    last_reported: Optional[datetime] = None
    categories: List[str] = Field(default_factory=list)

    # Indique si l'URL est dans la liste blanche officielle Megidai
    is_whitelisted: bool = Field(default=False)


class ScanRequest(BaseModel):
    """
    Requête d'analyse d'une URL envoyée par l'app Flutter.
    """
    url: str = Field(..., description="URL à analyser")
    context: Optional[str] = Field(
        None,
        description="Texte autour du lien (SMS, message...) pour l'analyse contextuelle"
    )
    source: Optional[str] = Field(None, description="App source du lien")


class ScanResult(BaseModel):
    """
    Résultat complet d'une analyse d'URL.
    Retourné à l'app Flutter pour affichage du feu tricolore.
    """
    url: str
    risk_score: int = Field(..., ge=0, le=100)

    # Niveau textuel pour l'app Flutter
    level: Literal["safe", "suspect", "danger"]

    # Raisons détaillées de la décision
    reasons: List[dict] = Field(default_factory=list)

    # Infos sur le domaine
    domain_age_days: Optional[int] = None
    has_https: bool = True
    is_redirect: bool = False
    final_url: Optional[str] = None

    # Données communautaires
    community_reports: int = Field(default=0)
    is_whitelisted: bool = Field(default=False)

    analysis_time_ms: int = Field(default=0)
