
# models/gradient.py
# Ce fichier définit la structure des données reçues de l'app Flutter
# Pydantic valide automatiquement les données entrantes

from pydantic import BaseModel, Field
from typing import List
from datetime import datetime

class GradientModel(BaseModel):
    """
    Représente les gradients envoyés par un appareil Flutter
    lors du Federated Learning.
    Les gradients sont des ajustements mathématiques du modèle IA —
    ils ne contiennent AUCUNE donnée personnelle.
    """

    # Identifiant anonyme de l'appareil (généré localement, pas lié à l'identité)
    device_id: str = Field(..., min_length=32, max_length=64)

    # Version du modèle sur lequel les gradients ont été calculés
    model_version: str = Field(..., example="1.0.0")

    # Les gradients eux-mêmes : liste de listes de nombres flottants
    # Chaque sous-liste correspond aux poids d'une couche du modèle
    gradients: List[List[float]] = Field(..., description="Gradients du modèle local")

    # Nombre d'exemples utilisés pour calculer ces gradients
    # Permet de pondérer correctement lors de l'agrégation FedAvg
    num_samples: int = Field(..., gt=0, description="Nombre de SMS analysés localement")

    # Horodatage de la génération des gradients
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                "model_version": "1.0.0",
                "gradients": [[0.001, -0.002, 0.003]],
                "num_samples": 42,
            }
        }


class AggregatedModel(BaseModel):
    """
    Représente le modèle global après agrégation FedAvg.
    Renvoyé aux appareils lors de la mise à jour.
    """
    model_version: str
    weights: List[List[float]]
    num_clients_aggregated: int
    aggregated_at: datetime = Field(default_factory=datetime.utcnow)
