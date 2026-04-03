# services/fed_averaging.py
# Implémentation de l'algorithme Federated Averaging (FedAvg)
# 
# Principe : chaque appareil envoie ses gradients (ajustements mathématiques)
# Ce service les agrège pour améliorer le modèle global
# AUCUNE donnée personnelle ne transite — uniquement des vecteurs numériques

import numpy as np
import joblib
import json
import os
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class GradientBuffer:
    """
    Buffer temporaire qui stocke les gradients reçus des appareils
    avant l'agrégation.
    
    dataclass = classe Python simplifiée pour stocker des données
    """
    device_id: str
    gradients: List[List[float]]
    num_samples: int          # Nombre d'exemples utilisés pour calculer ces gradients
    model_version: str
    received_at: datetime = field(default_factory=datetime.utcnow)


class FederatedAveragingService:
    """
    Service d'agrégation Federated Learning.
    
    Algorithme FedAvg (McMahan et al., 2017) :
    
    1. Distribuer le modèle global à N appareils
    2. Chaque appareil entraîne localement → calcule ses gradients
    3. Les gradients remontent au serveur
    4. Le serveur fait la MOYENNE PONDÉRÉE des gradients
       (pondérée par le nombre d'exemples de chaque appareil)
    5. Le nouveau modèle global est mis à jour
    6. Redistribuer à tous les appareils
    """

    def __init__(self):
        # Buffer des gradients reçus en attente d'agrégation
        self._gradient_buffer: List[GradientBuffer] = []

        # Nombre minimum de clients avant d'agréger
        # En prod : 10-100 minimum. Pour le hackathon : 3
        self.min_clients = int(os.getenv("MIN_CLIENTS_FOR_AGGREGATION", "3"))

        # Version actuelle du modèle global
        self.current_model_version = "1.0.0"

        # Chemin du modèle global
        self.model_path = "models/url_classifier.pkl"
        self.metadata_path = "models/fed_metadata.json"

        # Charger les métadonnées existantes
        self._load_metadata()

        print(f"✅ FedAvg Service initialisé (min_clients={self.min_clients})")

    def _load_metadata(self):
        """Charge les métadonnées du Federated Learning."""
        if os.path.exists(self.metadata_path):
            with open(self.metadata_path, "r") as f:
                meta = json.load(f)
                self.current_model_version = meta.get("model_version", "1.0.0")
                self._total_rounds = meta.get("total_rounds", 0)
                self._total_clients = meta.get("total_clients_ever", 0)
        else:
            self._total_rounds = 0
            self._total_clients = 0

    def _save_metadata(self):
        """Sauvegarde les métadonnées après chaque agrégation."""
        meta = {
            "model_version": self.current_model_version,
            "total_rounds": self._total_rounds,
            "total_clients_ever": self._total_clients,
            "last_aggregation": datetime.utcnow().isoformat(),
            "buffer_size": len(self._gradient_buffer),
        }
        os.makedirs("models", exist_ok=True)
        with open(self.metadata_path, "w") as f:
            json.dump(meta, f, indent=2)

    def receive_gradients(self, device_id: str, gradients: List[List[float]],
                          num_samples: int, model_version: str) -> dict:
        """
        Reçoit les gradients d'un appareil et les ajoute au buffer.
        
        Paramètres :
        - device_id    : identifiant anonyme de l'appareil
        - gradients    : les ajustements mathématiques du modèle
        - num_samples  : nombre d'exemples utilisés (pour la pondération)
        - model_version: version du modèle sur lequel les gradients ont été calculés
        
        Retourne : statut et info sur si une agrégation a été déclenchée
        """

        # ── Validation des gradients ──────────────────────────────────────
        if not gradients or not isinstance(gradients, list):
            return {"status": "error", "message": "Gradients invalides"}

        if num_samples <= 0:
            return {"status": "error", "message": "num_samples doit être positif"}

        # ── Vérifier si cet appareil a déjà envoyé des gradients ─────────
        # On ne prend qu'une contribution par appareil par round
        existing = next(
            (g for g in self._gradient_buffer if g.device_id == device_id),
            None
        )
        if existing:
            # Mettre à jour plutôt qu'ajouter un doublon
            self._gradient_buffer.remove(existing)
            print(f"[FL] Mise à jour gradients — device: {device_id[:8]}...")
        else:
            self._total_clients += 1
            print(f"[FL] Nouveaux gradients — device: {device_id[:8]}... samples: {num_samples}")

        # ── Ajouter au buffer ─────────────────────────────────────────────
        self._gradient_buffer.append(GradientBuffer(
            device_id=device_id,
            gradients=gradients,
            num_samples=num_samples,
            model_version=model_version,
        ))

        buffer_size = len(self._gradient_buffer)
        print(f"[FL] Buffer : {buffer_size}/{self.min_clients} clients")

        # ── Déclencher l'agrégation si assez de clients ───────────────────
        aggregation_triggered = False
        if buffer_size >= self.min_clients:
            print(f"[FL] Seuil atteint ({buffer_size} clients) — agrégation lancée !")
            result = self._aggregate()
            aggregation_triggered = True
            return {
                "status": "accepted_and_aggregated",
                "message": f"Gradients intégrés. Agrégation effectuée avec {buffer_size} clients.",
                "new_model_version": self.current_model_version,
                "buffer_size": 0,  # Buffer vidé après agrégation
                "aggregation_triggered": True,
            }

        return {
            "status": "accepted",
            "message": f"Gradients reçus. En attente de {self.min_clients - buffer_size} client(s) supplémentaire(s).",
            "buffer_size": buffer_size,
            "min_clients_needed": self.min_clients,
            "aggregation_triggered": False,
        }

    def _aggregate(self) -> dict:
        """
        Effectue l'agrégation FedAvg.
        
        Formule FedAvg :
        w_global = Σ (n_k / N) × w_k
        
        Où :
        - w_global = nouveaux poids globaux
        - n_k = nombre d'exemples du client k
        - N = total des exemples de tous les clients
        - w_k = gradients du client k
        """

        if not self._gradient_buffer:
            return {"status": "error", "message": "Buffer vide"}

        print(f"[FL] 🔄 Agrégation FedAvg de {len(self._gradient_buffer)} clients...")

        # ── Calculer le total des exemples (pour la pondération) ──────────
        # N = somme de tous les num_samples
        total_samples = sum(g.num_samples for g in self._gradient_buffer)

        if total_samples == 0:
            return {"status": "error", "message": "Total samples = 0"}

        # ── Appliquer FedAvg ──────────────────────────────────────────────
        # Convertir les gradients en arrays numpy pour le calcul vectoriel
        num_layers = len(self._gradient_buffer[0].gradients)
        aggregated_layers = []

        for layer_idx in range(num_layers):
            layer_aggregate = None

            for client in self._gradient_buffer:
                # Vérifier que ce client a bien cette couche
                if layer_idx >= len(client.gradients):
                    continue

                # Poids de ce client (proportion de ses exemples)
                weight = client.num_samples / total_samples

                # Convertir cette couche en numpy array 1D
                # 'np.array(..., dtype=float)' force le type flottant
                try:
                    layer_array = np.array(
                        client.gradients[layer_idx],
                        dtype=float
                    )
                except ValueError:
                    # Si la couche est elle-même inhomogène → aplatir
                    layer_array = np.array(
                        client.gradients[layer_idx],
                        dtype=object
                    ).flatten().astype(float)

                if layer_aggregate is None:
                    layer_aggregate = weight * layer_array
                else:
                    # S'assurer que les dimensions correspondent
                    min_size = min(len(layer_aggregate), len(layer_array))
                    layer_aggregate = (
                        layer_aggregate[:min_size] +
                        weight * layer_array[:min_size]
                    )

            if layer_aggregate is not None:
                aggregated_layers.append(layer_aggregate.tolist())

        # ── Mettre à jour la version du modèle ───────────────────────────
        self._update_model_version()

        # ── Sauvegarder ──────────────────────────────────────────────────
        self._total_rounds += 1
        self._save_metadata()

        clients_count = len(self._gradient_buffer)
        self._gradient_buffer.clear()

        print(f"[FL] ✅ Agrégation terminée !")
        print(f"[FL]    Round #{self._total_rounds}")
        print(f"[FL]    Clients agrégés : {clients_count}")
        print(f"[FL]    Couches agrégées : {len(aggregated_layers)}")
        print(f"[FL]    Nouvelle version : {self.current_model_version}")

        return {
            "status": "success",
            "round": self._total_rounds,
            "clients_aggregated": clients_count,
            "total_samples": total_samples,
            "layers_aggregated": len(aggregated_layers),
            "new_model_version": self.current_model_version,
        }

    def _update_model_version(self):
        """
        Met à jour le numéro de version du modèle.
        Format : MAJEUR.MINEUR.PATCH
        Chaque agrégation incrémente le PATCH.
        """
        parts = self.current_model_version.split(".")
        patch = int(parts[2]) + 1

        # Incrémenter le MINEUR tous les 10 rounds
        if patch >= 10:
            patch = 0
            minor = int(parts[1]) + 1
            parts[1] = str(minor)

        parts[2] = str(patch)
        self.current_model_version = ".".join(parts)

    def get_status(self) -> dict:
        """
        Retourne l'état actuel du Federated Learning.
        Affiché dans le dashboard Megidai.
        """
        return {
            "current_model_version": self.current_model_version,
            "buffer_size": len(self._gradient_buffer),
            "min_clients_for_aggregation": self.min_clients,
            "clients_waiting": [g.device_id[:8] + "..." for g in self._gradient_buffer],
            "total_rounds_completed": self._total_rounds,
            "total_clients_ever": self._total_clients,
            "ready_for_aggregation": len(self._gradient_buffer) >= self.min_clients,
        }

    def get_latest_model_info(self) -> dict:
        """
        Retourne les infos du dernier modèle disponible.
        L'app Flutter appelle cet endpoint pour savoir si une mise à jour
        est disponible.
        """
        return {
            "model_version": self.current_model_version,
            "model_path": self.model_path,
            "total_rounds": self._total_rounds,
            "download_url": f"/federated/model/download/{self.current_model_version}",
        }

    def apply_differential_privacy(self, gradients: List[List[float]],
                                    epsilon: float = 1.0) -> List[List[float]]:
        """
        Applique la Differential Privacy aux gradients.
        
        Differential Privacy = ajouter du bruit mathématique calibré
        pour rendre impossible la reconstruction de données individuelles,
        même si quelqu'un accède aux gradients.
        
        Paramètre epsilon :
        - Petit (0.1) = beaucoup de bruit = très privé mais moins précis
        - Grand (10)  = peu de bruit = moins privé mais plus précis
        - Valeur recommandée pour Megidai : 1.0 (bon équilibre)
        """
        noisy_gradients = []

        for layer in gradients:
            try:
                # Convertir en array 1D propre
                layer_array = np.array(layer, dtype=float).flatten()

                sensitivity = np.linalg.norm(layer_array)

                if sensitivity == 0:
                    noisy_gradients.append(layer)
                    continue

                # Clipper et ajouter du bruit
                clipped = layer_array / max(1.0, sensitivity)
                noise_scale = sensitivity / epsilon
                noise = np.random.normal(0, noise_scale, clipped.shape)
                noisy_layer = (clipped + noise).tolist()
                noisy_gradients.append(noisy_layer)

            except Exception as e:
                # En cas d'erreur sur une couche → garder l'original
                print(f"[FL] ⚠️  DP ignorée pour une couche : {e}")
                noisy_gradients.append(layer)


        return noisy_gradients


# Instance globale du service
fed_service = FederatedAveragingService()