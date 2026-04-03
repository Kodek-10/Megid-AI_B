# services/notification.py
# Service d'envoi de notifications push via Firebase Cloud Messaging (FCM)
# Utilisé exclusivement pour le Mode Ange Gardien
#
# GARANTIE DE CONFIDENTIALITÉ :
# Les notifications ne contiennent JAMAIS le contenu des messages
# de la personne protégée — uniquement le TYPE de menace détectée

import httpx
import os
import json
from datetime import datetime
from typing import Optional


class NotificationService:
    """
    Service d'envoi de notifications push Firebase.
    
    Firebase Cloud Messaging (FCM) = service Google qui permet
    d'envoyer des notifications sur les téléphones Android et iOS
    même quand l'application est fermée.
    
    Flux :
    1. Menace critique détectée sur le téléphone de Marcel (protégé)
    2. L'app Flutter de Marcel envoie une alerte au backend
    3. Le backend trouve le token FCM de Kader (Ange Gardien)
    4. Le backend envoie une notification à Kader via Firebase
    5. Kader reçoit la notification sur son téléphone
    """

    # URL de l'API FCM v1 de Firebase
    FCM_URL = "https://fcm.googleapis.com/fcm/send"

    def __init__(self):
        self.server_key = os.getenv("FIREBASE_SERVER_KEY", "")
        self.is_configured = bool(self.server_key)

        if self.is_configured:
            print("✅ Firebase FCM configuré")
        else:
            print("⚠️  Firebase FCM non configuré — mode simulation activé")

        # Client HTTP pour les appels Firebase
        self.client = httpx.AsyncClient(timeout=10.0)

    async def send_guardian_alert(
        self,
        guardian_fcm_token: str,
        protected_name: str,
        threat_type: str,
        threat_level: str,
        risk_score: int,
        threat_description: str = "",
    ) -> dict:
        """
        Envoie une alerte à un Ange Gardien.
        
        Paramètres :
        - guardian_fcm_token : token Firebase du téléphone de l'Ange Gardien
        - protected_name     : nom de la personne protégée ("Marcel")
        - threat_type        : type de menace ("phishing", "malicious_url"...)
        - threat_level       : niveau ("suspect" ou "danger")
        - risk_score         : score 0-100
        - threat_description : description courte de la menace
        
        Note : AUCUN contenu personnel de Marcel n'est inclus
        """

        # ── Construire le titre et le corps de la notification ────────────
        emoji = "🔴" if threat_level == "danger" else "🟠"

        title = f"{emoji} Alerte Megidai — {protected_name}"

        if threat_type == "phishing_sms":
            body = f"{protected_name} a reçu un SMS de phishing (score : {risk_score}/100). Contactez-le/la rapidement."
        elif threat_type == "malicious_url":
            body = f"{protected_name} a cliqué sur un lien dangereux (score : {risk_score}/100). Vérifiez qu'il/elle va bien."
        elif threat_type == "data_breach":
            body = f"Les données de {protected_name} ont été trouvées dans une fuite. Action requise."
        else:
            body = f"Une menace {threat_level} a été détectée sur l'appareil de {protected_name} (score : {risk_score}/100)."

        # ── Mode simulation (sans Firebase configuré) ─────────────────────
        if not self.is_configured or guardian_fcm_token.startswith("TEST_"):
            print(f"\n[FCM SIMULATION] ──────────────────────────────")
            print(f"  Destinataire : {guardian_fcm_token[:20]}...")
            print(f"  Titre        : {title}")
            print(f"  Corps        : {body}")
            print(f"  Données      : type={threat_type}, level={threat_level}, score={risk_score}")
            print(f"────────────────────────────────────────────────\n")

            return {
                "status": "simulated",
                "message": "Notification simulée (Firebase non configuré)",
                "notification": {"title": title, "body": body},
                "sent_at": datetime.utcnow().isoformat(),
            }

        # ── Envoi réel via Firebase ───────────────────────────────────────
        payload = {
            # "to" = token FCM du téléphone destinataire
            "to": guardian_fcm_token,

            # "notification" = ce qui s'affiche dans la barre de notifications
            "notification": {
                "title": title,
                "body": body,
                "sound": "default",   # Son de notification par défaut
                "badge": 1,           # Badge rouge sur l'icône de l'app
            },

            # "data" = données supplémentaires reçues par l'app Flutter
            # Permet à l'app de traiter l'alerte en arrière-plan
            # IMPORTANT : pas de données personnelles ici
            "data": {
                "type": "guardian_alert",
                "threat_type": threat_type,
                "threat_level": threat_level,
                "risk_score": str(risk_score),
                "protected_name": protected_name,
                "timestamp": datetime.utcnow().isoformat(),
                # PAS de contenu des messages, PAS de données personnelles
            },

            # Priorité haute = notification immédiate même en mode silencieux
            "priority": "high",

            # Notification persistante (ne disparaît pas automatiquement)
            "android": {
                "priority": "high",
                "notification": {
                    "channel_id": "megidai_guardian_alerts",
                    "notification_priority": "PRIORITY_MAX",
                }
            },
        }

        try:
            response = await self.client.post(
                self.FCM_URL,
                headers={
                    "Authorization": f"key={self.server_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )

            response_data = response.json()

            if response.status_code == 200 and response_data.get("success") == 1:
                print(f"[FCM] ✅ Notification envoyée à {guardian_fcm_token[:20]}...")
                return {
                    "status": "sent",
                    "firebase_response": response_data,
                    "sent_at": datetime.utcnow().isoformat(),
                }
            else:
                print(f"[FCM] ❌ Erreur Firebase : {response_data}")
                return {
                    "status": "failed",
                    "error": response_data,
                    "sent_at": datetime.utcnow().isoformat(),
                }

        except httpx.TimeoutException:
            return {"status": "timeout", "error": "Firebase ne répond pas"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def send_weekly_report(
        self,
        guardian_fcm_token: str,
        protected_name: str,
        threats_blocked: int,
        resilience_score: int,
    ) -> dict:
        """
        Envoie le rapport hebdomadaire à l'Ange Gardien.
        Envoyé automatiquement chaque dimanche.
        """
        if threats_blocked == 0:
            title = f"✅ Rapport Megidai — {protected_name}"
            body = f"Bonne nouvelle ! Aucune menace cette semaine pour {protected_name}. Score de résilience : {resilience_score}/100."
        else:
            title = f"🛡 Rapport Megidai — {protected_name}"
            body = f"{threats_blocked} menace(s) bloquée(s) cette semaine pour {protected_name}. Score : {resilience_score}/100."

        if not self.is_configured:
            print(f"\n[FCM RAPPORT HEBDO] {title}")
            print(f"  {body}\n")
            return {"status": "simulated", "title": title, "body": body}

        payload = {
            "to": guardian_fcm_token,
            "notification": {
                "title": title,
                "body": body,
                "sound": "default",
            },
            "data": {
                "type": "weekly_report",
                "protected_name": protected_name,
                "threats_blocked": str(threats_blocked),
                "resilience_score": str(resilience_score),
            },
        }

        try:
            response = await self.client.post(
                self.FCM_URL,
                headers={
                    "Authorization": f"key={self.server_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            return {"status": "sent", "response": response.json()}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    async def register_device(self, device_id: str, fcm_token: str) -> dict:
        """
        Enregistre ou met à jour le token FCM d'un appareil.
        Le token FCM change parfois (mise à jour de l'app, réinstallation).
        """
        print(f"[FCM] Enregistrement device {device_id[:8]}... token: {fcm_token[:20]}...")
        return {
            "status": "registered",
            "device_id": device_id,
            "token_preview": fcm_token[:20] + "...",
        }

    async def close(self):
        """Fermer le client HTTP."""
        await self.client.aclose()


# Instance globale
notification_service = NotificationService()