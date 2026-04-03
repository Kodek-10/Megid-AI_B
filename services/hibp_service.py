# Service de vérification des fuites de données via HaveIBeenPwned
# Utilise le protocole k-Anonymity : l'email complet ne quitte JAMAIS l'appareil

import hashlib
import httpx
from typing import Optional

class HIBPService:
    """
    Vérifie si une adresse email a été compromise dans une fuite de données.
    
    Protocole k-Anonymity utilisé :
    1. On calcule le hash SHA-1 de l'email
    2. On envoie UNIQUEMENT les 5 premiers caractères au serveur HIBP
    3. HIBP retourne tous les hashes commençant par ces 5 caractères
    4. On compare localement — HIBP ne sait jamais quel email on cherche
    """

    BASE_URL = "https://api.pwnedpasswords.com"
    HIBP_API_URL = "https://haveibeenpwned.com/api/v3"

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=5.0,
            headers={
                # HIBP exige un User-Agent personnalisé
                "User-Agent": "Megidai-Privacy-Shield-v1.0",
                "hibp-api-key": ""  # Clé API optionnelle pour lever les limites
            }
        )

    async def check_email_breach(self, email: str) -> dict:
        """
        Vérifie si un email a été compromis dans une fuite de données.
        
        Paramètre : email (str) — l'adresse email à vérifier
        Retourne  : dict avec le nombre de fuites et les détails
        """

        # ── Étape 1 : Calculer le hash SHA-1 de l'email ──────────────────
        # SHA-1 = fonction de hachage qui transforme n'importe quel texte
        # en une chaîne hexadécimale de 40 caractères
        # Exemple : "test@gmail.com" → "6E0B4D3E9A1C2F5B8D7E4A1C2F5B8D7E4A1C2F5B"
        email_normalized = email.lower().strip()
        sha1_hash = hashlib.sha1(email_normalized.encode('utf-8')).hexdigest().upper()

        # ── Étape 2 : Extraire les 5 premiers caractères (le préfixe) ────
        # C'est TOUT ce qui sera envoyé au serveur HIBP
        prefix = sha1_hash[:5]      # Ex: "6E0B4"
        suffix = sha1_hash[5:]      # Le reste reste LOCAL — jamais envoyé

        # ── Étape 3 : Interroger HIBP avec seulement le préfixe ──────────
        try:
            response = await self.client.get(
                f"{self.BASE_URL}/range/{prefix}"
            )

            if response.status_code != 200:
                return self._build_error_result(email, "Service HIBP indisponible")

        except httpx.TimeoutException:
            return self._build_error_result(email, "Délai d'attente dépassé")
        except httpx.ConnectError:
            return self._build_error_result(email, "Impossible de joindre HIBP")

        # ── Étape 4 : Comparer localement ────────────────────────────────
        # HIBP retourne des lignes comme : "SUFFIXE:NOMBRE_FOIS_VU"
        # Exemple : "A1B2C3D4E5F6...:42" signifie compromis 42 fois
        breaches_found = 0
        response_text = response.text

        for line in response_text.splitlines():
            # Chaque ligne : "HASH_SUFFIX:COUNT"
            parts = line.split(":")
            if len(parts) != 2:
                continue

            returned_suffix = parts[0].upper()
            count = int(parts[1])

            # Si le suffixe correspond → email trouvé dans une fuite !
            if returned_suffix == suffix:
                breaches_found = count
                break

        # ── Étape 5 : Construire le résultat ─────────────────────────────
        if breaches_found > 0:
            return {
                "email": self._mask_email(email),  # Masquer l'email dans la réponse
                "compromised": True,
                "times_seen": breaches_found,
                "risk_level": self._calculate_risk_level(breaches_found),
                "recommendation": self._get_recommendation(breaches_found),
                "checked_via": "k-Anonymity (email complet jamais transmis)"
            }
        else:
            return {
                "email": self._mask_email(email),
                "compromised": False,
                "times_seen": 0,
                "risk_level": "safe",
                "recommendation": "Aucune fuite détectée. Continuez à utiliser des mots de passe uniques.",
                "checked_via": "k-Anonymity (email complet jamais transmis)"
            }

    async def check_password_breach(self, password: str) -> dict:
        """
        Vérifie si un mot de passe a été compromis.
        MÊME protocole k-Anonymity — le mot de passe ne quitte jamais l'appareil.
        """
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            response = await self.client.get(f"{self.BASE_URL}/range/{prefix}")
            if response.status_code != 200:
                return {"compromised": False, "error": "Service indisponible"}
        except Exception:
            return {"compromised": False, "error": "Connexion impossible"}

        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                count = int(parts[1])
                return {
                    "compromised": True,
                    "times_seen": count,
                    "recommendation": "Ce mot de passe est connu des hackers. Changez-le immédiatement."
                }

        return {
            "compromised": False,
            "times_seen": 0,
            "recommendation": "Mot de passe non trouvé dans les bases connues."
        }

    def _mask_email(self, email: str) -> str:
        """
        Masque partiellement l'email pour l'affichage.
        Exemple : "aminata@gmail.com" → "am****@gmail.com"
        """
        parts = email.split("@")
        if len(parts) != 2:
            return "****"
        username = parts[0]
        domain = parts[1]
        # Garder les 2 premiers caractères, masquer le reste
        masked = username[:2] + "*" * (len(username) - 2)
        return f"{masked}@{domain}"

    def _calculate_risk_level(self, times_seen: int) -> str:
        """Calcule le niveau de risque selon le nombre de fois vu."""
        if times_seen >= 100:
            return "critical"   # Extrêmement dangereux
        elif times_seen >= 10:
            return "high"       # Très dangereux
        elif times_seen >= 1:
            return "medium"     # Dangereux
        return "safe"

    def _get_recommendation(self, times_seen: int) -> str:
        """Retourne une recommandation adaptée au niveau de risque."""
        if times_seen >= 100:
            return f"CRITIQUE : Cet email a été trouvé {times_seen} fois. Changez immédiatement tous vos mots de passe associés et activez l'authentification à deux facteurs."
        elif times_seen >= 10:
            return f"URGENT : Cet email apparaît dans {times_seen} fuites. Changez vos mots de passe sur tous les sites importants."
        else:
            return f"ATTENTION : Cet email a été compromis {times_seen} fois. Vérifiez et changez vos mots de passe."

    def _build_error_result(self, email: str, error_msg: str) -> dict:
        """Retourne un résultat en cas d'erreur de connexion."""
        return {
            "email": self._mask_email(email),
            "compromised": False,
            "error": error_msg,
            "risk_level": "unknown",
            "recommendation": "Vérification impossible actuellement. Réessayez plus tard."
        }

    async def close(self):
        """Fermer le client HTTP proprement."""
        await self.client.aclose()


# Instance globale
hibp_service = HIBPService()