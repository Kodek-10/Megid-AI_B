
# services/url_analyzer.py
# Service d'analyse d'URLs — implémente le score multi-critères Megidai
# Combine analyse syntaxique + liste blanche + réputation communautaire

import re
import socket
import hashlib
import time
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Optional, Tuple, List
import httpx

# ── Constantes ────────────────────────────────────────────────────────────────

# Raccourcisseurs de liens connus
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "short.link",
    "cutt.ly", "rb.gy", "is.gd", "buff.ly", "goo.gl"
}

# Marques officielles vérifiées et leurs domaines légitimes
VERIFIED_BRANDS = {
    "orange":     ["orange.bf", "orange.com", "orangemoney.com"],
    "moov":       ["moov.bf", "moovmoneybf.com"],
    "mtn":        ["mtn.com", "mtn.bf"],
    "bnb":        ["bnb.bf"],
    "ecobank":    ["ecobank.com"],
    "facebook":   ["facebook.com", "fb.com", "messenger.com"],
    "google":     ["google.com", "gmail.com", "youtube.com"],
    "whatsapp":   ["whatsapp.com", "whatsapp.net"],
}

# Domaines dans la liste blanche globale Megidai
GLOBAL_WHITELIST = {
    "orange.bf", "orange.com", "orangemoney.com",
    "moov.bf", "moovmoneybf.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "google.com", "youtube.com", "gmail.com",
    "wikipedia.org", "github.com",
    "bnb.bf", "ecobank.com",
}

# Mots-clés suspects dans les URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "winner", "prize", "congratulations", "free", "click", "urgent",
    "suspended", "limited", "expire", "validate", "signin",
    # Mots en français souvent utilisés dans les arnaques
    "gagner", "gratuit", "urgent", "compte", "suspendre",
    "verification", "confirmer", "cliquez",
]

# Mots associés aux marques ciblées par les arnaqueurs
BRAND_IMPERSONATION_KEYWORDS = [
    "orange", "moov", "mtn", "paypal", "amazon", "apple",
    "microsoft", "facebook", "whatsapp", "bnb", "ecobank",
]


class URLAnalyzer:
    """
    Service principal d'analyse d'URLs pour Megidai.
    Implémente le score multi-critères avec points positifs et négatifs.
    """

    def __init__(self):
        # Client HTTP asynchrone pour résoudre les raccourcisseurs
        self.http_client = httpx.AsyncClient(
            timeout=2.0,          # Max 2 secondes pour la résolution
            follow_redirects=True,
            max_redirects=5,
        )

    async def analyze(self, url: str, context: str = "") -> dict:
        """
        Analyse complète d'une URL.
        Retourne un dictionnaire avec score, niveau, raisons.
        """
        start_time = time.time()
        score = 0
        reasons = []

        # ── Étape 1 : Nettoyage et parsing de l'URL ──────────────────────
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Supprimer le 'www.' pour simplifier les comparaisons
            domain_clean = domain.replace("www.", "")
        except Exception:
            return self._build_result(url, 85, [], 0)

        final_url = url
        is_redirect = False

        # ── Étape 2 : Liste blanche — priorité absolue ────────────────────
        # Si le domaine est dans la liste blanche, score très bas garanti
        if domain_clean in GLOBAL_WHITELIST:
            reasons.append({
                "icon": "✅",
                "text": "Domaine dans la liste de confiance officielle Megidai",
                "points": -80,
                "positive": True
            })
            score -= 80

        # ── Étape 3 : Résolution des raccourcisseurs ──────────────────────
        if domain_clean in URL_SHORTENERS:
            reasons.append({
                "icon": "⚠️",
                "text": f"Raccourcisseur de lien détecté ({domain_clean})",
                "points": +15,
                "positive": False
            })
            score += 15

            # Résoudre pour trouver la vraie URL
            resolved = await self._resolve_redirect(url)
            if resolved and resolved != url:
                final_url = resolved
                is_redirect = True
                parsed = urlparse(final_url)
                domain = parsed.netloc.lower()
                domain_clean = domain.replace("www.", "")

                # Revérifier la liste blanche avec la vraie URL
                if domain_clean in GLOBAL_WHITELIST:
                    reasons.append({
                        "icon": "✅",
                        "text": f"Destination finale ({domain_clean}) est un domaine de confiance",
                        "points": -50,
                        "positive": True
                    })
                    score -= 50

        # ── Étape 4 : Analyse HTTPS ───────────────────────────────────────
        has_https = parsed.scheme == "https"
        if not has_https:
            reasons.append({
                "icon": "⚠️",
                "text": "Connexion non sécurisée (HTTP sans chiffrement)",
                "points": +25,
                "positive": False
            })
            score += 25
        else:
            reasons.append({
                "icon": "✅",
                "text": "Connexion sécurisée HTTPS",
                "points": -10,
                "positive": True
            })
            score -= 10

        # ── Étape 5 : Détection des homoglyphes ──────────────────────────
        # Caractères visuellement similaires mais techniquement différents
        if self._has_homoglyphs(domain):
            reasons.append({
                "icon": "🚨",
                "text": "Caractères trompeurs détectés dans le domaine (homoglyphes)",
                "points": +40,
                "positive": False
            })
            score += 40

        # ── Étape 6 : Détection d'imitation de marque ────────────────────
        impersonated = self._detect_brand_impersonation(domain_clean)
        if impersonated:
            reasons.append({
                "icon": "🚨",
                "text": f"Le domaine imite la marque '{impersonated}' sans être son site officiel",
                "points": +45,
                "positive": False
            })
            score += 45

        # ── Étape 7 : Analyse des mots-clés suspects dans l'URL ──────────
        suspicious_found = self._find_suspicious_keywords(url.lower())
        if suspicious_found:
            reasons.append({
                "icon": "⚠️",
                "text": f"Mots-clés suspects dans l'URL : {', '.join(suspicious_found[:3])}",
                "points": +20,
                "positive": False
            })
            score += 20

        # ── Étape 8 : IP directe dans l'URL ──────────────────────────────
        if self._has_ip_in_url(domain):
            reasons.append({
                "icon": "🚨",
                "text": "URL utilise une adresse IP directe (pas un nom de domaine)",
                "points": +35,
                "positive": False
            })
            score += 35

        # ── Étape 9 : Trop de sous-domaines ──────────────────────────────
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            reasons.append({
                "icon": "⚠️",
                "text": f"Structure de domaine suspecte ({subdomain_count} niveaux)",
                "points": +20,
                "positive": False
            })
            score += 20

        # ── Étape 10 : Analyse du contexte (texte du message) ────────────
        if context:
            context_score = self._analyze_context(context)
            if context_score > 0:
                reasons.append({
                    "icon": "⚠️",
                    "text": "Le message contient des formulations d'urgence ou de gain",
                    "points": context_score,
                    "positive": False
                })
                score += context_score

        # ── Calcul final ──────────────────────────────────────────────────
        # S'assurer que le score reste entre 0 et 100
        final_score = max(0, min(100, score))
        elapsed_ms = int((time.time() - start_time) * 1000)

        return self._build_result(
            url=url,
            score=final_score,
            reasons=reasons,
            elapsed_ms=elapsed_ms,
            final_url=final_url if is_redirect else None,
            is_redirect=is_redirect,
            has_https=has_https,
        )

    def _build_result(self, url, score, reasons, elapsed_ms,
                      final_url=None, is_redirect=False, has_https=True) -> dict:
        """Construit le dictionnaire de résultat final."""

        # Déterminer le niveau textuel
        if score <= 40:
            level = "safe"
        elif score <= 70:
            level = "suspect"
        else:
            level = "danger"

        return {
            "url": url,
            "risk_score": score,
            "level": level,
            "reasons": reasons,
            "has_https": has_https,
            "is_redirect": is_redirect,
            "final_url": final_url,
            "analysis_time_ms": elapsed_ms,
        }

    async def _resolve_redirect(self, url: str) -> Optional[str]:
        """
        Résout les raccourcisseurs de liens pour trouver la vraie URL.
        Utilise uniquement une requête HEAD (pas de téléchargement de page).
        """
        try:
            response = await self.http_client.head(url)
            return str(response.url)
        except Exception:
            return None

    def _has_homoglyphs(self, domain: str) -> bool:
        """
        Détecte les caractères Unicode trompeurs dans un domaine.
        Exemple : 'pаypal.com' avec 'а' cyrillique au lieu de 'a' latin.
        """
        # Vérifier si le domaine contient des caractères non-ASCII
        try:
            domain.encode('ascii')
            return False  # Que des caractères ASCII : pas d'homoglyphe
        except UnicodeEncodeError:
            return True   # Caractères non-ASCII détectés

    def _detect_brand_impersonation(self, domain: str) -> Optional[str]:
        """
        Détecte si un domaine imite une marque connue sans être son domaine officiel.
        Exemple : 'orange-money-secure.com' imite Orange sans être orange.bf
        """
        for brand, official_domains in VERIFIED_BRANDS.items():
            # Le domaine contient le nom de la marque...
            if brand in domain:
                # ...mais n'est pas dans les domaines officiels
                if domain not in official_domains and \
                   not any(domain == d for d in official_domains):
                    return brand
        return None

    def _find_suspicious_keywords(self, url: str) -> List[str]:
        """Trouve les mots-clés suspects dans une URL."""
        found = []
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url:
                found.append(keyword)
        return found

    def _has_ip_in_url(self, domain: str) -> bool:
        """Vérifie si le domaine est une adresse IP directe."""
        # Pattern pour les adresses IPv4 : 4 groupes de chiffres séparés par des points
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        return bool(ip_pattern.match(domain))

    def _analyze_context(self, context: str) -> int:
        """
        Analyse le texte autour du lien pour détecter des patterns d'arnaque.
        Retourne un score de risque contextuel (0-30).
        """
        context_lower = context.lower()
        score = 0

        # Mots d'urgence
        urgency_words = ["urgent", "immédiatement", "24h", "expire", "suspendu",
                         "bloqué", "maintenant", "today", "immediately"]
        if any(w in context_lower for w in urgency_words):
            score += 15

        # Promesses de gain
        gain_words = ["gagné", "winner", "prize", "gratuit", "free",
                      "félicitations", "congratulations", "million", "cadeau"]
        if any(w in context_lower for w in gain_words):
            score += 20

        # Demandes d'informations sensibles
        sensitive_words = ["mot de passe", "password", "code pin", "cvv",
                           "carte bancaire", "bank card", "credentials"]
        if any(w in context_lower for w in sensitive_words):
            score += 25

        return min(score, 30)  # Max 30 points de contexte

    async def close(self):
        """Fermer le client HTTP proprement."""
        await self.http_client.aclose()


# Instance globale du service (créée une fois, réutilisée partout)
url_analyzer = URLAnalyzer()
