# Service d'analyse NLP pour détecter le phishing dans les SMS et messages
# Version MVP : approche hybride règles + patterns (sans MobileBERT pour l'instant)
# MobileBERT sera intégré en Phase 2 une fois les données d'entraînement prêtes

import re
from typing import List, Tuple


class NLPAnalyzer:
    """
    Analyseur de texte pour détecter les tentatives de phishing et d'arnaque.
    
    Approche MVP en deux couches :
    1. Règles linguistiques (patterns, mots-clés) — rapide et léger
    2. Score combiné avec pondération contextuelle
    
    MobileBERT (couche 3) sera ajouté en Phase 2.
    """

    def __init__(self):
        # ── Dictionnaires de patterns par catégorie ───────────────────────

        # Mots d'urgence — score +20 chacun
        self.urgency_patterns = [
            r'\b(urgent|urgente|urgently)\b',
            r'\b(immédiatement|immediately|now|maintenant)\b',
            r'\b(expire[rs]?|expiration|expiré)\b',
            r'\b(suspendu|suspended|bloqué|blocked)\b',
            r'\b(dernière chance|last chance|dernier délai)\b',
            r'\b(dans les \d+h|within \d+ hours?|sous \d+ heures?)\b',
            r'\b(aujourd.hui seulement|today only)\b',
        ]

        # Promesses de gain — score +25 chacun
        self.gain_patterns = [
            r'\b(gagné|won|winner|gagnant)\b',
            r'\b(félicitations|congratulations|congrats)\b',
            r'\b(prix|prize|récompense|reward)\b',
            r'\b(gratuit|free|offert|offer)\b',
            r'\b(\d+[\s]*(fcfa|cfa|xof|euro?s?|dollars?|usd))\b',
            r'\b(million|millier|thousand)\b',
            r'\b(cashback|remboursement|refund)\b',
        ]

        # Demandes d'informations sensibles — score +35 chacun
        self.sensitive_patterns = [
            r'\b(code\s*pin|pin\s*code|mot\s*de\s*passe|password)\b',
            r'\b(numéro\s*de\s*carte|card\s*number|cvv|cvc)\b',
            r'\b(identifiant|login|username|user\s*id)\b',
            r'\b(informations?\s*personnelles?|personal\s*info)\b',
            r'\b(confirme[rz]?\s*(votre|your|ton)|verify\s*your)\b',
            r'\b(compte\s*bancaire|bank\s*account|iban|rib)\b',
        ]

        # Usurpation d'identité institutionnelle — score +30 chacun
        self.impersonation_patterns = [
            r'\b(orange\s*money|orangemoney)\b',
            r'\b(moov\s*money|moovmoney)\b',
            r'\b(mtn\s*money)\b',
            r'\b(western\s*union|moneygram)\b',
            r'\b(service\s*client|customer\s*service|support\s*technique)\b',
            r'\b(votre\s*banque|your\s*bank|bnb|ecobank|coris)\b',
            r'\b(ministère|ministry|gouvernement|government)\b',
            r'\b(police|gendarmerie|interpol)\b',
        ]

        # Patterns de liens suspects dans le texte — score +15 chacun
        self.link_patterns = [
            r'https?://\S+',          # Tout lien dans le message
            r'bit\.ly/\S+',           # Raccourcisseurs
            r'tinyurl\.com/\S+',
            r'(?<!\w)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Adresse IP
        ]

        # Patterns positifs — réduisent le score
        self.safe_patterns = [
            r'\b(votre commande|your order|numéro de commande)\b',   # Commerce légitime
            r'\b(facture|invoice|reçu|receipt)\b',                    # Documents légitimes
            r'\b(rendez-vous|appointment|réservation|booking)\b',     # Rappels légitimes
            r'\b(livraison|delivery|expédition|shipping)\b',          # Livraisons
        ]

    def analyze_text(self, text: str) -> dict:
        """
        Analyse un texte (SMS, message) pour détecter le phishing.
        
        Paramètre : text (str) — le texte à analyser
        Retourne  : dict avec score, niveau, catégories détectées
        """
        if not text or len(text.strip()) < 3:
            return self._build_result(0, [], text)

        text_lower = text.lower()
        score = 0
        detected_categories = []
        reasons = []

        # ── Analyse des patterns d'urgence ───────────────────────────────
        urgency_hits = self._match_patterns(text_lower, self.urgency_patterns)
        if urgency_hits:
            points = min(20 * len(urgency_hits), 40)  # Max 40 points
            score += points
            detected_categories.append("urgence")
            reasons.append({
                "icon": "⚠️",
                "text": f"Langage d'urgence détecté : '{urgency_hits[0]}'",
                "points": points,
                "positive": False
            })

        # ── Analyse des promesses de gain ─────────────────────────────────
        gain_hits = self._match_patterns(text_lower, self.gain_patterns)
        if gain_hits:
            points = min(25 * len(gain_hits), 50)  # Max 50 points
            score += points
            detected_categories.append("gain_promis")
            reasons.append({
                "icon": "🚨",
                "text": f"Promesse de gain suspecte détectée : '{gain_hits[0]}'",
                "points": points,
                "positive": False
            })

        # ── Analyse des demandes d'informations sensibles ─────────────────
        sensitive_hits = self._match_patterns(text_lower, self.sensitive_patterns)
        if sensitive_hits:
            points = min(35 * len(sensitive_hits), 70)  # Max 70 points
            score += points
            detected_categories.append("info_sensible")
            reasons.append({
                "icon": "🚨",
                "text": f"Demande d'informations sensibles : '{sensitive_hits[0]}'",
                "points": points,
                "positive": False
            })

        # ── Analyse de l'usurpation d'identité ───────────────────────────
        impersonation_hits = self._match_patterns(text_lower, self.impersonation_patterns)
        if impersonation_hits:
            points = min(30 * len(impersonation_hits), 60)  # Max 60 points
            score += points
            detected_categories.append("usurpation_identite")
            reasons.append({
                "icon": "🚨",
                "text": f"Possible usurpation d'identité : '{impersonation_hits[0]}'",
                "points": points,
                "positive": False
            })

        # ── Analyse des liens dans le texte ──────────────────────────────
        link_hits = self._match_patterns(text_lower, self.link_patterns)
        if link_hits:
            score += 15
            detected_categories.append("lien_present")
            reasons.append({
                "icon": "⚠️",
                "text": "Lien détecté dans le message",
                "points": 15,
                "positive": False
            })

        # ── Patterns positifs (réduisent le score) ────────────────────────
        safe_hits = self._match_patterns(text_lower, self.safe_patterns)
        if safe_hits:
            reduction = min(15 * len(safe_hits), 30)
            score -= reduction
            reasons.append({
                "icon": "✅",
                "text": "Contenu cohérent avec un message commercial légitime",
                "points": -reduction,
                "positive": True
            })

        # ── Longueur du message ───────────────────────────────────────────
        # Les SMS d'arnaque sont souvent très courts ou anormalement longs
        word_count = len(text.split())
        if word_count < 5 and link_hits:
            score += 10  # SMS très court avec lien = suspect
        elif word_count > 200:
            score += 5   # Message anormalement long

        # ── Score final ───────────────────────────────────────────────────
        final_score = max(0, min(100, score))
        return self._build_result(final_score, reasons, text, detected_categories)

    def analyze_batch(self, messages: List[str]) -> List[dict]:
        """
        Analyse plusieurs messages en une seule fois.
        Utile pour le scan de la boîte SMS complète.
        """
        return [self.analyze_text(msg) for msg in messages]

    def _match_patterns(self, text: str, patterns: List[str]) -> List[str]:
        """
        Cherche tous les patterns dans le texte.
        Retourne la liste des correspondances trouvées.
        """
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            matches.extend(found)
        return matches

    def _build_result(self, score: int, reasons: list,
                      original_text: str, categories: list = []) -> dict:
        """Construit le dictionnaire de résultat."""

        if score <= 30:
            level = "safe"
        elif score <= 65:
            level = "suspect"
        else:
            level = "danger"

        return {
            "risk_score": score,
            "level": level,
            "categories": categories,
            "reasons": reasons,
            "text_length": len(original_text),
            "word_count": len(original_text.split()),
        }


# Instance globale
nlp_analyzer = NLPAnalyzer()