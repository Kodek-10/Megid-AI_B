# ai/train_url.py
# Entraînement du modèle Random Forest pour la détection d'URLs malveillantes
# Ce script est exécuté UNE SEULE FOIS pour créer le modèle
# Le modèle entraîné est sauvegardé et chargé par le backend

import numpy as np
import joblib
import re
import os
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ── Dataset d'entraînement ────────────────────────────────────────────────────
# Format : (url, label) — 0 = légitime, 1 = malveillant
# Ce dataset est manuel pour le MVP — en production on utilisera
# des datasets publics comme PhishTank ou OpenPhish

TRAINING_DATA = [

    # ── URLs légitimes (label = 0) ────────────────────────────────────
    ("https://www.orange.bf/mobile-money", 0),
    ("https://orange.com/fr/offres", 0),
    ("https://www.facebook.com/login", 0),
    ("https://google.com", 0),
    ("https://www.youtube.com/watch?v=abc123", 0),
    ("https://github.com/megidai/backend", 0),
    ("https://wikipedia.org/wiki/Cybersecurite", 0),
    ("https://moov.bf/services", 0),
    ("https://ecobank.com/bf/particuliers", 0),
    ("https://bnb.bf/credits", 0),
    ("https://www.amazon.fr/products", 0),
    ("https://docs.python.org/3/library", 0),
    ("https://stackoverflow.com/questions/12345", 0),
    ("https://linkedin.com/in/profil", 0),
    ("https://twitter.com/megidai_app", 0),
    ("https://paypal.com/fr/home", 0),
    ("https://microsoft.com/fr-fr/windows", 0),
    ("https://apple.com/iphone", 0),
    ("https://netflix.com/browse", 0),
    ("https://whatsapp.com/download", 0),
    ("https://instagram.com/explore", 0),
    ("https://gmail.com", 0),
    ("https://outlook.live.com/mail", 0),
    ("https://drive.google.com/drive/my-drive", 0),
    ("https://maps.google.com/maps", 0),

    # ── URLs malveillantes (label = 1) ────────────────────────────────
    # Imitation de marques
    ("http://orange-money-secure.com/login", 1),
    ("https://orangemoney-verify.net/account", 1),
    ("http://moov-money-alert.com/suspend", 1),
    ("https://facebook-security-alert.net/verify", 1),
    ("http://paypal-secure-login.com/signin", 1),
    ("https://apple-id-verify.com/update", 1),
    ("http://microsoft-support-alert.net/fix", 1),
    ("https://amazon-prize-winner.com/claim", 1),

    # Raccourcisseurs vers sites malveillants
    ("http://bit.ly/free-orange-money-2026", 1),
    ("https://tinyurl.com/gain-fcfa-gratuit", 1),
    ("http://t.co/arnaque-mobile-money", 1),

    # Adresses IP directes
    ("http://192.168.1.105/orange/login", 1),
    ("http://41.202.219.100/paypal/verify", 1),
    ("https://10.0.0.1/facebook/account", 1),

    # Homoglyphes et caractères trompeurs
    ("https://оrange.com/login", 1),       # 'о' cyrillique
    ("https://payраl.com/signin", 1),      # 'р' cyrillique
    ("https://fасebook.com/login", 1),     # 'а' cyrillique

    # Sous-domaines suspects
    ("https://orange.bf.verify.malicious.com/login", 1),
    ("http://secure.orange.bf.phishing.net/account", 1),
    ("https://facebook.com.login.verify.tk/signin", 1),

    # Mots-clés suspects dans l'URL
    ("https://verify-your-account-now.com/orange", 1),
    ("http://confirm-identity-urgent.net/moov", 1),
    ("https://suspended-account-alert.com/login", 1),
    ("http://free-prize-winner-2026.com/claim", 1),
    ("https://urgent-account-update.net/orange-bf", 1),

    # HTTP sans HTTPS
    ("http://orange-money-login.com/account", 1),
    ("http://moov-money-verify.net/pin", 1),
    ("http://bnb-bank-alert.com/suspended", 1),

    # Domaines à extensions suspectes
    ("https://orange-money.tk/login", 1),
    ("https://facebook-verify.ml/account", 1),
    ("https://paypal-secure.cf/signin", 1),
    ("https://orange.bf.money.gq/verify", 1),

    # Combinaisons multiples de signaux
    ("http://bit.ly/orange-prize-winner-fcfa", 1),
    ("http://192.168.0.1/orange-money/pin-code", 1),
    ("https://orange-money-suspended-urgent.com/verify-now", 1),
    ("http://facebook-security.tk/login-verify-account", 1),
]


# ── Extraction des features (caractéristiques) ────────────────────────────────

def extract_features(url: str) -> list:
    """
    Extrait 15 caractéristiques numériques d'une URL.
    Ces chiffres sont ce que le Random Forest analyse pour décider.
    
    Chaque feature = une question que le modèle se pose sur l'URL.
    """
    features = []

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        domain_clean = domain.replace("www.", "")
    except Exception:
        return [0] * 15  # Retourner des zéros si l'URL est invalide

    # Feature 1 : Longueur totale de l'URL
    # Les URLs malveillantes sont souvent très longues
    features.append(len(url))

    # Feature 2 : Longueur du domaine
    # Domaines légitimes sont généralement courts
    features.append(len(domain))

    # Feature 3 : Longueur du chemin (path)
    features.append(len(path))

    # Feature 4 : Utilise HTTPS ? (1 = oui, 0 = non)
    # HTTP sans S = pas de chiffrement = suspect
    features.append(1 if parsed.scheme == "https" else 0)

    # Feature 5 : Nombre de points dans le domaine
    # orange.bf.verify.malicious.com = 4 points = très suspect
    features.append(domain.count("."))

    # Feature 6 : Nombre de tirets dans le domaine
    # orange-money-secure-verify.com = beaucoup de tirets = suspect
    features.append(domain.count("-"))

    # Feature 7 : Nombre de chiffres dans le domaine
    # free-prize-2026-winner.com = chiffres dans domaine = suspect
    features.append(sum(c.isdigit() for c in domain))

    # Feature 8 : Contient une adresse IP ? (1 = oui, 0 = non)
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    features.append(1 if ip_pattern.search(domain) else 0)

    # Feature 9 : Utilise un raccourcisseur ? (1 = oui, 0 = non)
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "ow.ly", "rb.gy", "is.gd"}
    features.append(1 if domain_clean in shorteners else 0)

    # Feature 10 : Contient des mots-clés suspects ? (compte le nombre)
    suspicious_words = [
        "verify", "secure", "login", "update", "confirm", "account",
        "suspend", "alert", "urgent", "winner", "prize", "free",
        "vérif", "sécur", "connexion", "mise-à-jour", "gratuit"
    ]
    suspicious_count = sum(1 for w in suspicious_words if w in url.lower())
    features.append(suspicious_count)

    # Feature 11 : Imite une marque connue ? (1 = oui, 0 = non)
    brands = ["orange", "moov", "mtn", "paypal", "facebook", "apple",
              "microsoft", "amazon", "google", "bnb", "ecobank"]
    official_domains = {
        "orange.bf", "orange.com", "facebook.com", "google.com",
        "paypal.com", "microsoft.com", "apple.com", "amazon.fr",
        "moov.bf", "bnb.bf", "ecobank.com"
    }
    brand_in_url = any(b in domain for b in brands)
    is_official = domain_clean in official_domains
    features.append(1 if brand_in_url and not is_official else 0)

    # Feature 12 : Extension de domaine suspecte ? (1 = oui, 0 = non)
    # .tk, .ml, .cf, .gq sont souvent utilisés pour les arnaques (gratuits)
    suspicious_tlds = {".tk", ".ml", ".cf", ".gq", ".ga", ".xyz"}
    has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)
    features.append(1 if has_suspicious_tld else 0)

    # Feature 13 : Contient des caractères non-ASCII (homoglyphes) ?
    try:
        domain.encode('ascii')
        features.append(0)  # Que des caractères ASCII = pas d'homoglyphe
    except UnicodeEncodeError:
        features.append(1)  # Caractères non-ASCII = possible homoglyphe

    # Feature 14 : Nombre de sous-domaines
    # google.com = 0 sous-domaine
    # secure.orange.bf.verify.com = 3 sous-domaines = suspect
    parts = domain_clean.split(".")
    features.append(max(0, len(parts) - 2))

    # Feature 15 : Contient des paramètres de requête suspects ?
    query = parsed.query.lower()
    suspicious_params = ["redirect", "url=", "next=", "return=", "goto="]
    has_suspicious_params = any(p in query for p in suspicious_params)
    features.append(1 if has_suspicious_params else 0)

    return features


# ── Entraînement du modèle ────────────────────────────────────────────────────

def train_model():
    """
    Entraîne le Random Forest et sauvegarde le modèle.
    À exécuter une seule fois depuis le terminal.
    """
    print("🧠 Préparation des données d'entraînement...")

    # Séparer les URLs et les labels
    urls   = [item[0] for item in TRAINING_DATA]
    labels = [item[1] for item in TRAINING_DATA]

    # Extraire les features pour chaque URL
    X = np.array([extract_features(url) for url in urls])
    y = np.array(labels)

    print(f"✅ {len(urls)} URLs chargées")
    print(f"   └─ {sum(y == 0)} légitimes | {sum(y == 1)} malveillantes")
    print(f"   └─ {X.shape[1]} features extraites par URL")

    # ── Séparation train/test ──────────────────────────────────────────
    # 80% pour entraîner, 20% pour tester les performances
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,      # 20% pour le test
        random_state=42,    # Graine aléatoire fixe = résultats reproductibles
        stratify=y          # Garder les proportions légitimes/malveillantes
    )

    print(f"\n📊 Split train/test :")
    print(f"   └─ Entraînement : {len(X_train)} URLs")
    print(f"   └─ Test         : {len(X_test)} URLs")

    # ── Créer et entraîner le Random Forest ───────────────────────────
    print("\n🌲 Entraînement du Random Forest...")

    model = RandomForestClassifier(
        n_estimators=100,    # 100 arbres de décision
        max_depth=10,        # Profondeur max de chaque arbre
        min_samples_split=2, # Minimum d'exemples pour diviser un noeud
        random_state=42,     # Reproductibilité
        n_jobs=-1,           # Utiliser tous les coeurs CPU disponibles
        class_weight="balanced"  # Compenser si dataset déséquilibré
    )

    model.fit(X_train, y_train)
    print("✅ Modèle entraîné !")

    # ── Évaluation des performances ───────────────────────────────────
    print("\n📈 Évaluation sur les données de test :")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"   └─ Précision globale : {accuracy * 100:.1f}%")
    print("\n" + classification_report(
        y_test, y_pred,
        target_names=["Légitime", "Malveillant"]
    ))

    # ── Importance des features ───────────────────────────────────────
    feature_names = [
        "longueur_url", "longueur_domaine", "longueur_path",
        "https", "nb_points", "nb_tirets", "nb_chiffres",
        "adresse_ip", "raccourcisseur", "mots_suspects",
        "imitation_marque", "tld_suspect", "homoglyphes",
        "nb_sous_domaines", "params_suspects"
    ]

    print("\n🔍 Importance des features (top 5) :")
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    for i in range(min(5, len(feature_names))):
        idx = indices[i]
        print(f"   {i+1}. {feature_names[idx]:<25} {importances[idx]:.3f}")

    # ── Sauvegarder le modèle ─────────────────────────────────────────
    os.makedirs("models", exist_ok=True)
    model_path = "models/url_classifier.pkl"
    joblib.dump(model, model_path)
    print(f"\n💾 Modèle sauvegardé : {model_path}")

    # Sauvegarder aussi les noms des features pour référence
    import json
    metadata = {
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "n_estimators": 100,
        "accuracy": float(accuracy),
        "training_samples": len(X_train),
    }
    with open("models/url_classifier_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print("✅ Métadonnées sauvegardées : models/url_classifier_metadata.json")
    print("\n🎉 Entraînement terminé ! Le modèle est prêt.")
    return model


# Point d'entrée
if __name__ == "__main__":
    train_model()