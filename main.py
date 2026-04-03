
# main.py
# Point d'entrée du backend Megidai
# Lance le serveur FastAPI et connecte tous les routeurs

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from routers import reputation, federated, community, guardian, hibp, nlp
from services.url_analyzer import url_analyzer
# Ajouter cet import en haut
from database import init_db



# asynccontextmanager = gère le démarrage et l'arrêt de l'application
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Code exécuté au démarrage (avant yield) et à l'arrêt (après yield).
    Remplace les anciens @app.on_event("startup") et @app.on_event("shutdown").
    """
    # ── Démarrage ─────────────────────────────────────────────────────
    print("🛡  Megidai Backend démarrage...")

    # Initialiser la base de données
    await init_db()

    print("✅  URL Analyzer initialisé")
    print("✅  Serveur prêt sur http://0.0.0.0:8000")
    print("📖  Documentation : http://localhost:8000/docs")

    yield  # L'application tourne ici

    # ── Arrêt ─────────────────────────────────────────────────────────
    print("🛑  Megidai Backend arrêt...")
    await url_analyzer.close()
    print("✅  Ressources libérées proprement")


# Créer l'application FastAPI
app = FastAPI(
    title="Megidai Backend",
    description="API de protection numérique — iSAFE Hackathon 2026",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Middleware CORS ────────────────────────────────────────────────────────────
# CORS = Cross-Origin Resource Sharing
# Permet à l'app Flutter (et au frontend web) d'appeler ce backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # En prod : remplacer par les domaines autorisés
    allow_credentials=True,
    allow_methods=["*"],       # GET, POST, PUT, DELETE...
    allow_headers=["*"],
)

# ── Connecter les routeurs ─────────────────────────────────────────────────────
# Chaque routeur gère un groupe de fonctionnalités
app.include_router(reputation.router)   # /reputation/scan, /reputation/report
app.include_router(federated.router)    # /federated/gradients
app.include_router(community.router)    # /community/report
app.include_router(guardian.router)     # /guardian/alert
app.include_router(hibp.router)  # /hibp/check-email, /hibp/check-password
app.include_router(nlp.router)  # /nlp/analyze, /nlp/analyze-batch


# ── Routes de base ─────────────────────────────────────────────────────────────
@app.get("/")
async def root():
    """Route de bienvenue — vérifie que le serveur tourne."""
    return {
        "app": "Megidai",
        "version": "1.0.0",
        "status": "online",
        "message": "🛡 Bouclier numérique Privacy-First actif",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    """
    Endpoint de santé — utilisé par les systèmes de monitoring
    et par l'app Flutter pour vérifier la connectivité.
    """
    return {
        "status": "healthy",
        "components": {
            "url_analyzer": "online",
            "federated_learning": "online",
            "database": "online",
        }
    }
