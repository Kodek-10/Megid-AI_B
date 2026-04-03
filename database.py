# database.py
# Configuration et initialisation de la base de données SQLite
# SQLAlchemy = bibliothèque Python pour interagir avec les bases de données
# sans écrire de SQL brut — on utilise des classes Python à la place

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text
from datetime import datetime

# ── Connexion à la base de données ───────────────────────────────────────────
# sqlite+aiosqlite = SQLite en mode asynchrone (compatible avec FastAPI async)
# ./megidai.db = fichier créé automatiquement dans le dossier courant
DATABASE_URL = "sqlite+aiosqlite:///./megidai.db"

# Le moteur = la connexion principale à la base de données
# echo=True = affiche les requêtes SQL dans le terminal (utile pour déboguer)
engine = create_async_engine(DATABASE_URL, echo=False)

# La session = une "conversation" avec la base de données
# Chaque requête HTTP aura sa propre session
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False  # Les objets restent utilisables après commit
)

# Base = classe parente de tous nos modèles de tables
class Base(DeclarativeBase):
    pass


# ── Définition des tables ─────────────────────────────────────────────────────

class URLReputationDB(Base):
    """
    Table de réputation des URLs.
    Stocke les signalements communautaires et les scores calculés.
    """
    __tablename__ = "url_reputation"

    # Clé primaire : identifiant unique auto-incrémenté
    id = Column(Integer, primary_key=True, autoincrement=True)

    # L'URL signalée (indexée pour des recherches rapides)
    url = Column(String(2048), nullable=False, index=True)

    # Le domaine extrait (pour regrouper les URLs du même site)
    domain = Column(String(255), nullable=False, index=True)

    # Compteurs de signalements
    malicious_reports = Column(Integer, default=0)  # Signalements "arnaque"
    safe_reports = Column(Integer, default=0)        # Signalements "faux positif"

    # Score de risque calculé (0-100)
    risk_score = Column(Integer, default=0)

    # Catégorie principale de l'arnaque
    category = Column(String(50), nullable=True)

    # Dans la liste blanche officielle Megidai ?
    is_whitelisted = Column(Boolean, default=False)

    # Dans la liste noire (bloqué automatiquement) ?
    is_blacklisted = Column(Boolean, default=False)

    # Horodatages
    first_reported = Column(DateTime, default=datetime.utcnow)
    last_reported = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScanLogDB(Base):
    """
    Table des analyses effectuées.
    Permet de suivre les statistiques et d'améliorer le modèle.
    Aucune donnée personnelle n'est stockée — uniquement les URLs et scores.
    """
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # URL analysée
    url = Column(String(2048), nullable=False)

    # Score attribué par Megidai
    risk_score = Column(Integer, nullable=False)

    # Niveau textuel (safe/suspect/danger)
    level = Column(String(20), nullable=False)

    # Source du lien (sms/whatsapp/facebook...)
    source = Column(String(50), nullable=True)

    # Temps d'analyse en millisecondes
    analysis_time_ms = Column(Integer, default=0)

    # Identifiant anonyme de l'appareil (pas d'info personnelle)
    device_id = Column(String(64), nullable=True)

    # Date et heure de l'analyse
    scanned_at = Column(DateTime, default=datetime.utcnow)


class CommunityReportDB(Base):
    """
    Table des signalements communautaires.
    Chaque signalement d'un utilisateur est enregistré ici.
    """
    __tablename__ = "community_reports"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # URL signalée
    url = Column(String(2048), nullable=False)

    # Type : 'malicious' ou 'safe'
    report_type = Column(String(20), nullable=False)

    # Catégorie d'arnaque
    category = Column(String(50), nullable=True)

    # Source du lien
    source = Column(String(50), nullable=True)

    # Identifiant anonyme du signaleur
    device_id = Column(String(64), nullable=False)

    # Date du signalement
    reported_at = Column(DateTime, default=datetime.utcnow)


class GuardianPairDB(Base):
    """
    Table des paires Protégé ↔ Ange Gardien.
    Stocke les relations familiales pour le Mode Ange Gardien.
    """
    __tablename__ = "guardian_pairs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Identifiant de la personne protégée
    protected_device_id = Column(String(64), nullable=False, index=True)

    # Identifiant de l'Ange Gardien
    guardian_device_id = Column(String(64), nullable=False, index=True)

    # Token Firebase de l'Ange Gardien (pour les notifications)
    guardian_fcm_token = Column(String(256), nullable=True)

    # Nom affiché de la personne protégée (choisi par l'Ange Gardien)
    protected_name = Column(String(100), nullable=True)

    # Mode de sensibilité imposé par l'Ange Gardien
    # 'prudent' = seuil 50, 'balanced' = seuil 65, 'expert' = seuil 80
    sensitivity_mode = Column(String(20), default="balanced")

    # La relation est-elle active ?
    is_active = Column(Boolean, default=True)

    # Dates
    created_at = Column(DateTime, default=datetime.utcnow)


class AlertLogDB(Base):
    """
    Table des alertes envoyées aux Anges Gardiens.
    Historique complet des notifications.
    """
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Qui a déclenché l'alerte
    protected_device_id = Column(String(64), nullable=False)

    # Qui a reçu l'alerte
    guardian_device_id = Column(String(64), nullable=False)

    # Type de menace détectée
    threat_type = Column(String(50), nullable=False)

    # Niveau de la menace
    threat_level = Column(String(20), nullable=False)

    # Score de risque
    risk_score = Column(Integer, nullable=False)

    # Notification envoyée avec succès ?
    notification_sent = Column(Boolean, default=False)

    # Date de l'alerte
    alerted_at = Column(DateTime, default=datetime.utcnow)


# ── Fonctions utilitaires ─────────────────────────────────────────────────────

async def init_db():
    """
    Crée toutes les tables dans la base de données.
    Appelé au démarrage du serveur dans main.py.
    """
    async with engine.begin() as conn:
        # create_all crée les tables si elles n'existent pas encore
        # Si elles existent déjà, rien ne se passe (pas d'erreur)
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Base de données initialisée")


async def get_db():
    """
    Générateur de session de base de données.
    Utilisé par FastAPI pour injecter une session dans chaque endpoint.
    
    'yield' = fournit la session, puis ferme automatiquement après la requête
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()  # Valider les changements
        except Exception:
            await session.rollback()  # Annuler en cas d'erreur
            raise
        finally:
            await session.close()  # Toujours fermer la session