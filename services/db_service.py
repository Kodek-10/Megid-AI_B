# services/db_service.py
# Service d'accès à la base de données
# Toutes les opérations CRUD (Create, Read, Update, Delete) sont ici

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func
from datetime import datetime
from urllib.parse import urlparse
from database import (
    URLReputationDB, ScanLogDB, CommunityReportDB,
    GuardianPairDB, AlertLogDB
)


class DBService:
    """
    Service centralisé pour toutes les opérations de base de données.
    Chaque méthode reçoit une session en paramètre.
    """

    # ── Réputation des URLs ───────────────────────────────────────────────────

    async def get_url_reputation(self, db: AsyncSession, url: str) -> dict | None:
        """
        Récupère la réputation d'une URL depuis la base de données.
        Retourne None si l'URL n'a jamais été signalée.
        """
        # select() = équivalent de SELECT en SQL
        # where() = équivalent de WHERE en SQL
        result = await db.execute(
            select(URLReputationDB).where(URLReputationDB.url == url)
        )
        record = result.scalar_one_or_none()

        if record is None:
            return None

        return {
            "url": record.url,
            "risk_score": record.risk_score,
            "malicious_reports": record.malicious_reports,
            "safe_reports": record.safe_reports,
            "is_whitelisted": record.is_whitelisted,
            "is_blacklisted": record.is_blacklisted,
            "category": record.category,
            "last_reported": record.last_reported,
        }

    async def get_domain_reputation(self, db: AsyncSession, domain: str) -> dict | None:
        """
        Récupère la réputation d'un domaine entier.
        Utile quand l'URL exacte n'est pas connue mais le domaine l'est.
        """
        result = await db.execute(
            select(URLReputationDB)
            .where(URLReputationDB.domain == domain)
            .order_by(URLReputationDB.malicious_reports.desc())
            .limit(1)
        )
        record = result.scalar_one_or_none()

        if record is None:
            return None

        return {
            "domain": record.domain,
            "risk_score": record.risk_score,
            "malicious_reports": record.malicious_reports,
            "is_blacklisted": record.is_blacklisted,
        }

    async def save_report(self, db: AsyncSession, url: str,
                          report_type: str, category: str = None,
                          device_id: str = None, source: str = None):
        """
        Enregistre un signalement communautaire et met à jour la réputation.
        
        report_type : 'malicious' ou 'safe'
        """
        # Extraire le domaine de l'URL
        try:
            domain = urlparse(url).netloc.lower().replace("www.", "")
        except Exception:
            domain = ""

        # ── Enregistrer le signalement brut ──────────────────────────────
        report = CommunityReportDB(
            url=url,
            report_type=report_type,
            category=category,
            source=source,
            device_id=device_id or "anonymous",
            reported_at=datetime.utcnow()
        )
        db.add(report)

        # ── Mettre à jour ou créer la réputation ──────────────────────────
        result = await db.execute(
            select(URLReputationDB).where(URLReputationDB.url == url)
        )
        reputation = result.scalar_one_or_none()

        if reputation is None:
            # Première fois que cette URL est signalée : créer l'entrée
            reputation = URLReputationDB(
                url=url,
                domain=domain,
                malicious_reports=1 if report_type == "malicious" else 0,
                safe_reports=1 if report_type == "safe" else 0,
                category=category,
                risk_score=80 if report_type == "malicious" else 10,
            )
            db.add(reputation)

        else:
            # Mettre à jour les compteurs
            if report_type == "malicious":
                reputation.malicious_reports += 1
            else:
                reputation.safe_reports += 1

            # Recalculer le score basé sur les signalements
            total = reputation.malicious_reports + reputation.safe_reports
            if total > 0:
                malicious_ratio = reputation.malicious_reports / total
                reputation.risk_score = int(malicious_ratio * 100)

            # Auto-blacklist si trop de signalements malveillants
            if reputation.malicious_reports >= 5:
                reputation.is_blacklisted = True
                print(f"🚨 Auto-blacklist : {domain} ({reputation.malicious_reports} signalements)")

            # Auto-whitelist si beaucoup de signalements sûrs
            if reputation.safe_reports >= 10 and reputation.malicious_reports == 0:
                reputation.is_whitelisted = True

            reputation.last_reported = datetime.utcnow()

        await db.flush()  # Écrire en base sans encore committer
        return {"status": "saved", "url": url, "type": report_type}

    # ── Logs des analyses ─────────────────────────────────────────────────────

    async def log_scan(self, db: AsyncSession, url: str, risk_score: int,
                       level: str, source: str = None,
                       device_id: str = None, analysis_time_ms: int = 0):
        """
        Enregistre une analyse dans les logs.
        Permet de suivre les statistiques globales.
        """
        log = ScanLogDB(
            url=url,
            risk_score=risk_score,
            level=level,
            source=source,
            device_id=device_id,
            analysis_time_ms=analysis_time_ms,
            scanned_at=datetime.utcnow()
        )
        db.add(log)
        await db.flush()

    async def get_stats(self, db: AsyncSession) -> dict:
        """
        Retourne les statistiques globales de la plateforme.
        Affiché sur le tableau de bord Megidai.
        """
        # Compter le total des analyses
        total_scans = await db.scalar(select(func.count(ScanLogDB.id)))

        # Compter les menaces bloquées (niveau danger)
        threats_blocked = await db.scalar(
            select(func.count(ScanLogDB.id))
            .where(ScanLogDB.level == "danger")
        )

        # Compter les signalements
        total_reports = await db.scalar(
            select(func.count(CommunityReportDB.id))
        )

        # URLs dans la liste noire
        blacklisted = await db.scalar(
            select(func.count(URLReputationDB.id))
            .where(URLReputationDB.is_blacklisted == True)
        )

        return {
            "total_scans": total_scans or 0,
            "threats_blocked": threats_blocked or 0,
            "total_community_reports": total_reports or 0,
            "blacklisted_urls": blacklisted or 0,
        }

    # ── Mode Ange Gardien ─────────────────────────────────────────────────────

    async def create_guardian_pair(self, db: AsyncSession,
                                   protected_device_id: str,
                                   guardian_device_id: str,
                                   guardian_fcm_token: str = None,
                                   protected_name: str = None) -> dict:
        """
        Crée une relation Protégé ↔ Ange Gardien.
        """
        # Vérifier si la paire existe déjà
        result = await db.execute(
            select(GuardianPairDB).where(
                GuardianPairDB.protected_device_id == protected_device_id,
                GuardianPairDB.guardian_device_id == guardian_device_id
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Mettre à jour le token FCM si fourni
            if guardian_fcm_token:
                existing.guardian_fcm_token = guardian_fcm_token
            return {"status": "already_exists", "pair_id": existing.id}

        pair = GuardianPairDB(
            protected_device_id=protected_device_id,
            guardian_device_id=guardian_device_id,
            guardian_fcm_token=guardian_fcm_token,
            protected_name=protected_name or "Proche protégé",
            is_active=True,
        )
        db.add(pair)
        await db.flush()

        return {"status": "created", "pair_id": pair.id}

    async def get_guardians(self, db: AsyncSession,
                            protected_device_id: str) -> list:
        """
        Retourne tous les Anges Gardiens d'un utilisateur protégé.
        """
        result = await db.execute(
            select(GuardianPairDB).where(
                GuardianPairDB.protected_device_id == protected_device_id,
                GuardianPairDB.is_active == True
            )
        )
        pairs = result.scalars().all()

        return [
            {
                "guardian_device_id": p.guardian_device_id,
                "guardian_fcm_token": p.guardian_fcm_token,
                "sensitivity_mode": p.sensitivity_mode,
            }
            for p in pairs
        ]

    async def log_alert(self, db: AsyncSession,
                        protected_device_id: str,
                        guardian_device_id: str,
                        threat_type: str,
                        threat_level: str,
                        risk_score: int,
                        notification_sent: bool = False):
        """Enregistre une alerte envoyée à un Ange Gardien."""
        alert = AlertLogDB(
            protected_device_id=protected_device_id,
            guardian_device_id=guardian_device_id,
            threat_type=threat_type,
            threat_level=threat_level,
            risk_score=risk_score,
            notification_sent=notification_sent,
        )
        db.add(alert)
        await db.flush()


# Instance globale
db_service = DBService()