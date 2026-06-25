from app import db
from app.models import AuditLog
from datetime import datetime, timedelta, timezone


class AuditService:

    @staticmethod
    def log(user_id, username, action, target_type=None, target_id=None,
            details=None, ip_address=None):
        log = AuditLog(
            user_id=user_id, username=username, action=action,
            target_type=target_type, target_id=target_id,
            details=details, ip_address=ip_address
        )
        db.session.add(log)
        db.session.commit()
        return log

    @staticmethod
    def get_recent_logs(limit=20):
        return AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_logs_by_user(username, limit=50):
        return AuditLog.query.filter_by(username=username).order_by(
            AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_logs_by_action(action, limit=50):
        return AuditLog.query.filter_by(action=action).order_by(
            AuditLog.timestamp.desc()).limit(limit).all()

    @staticmethod
    def get_logs_in_date_range(start, end):
        return AuditLog.query.filter(
            AuditLog.timestamp >= start,
            AuditLog.timestamp <= end
        ).order_by(AuditLog.timestamp.desc()).all()

    @staticmethod
    def get_recent_activities(hours=24):
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        return AuditLog.query.filter(AuditLog.timestamp >= since).order_by(
            AuditLog.timestamp.desc()).all()

    @staticmethod
    def get_distinct_actions():
        return [a[0] for a in db.session.query(AuditLog.action).distinct().all()]
