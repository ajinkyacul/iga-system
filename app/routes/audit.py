from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from app import db
from app.models import AuditLog

audit_bp = Blueprint('audit', __name__, url_prefix='/audit')


@audit_bp.route('/')
@login_required
def view_audit():
    if not current_user.is_admin and not current_user.has_permission('audit_view'):
        return render_template('audit.html', logs=[], error='Permission denied')
    page = request.args.get('page', 1, type=int)
    per_page = 50
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('username', '')
    query = AuditLog.query
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    if user_filter:
        query = query.filter(AuditLog.username.contains(user_filter))
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False)
    actions = db.session.query(AuditLog.action).distinct().all()
    return render_template('audit.html', logs=logs, actions=[a[0] for a in actions])
