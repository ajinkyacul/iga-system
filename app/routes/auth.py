from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timezone
from app import db
from app.models import User, AuditLog

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('auth.dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.is_active and user.check_password(password):
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            log = AuditLog(
                user_id=user.id, username=user.username,
                action='LOGIN', target_type='User', target_id=str(user.id),
                details='User logged in', ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            return redirect(url_for('auth.dashboard'))
        flash('Invalid credentials or account disabled', 'error')
    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    log = AuditLog(
        user_id=current_user.id, username=current_user.username,
        action='LOGOUT', target_type='User', target_id=str(current_user.id),
        details='User logged out', ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old = request.form.get('old_password')
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        if not current_user.check_password(old):
            flash('Current password is incorrect', 'error')
        elif new != confirm:
            flash('New passwords do not match', 'error')
        elif len(new) < 6:
            flash('Password must be at least 6 characters', 'error')
        else:
            current_user.set_password(new)
            log = AuditLog(
                user_id=current_user.id, username=current_user.username,
                action='PASSWORD_CHANGE', target_type='User',
                target_id=str(current_user.id),
                details='Password changed', ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            flash('Password changed successfully', 'success')
            return redirect(url_for('auth.dashboard'))
    return render_template('change_password.html')


@auth_bp.route('/')
@auth_bp.route('/dashboard')
@login_required
def dashboard():
    from app.models import User, Role, AccessRequest, AuditLog
    total_users = User.query.count()
    total_roles = Role.query.count()
    pending_requests = AccessRequest.query.filter_by(status='pending').count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()
    return render_template('dashboard.html', total_users=total_users,
                           total_roles=total_roles, pending_requests=pending_requests,
                           recent_logs=recent_logs)
