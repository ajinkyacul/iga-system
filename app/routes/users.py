from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import User, Role, AuditLog

users_bp = Blueprint('users', __name__, url_prefix='/users')


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('auth.dashboard'))
        return f(*args, **kwargs)
    return decorated


@users_bp.route('/')
@login_required
def list_users():
    if not current_user.has_permission('user_view') and not current_user.is_admin:
        flash('Permission denied', 'error')
        return redirect(url_for('auth.dashboard'))
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=users)


@users_bp.route('/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        department = request.form.get('department')
        if not username or not email or not password:
            flash('Username, email, and password are required', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
        else:
            user = User(username=username, email=email,
                        full_name=full_name, department=department)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            role_ids = request.form.getlist('roles')
            for rid in role_ids:
                role = db.session.get(Role, int(rid))
                if role:
                    user.roles.append(role)
            db.session.commit()
            log = AuditLog(user_id=current_user.id, username=current_user.username,
                           action='USER_CREATE', target_type='User', target_id=str(user.id),
                           details=f'Created user {username}', ip_address=request.remote_addr)
            db.session.add(log)
            db.session.commit()
            flash(f'User {username} created successfully', 'success')
            return redirect(url_for('users.list_users'))
    roles = Role.query.all()
    return render_template('user_form.html', user=None, roles=roles)


@users_bp.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('users.list_users'))
    if request.method == 'POST':
        user.email = request.form.get('email', user.email)
        user.full_name = request.form.get('full_name', user.full_name)
        user.department = request.form.get('department', user.department)
        user.is_active = request.form.get('is_active') == 'on'
        user.roles = []
        role_ids = request.form.getlist('roles')
        for rid in role_ids:
            role = db.session.get(Role, int(rid))
            if role:
                user.roles.append(role)
        password = request.form.get('password')
        if password:
            user.set_password(password)
        log = AuditLog(user_id=current_user.id, username=current_user.username,
                       action='USER_EDIT', target_type='User', target_id=str(user.id),
                       details=f'Edited user {user.username}', ip_address=request.remote_addr)
        db.session.add(log)
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('users.list_users'))
    roles = Role.query.all()
    return render_template('user_form.html', user=user, roles=roles)


@users_bp.route('/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('users.list_users'))
    if user.id == current_user.id:
        flash('Cannot delete yourself', 'error')
        return redirect(url_for('users.list_users'))
    if user.is_admin:
        flash('Cannot delete admin users', 'error')
        return redirect(url_for('users.list_users'))
    log = AuditLog(user_id=current_user.id, username=current_user.username,
                   action='USER_DELETE', target_type='User', target_id=str(user.id),
                   details=f'Deleted user {user.username}', ip_address=request.remote_addr)
    db.session.add(log)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('users.list_users'))
