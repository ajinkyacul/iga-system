from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import Role, Permission, AuditLog

roles_bp = Blueprint('roles', __name__, url_prefix='/roles')


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('auth.dashboard'))
        return f(*args, **kwargs)
    return decorated


@roles_bp.route('/')
@login_required
def list_roles():
    if not current_user.has_permission('role_view') and not current_user.is_admin:
        flash('Permission denied', 'error')
        return redirect(url_for('auth.dashboard'))
    roles = Role.query.all()
    return render_template('roles.html', roles=roles)


@roles_bp.route('/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_role():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        if not name:
            flash('Role name is required', 'error')
        elif Role.query.filter_by(name=name).first():
            flash('Role name already exists', 'error')
        else:
            role = Role(name=name, description=description)
            db.session.add(role)
            db.session.commit()
            perm_ids = request.form.getlist('permissions')
            for pid in perm_ids:
                perm = db.session.get(Permission, int(pid))
                if perm:
                    role.permissions.append(perm)
            log = AuditLog(user_id=current_user.id, username=current_user.username,
                           action='ROLE_CREATE', target_type='Role', target_id=str(role.id),
                           details=f'Created role {name}', ip_address=request.remote_addr)
            db.session.add(log)
            db.session.commit()
            flash(f'Role {name} created successfully', 'success')
            return redirect(url_for('roles.list_roles'))
    permissions = Permission.query.order_by(Permission.category, Permission.name).all()
    return render_template('role_form.html', role=None, permissions=permissions)


@roles_bp.route('/edit/<int:role_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_role(role_id):
    role = db.session.get(Role, role_id)
    if not role:
        flash('Role not found', 'error')
        return redirect(url_for('roles.list_roles'))
    if request.method == 'POST':
        role.description = request.form.get('description', role.description)
        role.permissions = []
        perm_ids = request.form.getlist('permissions')
        for pid in perm_ids:
            perm = db.session.get(Permission, int(pid))
            if perm:
                role.permissions.append(perm)
        log = AuditLog(user_id=current_user.id, username=current_user.username,
                       action='ROLE_EDIT', target_type='Role', target_id=str(role.id),
                       details=f'Edited role {role.name}', ip_address=request.remote_addr)
        db.session.add(log)
        db.session.commit()
        flash('Role updated successfully', 'success')
        return redirect(url_for('roles.list_roles'))
    permissions = Permission.query.order_by(Permission.category, Permission.name).all()
    return render_template('role_form.html', role=role, permissions=permissions)


@roles_bp.route('/delete/<int:role_id>', methods=['POST'])
@login_required
@admin_required
def delete_role(role_id):
    role = db.session.get(Role, role_id)
    if not role:
        flash('Role not found', 'error')
        return redirect(url_for('roles.list_roles'))
    if role.is_system_role:
        flash('Cannot delete system roles', 'error')
        return redirect(url_for('roles.list_roles'))
    log = AuditLog(user_id=current_user.id, username=current_user.username,
                   action='ROLE_DELETE', target_type='Role', target_id=str(role.id),
                   details=f'Deleted role {role.name}', ip_address=request.remote_addr)
    db.session.add(log)
    db.session.delete(role)
    db.session.commit()
    flash('Role deleted successfully', 'success')
    return redirect(url_for('roles.list_roles'))
