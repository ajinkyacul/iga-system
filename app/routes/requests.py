from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from datetime import datetime, timezone
from app import db
from app.models import User, Role, AccessRequest, AuditLog

requests_bp = Blueprint('requests', __name__, url_prefix='/requests')


@requests_bp.route('/')
@login_required
def list_requests():
    if current_user.is_admin:
        requests = AccessRequest.query.order_by(AccessRequest.requested_at.desc()).all()
    else:
        requests = AccessRequest.query.filter_by(user_id=current_user.id).order_by(
            AccessRequest.requested_at.desc()).all()
    return render_template('access_requests.html', requests=requests)


@requests_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_request():
    if request.method == 'POST':
        role_id = request.form.get('role_id')
        reason = request.form.get('reason')
        if not role_id:
            flash('Please select a role', 'error')
        else:
            role = db.session.get(Role, int(role_id))
            if not role:
                flash('Role not found', 'error')
            elif AccessRequest.query.filter_by(
                    user_id=current_user.id, role_id=role.id,
                    status='pending').first():
                flash('You already have a pending request for this role', 'error')
            else:
                req = AccessRequest(
                    user_id=current_user.id, role_id=role.id,
                    reason=reason, status='pending'
                )
                db.session.add(req)
                log = AuditLog(user_id=current_user.id, username=current_user.username,
                               action='ACCESS_REQUEST', target_type='AccessRequest',
                               target_id=str(req.id),
                               details=f'Requested role {role.name}',
                               ip_address=request.remote_addr)
                db.session.add(log)
                db.session.commit()
                flash('Access request submitted for approval', 'success')
                return redirect(url_for('requests.list_requests'))
    roles = Role.query.all()
    return render_template('request_form.html', roles=roles)


@requests_bp.route('/approve/<int:req_id>', methods=['POST'])
@login_required
def approve_request(req_id):
    if not current_user.is_admin and not current_user.has_permission('access_request_approve'):
        flash('Permission denied', 'error')
        return redirect(url_for('requests.list_requests'))
    req = db.session.get(AccessRequest, req_id)
    if not req or req.status != 'pending':
        flash('Request not found or already processed', 'error')
        return redirect(url_for('requests.list_requests'))
    user = db.session.get(User, req.user_id)
    if user:
        user.roles.append(req.role)
    req.status = 'approved'
    req.approved_by = current_user.id
    req.approved_at = datetime.now(timezone.utc)
    log = AuditLog(user_id=current_user.id, username=current_user.username,
                   action='ACCESS_APPROVED', target_type='AccessRequest',
                   target_id=str(req.id),
                   details=f'Approved role {req.role.name} for {user.username if user else "unknown"}',
                   ip_address=request.remote_addr)
    db.session.add(log)
    db.session.commit()
    flash('Access request approved', 'success')
    return redirect(url_for('requests.list_requests'))


@requests_bp.route('/deny/<int:req_id>', methods=['POST'])
@login_required
def deny_request(req_id):
    if not current_user.is_admin and not current_user.has_permission('access_request_approve'):
        flash('Permission denied', 'error')
        return redirect(url_for('requests.list_requests'))
    req = db.session.get(AccessRequest, req_id)
    if not req or req.status != 'pending':
        flash('Request not found or already processed', 'error')
        return redirect(url_for('requests.list_requests'))
    reason = request.form.get('denied_reason', 'No reason provided')
    req.status = 'denied'
    req.approved_by = current_user.id
    req.approved_at = datetime.now(timezone.utc)
    req.denied_reason = reason
    log = AuditLog(user_id=current_user.id, username=current_user.username,
                   action='ACCESS_DENIED', target_type='AccessRequest',
                   target_id=str(req.id),
                   details=f'Denied role {req.role.name}: {reason}',
                   ip_address=request.remote_addr)
    db.session.add(log)
    db.session.commit()
    flash('Access request denied', 'success')
    return redirect(url_for('requests.list_requests'))
