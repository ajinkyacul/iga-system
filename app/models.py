from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager


user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(120))
    department = db.Column(db.String(80))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery', backref=db.backref('users', lazy=True))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        return any(
            p.name == permission_name
            for role in self.roles
            for p in role.permissions
        )

    def has_role(self, role_name):
        return any(r.name == role_name for r in self.roles)

    def __repr__(self):
        return f'<User {self.username}>'


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False, index=True)
    description = db.Column(db.String(256))
    is_system_role = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    permissions = db.relationship('Permission', secondary=role_permissions, lazy='subquery',
                                  backref=db.backref('roles', lazy=True))

    def __repr__(self):
        return f'<Role {self.name}>'


class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(256))
    category = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Permission {self.name}>'


class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    reason = db.Column(db.Text)
    requested_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    denied_reason = db.Column(db.Text, nullable=True)
    requestor = db.relationship('User', foreign_keys=[user_id], backref=db.backref('access_requests', lazy=True))
    approver = db.relationship('User', foreign_keys=[approved_by], backref=db.backref('approved_requests', lazy=True))
    role = db.relationship('Role', backref=db.backref('access_requests', lazy=True))

    def __repr__(self):
        return f'<AccessRequest {self.id} - {self.status}>'


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80))
    action = db.Column(db.String(80), nullable=False)
    target_type = db.Column(db.String(80))
    target_id = db.Column(db.String(80))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))

    def __repr__(self):
        return f'<AuditLog {self.action} by {self.username}>'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def seed_defaults():
    if User.query.first() is not None:
        return

    admin_perms = []
    for perm_name, desc, cat in [
        ('user_view', 'View users', 'User Management'),
        ('user_create', 'Create users', 'User Management'),
        ('user_edit', 'Edit users', 'User Management'),
        ('user_delete', 'Delete users', 'User Management'),
        ('role_view', 'View roles', 'Role Management'),
        ('role_create', 'Create roles', 'Role Management'),
        ('role_edit', 'Edit roles', 'Role Management'),
        ('role_delete', 'Delete roles', 'Role Management'),
        ('access_request_approve', 'Approve access requests', 'Access Requests'),
        ('audit_view', 'View audit logs', 'Audit'),
    ]:
        perm = Permission(name=perm_name, description=desc, category=cat)
        db.session.add(perm)
        admin_perms.append(perm)

    view_role = Role(name='Viewer', description='Can view users and roles', is_system_role=True)
    user_role = Role(name='User', description='Standard user with basic access', is_system_role=True)
    admin_role = Role(name='Administrator', description='Full system access', is_system_role=True)
    db.session.add_all([view_role, user_role, admin_role])

    admin_role.permissions.extend(admin_perms)
    view_role.permissions.append(Permission.query.filter_by(name='user_view').first())
    view_role.permissions.append(Permission.query.filter_by(name='role_view').first())
    user_role.permissions.append(Permission.query.filter_by(name='user_view').first())
    user_role.permissions.append(Permission.query.filter_by(name='role_view').first())

    admin = User(
        username='admin',
        email='admin@iga.local',
        full_name='System Administrator',
        department='IT',
        is_active=True,
        is_admin=True
    )
    admin.set_password('Admin@123')
    admin.roles.append(admin_role)
    db.session.add(admin)

    db.session.commit()
