from app import db
from app.models import Role, Permission


class RoleService:

    @staticmethod
    def get_role_by_id(role_id):
        return db.session.get(Role, role_id)

    @staticmethod
    def get_role_by_name(name):
        return Role.query.filter_by(name=name).first()

    @staticmethod
    def get_all_roles():
        return Role.query.all()

    @staticmethod
    def create_role(name, description=None, permissions=None):
        role = Role(name=name, description=description)
        if permissions:
            role.permissions.extend(permissions)
        db.session.add(role)
        db.session.commit()
        return role

    @staticmethod
    def assign_permission_to_role(role, permission):
        if permission not in role.permissions:
            role.permissions.append(permission)
            db.session.commit()

    @staticmethod
    def remove_permission_from_role(role, permission):
        if permission in role.permissions:
            role.permissions.remove(permission)
            db.session.commit()

    @staticmethod
    def get_all_permissions():
        return Permission.query.order_by(Permission.category, Permission.name).all()

    @staticmethod
    def get_permissions_by_category():
        perms = Permission.query.order_by(Permission.category, Permission.name).all()
        grouped = {}
        for p in perms:
            grouped.setdefault(p.category, []).append(p)
        return grouped

    @staticmethod
    def get_roles_for_user(user):
        return user.roles

    @staticmethod
    def get_role_count():
        return Role.query.count()
