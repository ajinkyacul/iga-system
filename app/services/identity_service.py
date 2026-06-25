from app import db
from app.models import User


class IdentityService:

    @staticmethod
    def get_user_by_id(user_id):
        return db.session.get(User, user_id)

    @staticmethod
    def get_user_by_username(username):
        return User.query.filter_by(username=username).first()

    @staticmethod
    def get_all_users():
        return User.query.order_by(User.created_at.desc()).all()

    @staticmethod
    def get_active_users():
        return User.query.filter_by(is_active=True).all()

    @staticmethod
    def search_users(query):
        return User.query.filter(
            User.username.contains(query) |
            User.email.contains(query) |
            User.full_name.contains(query)
        ).all()

    @staticmethod
    def create_user(username, email, password, full_name=None, department=None, roles=None):
        user = User(username=username, email=email,
                    full_name=full_name, department=department)
        user.set_password(password)
        if roles:
            user.roles.extend(roles)
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def deactivate_user(user_id):
        user = db.session.get(User, user_id)
        if user:
            user.is_active = False
            db.session.commit()
        return user

    @staticmethod
    def get_users_by_role(role_name):
        return User.query.filter(User.roles.any(name=role_name)).all()

    @staticmethod
    def get_user_count():
        return User.query.count()
