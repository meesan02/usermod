from models import Role, User, Permission, Applications, RoutePermissionMap
from sqlalchemy.orm import Session
from typing import Optional
from core import NotFoundException, AlreadyExistsException

class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email).first()

    def get_by_username(self, username: str) -> Optional[User]:
        return self.db.query(User).filter(User.username == username).first()

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        return self.db.query(User).filter_by(id=user_id).first()

    def get_user_by_id_and_username(self, user_id: str, username: str) -> Optional[User]:
        return self.db.query(User).filter_by(id=user_id, username=username).first()
    
    def get_user_by_id_and_email(self, user_id: str, email: str) -> Optional[User]:
        return self.db.query(User).filter_by(id=user_id, email=email).first()
    
    def get_user_by_email_and_username(self, email: str, username: str) -> Optional[User]:
        return self.db.query(User).filter_by(email=email, username=username).first()

    def add_user(self, user: User):
        try:
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            return user
        except Exception as e:
            self.db.rollback()
            raise e

    def update_user(self, user: User):
        self.db.commit()
        self.db.refresh(user)
        return user
    
    def update_role(self, role: Role):
        self.db.commit()
        self.db.refresh(role)
        return role

    def get_role_by_name(self, role_name: str) -> Optional[Role]:
        return self.db.query(Role).filter(Role.name == role_name).first()
    
    def add_role(self, role: Role):
        try:
            self.db.add(role)
            self.db.commit()
            self.db.refresh(role)
            return role
        except Exception as e:
            self.db.rollback()
            raise e
    
    def delete_role(self, role_name: str):
        role = self.get_role_by_name(role_name)
        if not role:
            raise NotFoundException("Role not found")
        self.db.delete(role)
        self.db.commit()
        return {"detail": "Role deleted successfully."}

    def add_user_oauth(self, email: str, username: str, first_name: str, last_name: str, provider: str):
        try:
            user = User(
                email=email,
                username=username,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
                is_verified=True,
                oauth_provider=provider
            )
            self.db.add(user)
            self.db.commit()
            self.db.refresh(user)
            return user
        except Exception as e:
            self.db.rollback()
            raise e
    
    def get_permission_by_name(self, permission_name: str) -> Optional[Permission]:
        return self.db.query(Permission).filter(Permission.name == permission_name).first()

    def add_permission(self, permission: str, description: str = None):
        try:
            permission_exists = self.get_permission_by_name(permission)
            if permission_exists:
                return permission_exists
            permission_data = Permission(name=permission, description=description)
            self.db.add(permission_data)
            self.db.commit()
            self.db.refresh(permission_data)
            return permission_data
        except Exception as e:
            self.db.rollback()
            raise e
    
    def delete_permission(self, permission_name: str):
        permission = self.get_permission_by_name(permission_name)
        if not permission:
            raise NotFoundException("Permission not found")
        self.db.delete(permission)
        self.db.commit()
        return {"detail": "Permission deleted successfully."}
    
    def get_applications_by_user_id(self, user_id: str) -> list:
        user_data = self.db.query(User).filter_by(id=user_id).first()
        return user_data.applications if user_data else []
    
    def update_applications_by_user_id(self, user_id: str, applications: list[str]):
        try:
            # for i in applications:
            #     if self.fetch_application(i) is None:
            #         raise Exception(f"{i} Application do not exist")
            if self.db.query(Applications).filter(Applications.name.in_(applications)).count() != len(applications):
                raise NotFoundException("One or more applications do not exist")
            self.db.query(User).filter_by(id=user_id).update({"applications": applications})
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise e

    def add_application(self, application: str, description: str = None):
        try:
            if not self.db.query(Applications).filter_by(name=application).first():
                application_data = Applications(name=application, description=description)
                self.db.add(application_data)
                self.db.commit()
                self.db.refresh(application_data)
                return application_data
            else:
                raise AlreadyExistsException("Application already exists")
        except Exception as e:
            self.db.rollback()
            raise e
    
    def fetch_application(self, application_name: str) -> Optional[Applications]:
        return self.db.query(Applications).filter_by(name=application_name).first()
    
    def fetch_all_applications(self) -> list[str]:
        return self.db.query(Applications.name).scalars().all()
    
    def create_route_map(self, route: str, permission: str):
        try:
            permission = self.db.query(Permission).filter_by(name=permission).first()
            if not permission:
                raise NotFoundException("Permission does not exist")
            route_map = RoutePermissionMap(route=route, permission=permission)
            self.db.add(route_map)
            self.db.commit()
            self.db.refresh(route_map)
            return route_map
        except Exception as e:
            self.db.rollback()
            raise e
    
    def update_route_map_permission(self, route: str, old_permission: str, new_permission: str):
        try:
            old_permission_obj = self.db.query(Permission).filter_by(name=old_permission).first()
            new_permission_obj = self.db.query(Permission).filter_by(name=new_permission).first()
            if not old_permission_obj or not new_permission_obj:
                raise NotFoundException("Permission does not exist")


            route_map = self.db.query(RoutePermissionMap).filter_by(route=route, permission_name=old_permission).first()
            if not route_map:
                raise NotFoundException(f"Route mapping for '{route}' with permission '{old_permission}' not found.")

            route_map.permission_name = new_permission
            route_map.permission = new_permission_obj
            self.db.commit()
    
        except Exception as e:
            self.db.rollback()
            raise e
    
    def delete_route_map(self, route: str):
        try:
            self.db.query(RoutePermissionMap).filter_by(route=route).delete()
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            raise e
    
    def fetch_route_map(self, route: str) -> Optional[RoutePermissionMap]:
        return self.db.query(RoutePermissionMap).filter_by(route=route).first()
    
    def fetch_all_route_map(self) -> list[RoutePermissionMap]:
        return self.db.query(RoutePermissionMap).all()
    
    def update_user_verification(self, user_id: str, verification_status: bool = True):
        user = self.get_user_by_id(user_id)
        if not user:
            raise NotFoundException("User not found")
        user.is_verified = verification_status
        self.db.commit()
        self.db.refresh(user)
        return user

