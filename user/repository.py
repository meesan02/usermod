from .models import Role, User
from sqlalchemy.orm import Session
from typing import Optional

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
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update_user(self, user: User):
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_role_by_name(self, role_name: str) -> Optional[Role]:
        return self.db.query(Role).filter(Role.name == role_name).first()
    
    def add_role(self, role: Role):
        self.db.add(role)
        self.db.commit()
        self.db.refresh(role)
        return role

    def add_user_oauth(self, email: str, username: str, first_name: str, last_name: str, provider: str):
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
