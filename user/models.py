from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import uuid
from datetime import datetime

UserBase = declarative_base()

class User(UserBase):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    first_name = Column(String(100), nullable=True)
    last_name = Column(String(100), nullable=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    role_id = Column(String(36), ForeignKey("roles.id"))
    role = relationship("Role", back_populates="users")
    auth_code = Column(String(255), nullable=True)
    consent = Column(Boolean, default=False)
    oauth_provider = Column(String(50), nullable=True)
    # auth_code_expiry = Column(DateTime, nullable=True)

class Role(UserBase):
    __tablename__ = "roles"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    name = Column(String(72), unique=True, nullable=False)
    permissions = Column(String(255), nullable=False)
    users = relationship("User", back_populates="role")  # Comma-separated permission strings
