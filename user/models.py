from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import uuid
from datetime import datetime

UserBase = declarative_base()


# --- Association Tables for Many-to-Many Relationships ---

# Associates Users with Roles
user_role_association = Table(
    "user_roles",
    UserBase.metadata,
    Column("user_id", String(36), ForeignKey("users.id"), primary_key=True),
    Column("role_id", String(36), ForeignKey("roles.id"), primary_key=True),
)

# Associates Roles with Permissions
role_permission_association = Table(
    "role_permissions",
    UserBase.metadata,
    Column("role_id", String(36), ForeignKey("roles.id"), primary_key=True),
    Column("permission_id", String(36), ForeignKey("permissions.id"), primary_key=True),
)

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
    # role_id = Column(String(36), ForeignKey("roles.id"))
    roles = relationship("Role", secondary=user_role_association, back_populates="users")
    auth_code = Column(String(255), nullable=True)
    consent = Column(Boolean, default=False)
    oauth_provider = Column(String(50), nullable=True)
    # auth_code_expiry = Column(DateTime, nullable=True)

class Role(UserBase):
    __tablename__ = "roles"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    name = Column(String(72), unique=True, nullable=False)
    # permissions = relationship("Permission", back_populates="roles")
    permissions = relationship("Permission", secondary=role_permission_association, back_populates="roles")
    users = relationship("User", secondary=user_role_association, back_populates="roles")  # Comma-separated permission strings

class Permission(UserBase):
    __tablename__ = "permissions"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    name = Column(String(72), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    roles = relationship("Role", secondary=role_permission_association, back_populates="permissions")
    # users = relationship("User", secondary="user_permissions", back_populates="permissions")

# class UserPermission(UserBase):
#     __tablename__ = "user_permissions"
#     user_id = Column(String(36), ForeignKey("users.id"), primary_key=True)
#     permission_id = Column(list[String(36)], ForeignKey("permissions.id"), primary_key=True)
#     # permission_id = Column(String(36), ForeignKey("permissions.id"), primary_key=True)
#     user = relationship("User", back_populates="permissions")
#     permission = relationship("Permission")

