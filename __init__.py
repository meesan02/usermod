"""
The user package, providing models, services, and API routes for user management.
"""

from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from the .env file in this directory.
# This is done here to ensure that modules like `sso_router` and `config`
# have access to the environment variables when they are imported.
dotenv_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=dotenv_path, override=True)

# Routers
from .app import router, sso_router

# Core components
from .services import UserService
from .repository import UserRepository

# Data models and schemas
from .models import User, Role
from .schemas import (
    UserBase,
    UserCreate,
    UserInDB,
    UserLogin,
    UserUpdate,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    AssignRoleRequest,
    PermissionsRequest,
    RoleBase,
    RoleCreate,
    RoleInDB,
    GetRole,
)

# Database connection
from .db import get_db, create_db_and_tables

# Utility functions and configuration
from .helper import hash_password, verify_password, get_session_secret
from .core import settings
from .permissions import PERMISSIONS, ENDPOINT_PERMISSIONS

# Middleware and Authcode header for authentication
from .middleware import AuthCodeMiddleware, custom_openapi_authcode_header


# Expose key components for easier access from other parts of the application.
__all__ = [
    # Routers
    "router",
    "sso_router",
    # Services & Repos
    "UserService",
    "UserRepository",
    # Models
    "User",
    "Role",
    # Schemas
    "UserBase",
    "UserCreate",
    "UserInDB",
    "UserLogin",
    "UserUpdate",
    "ForgotPasswordRequest",
    "ResetPasswordRequest",
    "AssignRoleRequest",
    "PermissionsRequest",
    "RoleBase",
    "RoleCreate",
    "RoleInDB",
    "GetRole",
    # DB
    "get_db",
    "create_db_and_tables",
    # Helpers & Config
    "hash_password",
    "verify_password",
    "settings",
    "PERMISSIONS",
    "ENDPOINT_PERMISSIONS",
    "get_session_secret",
    # Middleware
    "AuthCodeMiddleware",
    # Authcode header
    "custom_openapi_authcode_header",
]