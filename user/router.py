from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .sso_router import router as sso_router
from .db import get_db
from .schemas import (
    UserBase,
    UserCreate,
    UserInDB,
    UserLogin,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    AssignRoleRequest,
    PermissionsRequest,
    RoleBase,
    RoleCreate,
    RoleInDB,
)
from .service import UserService
from .repository import UserRepository
from .config import settings


router = APIRouter()


router.include_router(sso_router, prefix="/sso", tags=["SSO"])



@router.post("/register", response_model=UserInDB)
def register(user: UserCreate, db: Session = Depends(get_db)):
    new_user = UserService(db).register_user(user)
    return UserInDB(
        user_id=new_user.id,
        email=new_user.email,
        username=new_user.username,
        first_name=new_user.first_name,
        last_name=new_user.last_name,
        is_active=new_user.is_active,
        is_verified=new_user.is_verified,
        role=new_user.role.name if new_user.role else None,
        consent=new_user.consent
    )

@router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    return UserService(db).authenticate_user(user)

@router.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    return UserService(db).forgot_password(request.email)

@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    return UserService(db).reset_password(request.token, request.new_password)

@router.post("/permissions", response_model=list[str])
def get_permissions(request: PermissionsRequest, db: Session = Depends(get_db)):
    return UserService(db).get_user_permissions(request.user_id)

@router.post("/assign-role", response_model=UserInDB)
def assign_role(request: AssignRoleRequest, db: Session = Depends(get_db)):
    updated_user = UserService(db).assign_role(request.user_id, request.role_name)
    return UserInDB(
        user_id=updated_user.id,
        email=updated_user.email,
        username=updated_user.username,
        is_active=updated_user.is_active,
        is_verified=updated_user.is_verified,
        role=updated_user.role.name if updated_user.role else None
    )


@router.post("/get-user", response_model=UserInDB)
def get_current_user(user: UserBase, db: Session = Depends(get_db)):
    if user.email:
        user = UserRepository(db).get_user_by_id_and_email(user_id=user.user_id, email=user.email)
    elif user.username:
        user = UserRepository(db).get_user_by_id_and_username(user_id=user.user_id, username=user.username)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email or username not provided")
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserInDB(
        user_id=user.id,
        username=user.username,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        is_active=user.is_active,
        is_verified=user.is_verified,
        role=user.role.name if user.role else None,
        consent=user.consent
    )


@router.post("/create-role", response_model=RoleInDB)
def create_role(role: RoleCreate, db: Session = Depends(get_db)):
    role_exists = UserRepository(db).get_role_by_name(role_name=role.name)
    if role_exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role already exists")
    role = UserRepository(db).add_role(role)
    return RoleInDB(
        id=role.id,
        name=role.name,
        permissions=role.permissions
    )

@router.post("/get-roles", response_model=RoleInDB)
def get_roles(role: RoleBase, db: Session = Depends(get_db)):
    role = UserRepository(db).get_role_by_name(role_name=role.name)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return RoleInDB(
        id=role.id,
        name=role.name,
        permissions=role.permissions,
        users=role.users
    )
