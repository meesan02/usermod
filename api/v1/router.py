from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from .sso_router import router as sso_router
from db import get_db
from schemas import (
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
    FetchPermission,
    Map,
    PermissionBase,
)
from services import UserService
from repository import UserRepository


router = APIRouter()


router.include_router(sso_router, prefix="/sso")



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
        consent=new_user.consent,
        roles=[role.name for role in new_user.roles]
    )

@router.post("/login")
def login(user: UserLogin, request: Request, db: Session = Depends(get_db)):
    application = request.headers.get("X-Application")
    return UserService(db).authenticate_user(user, application)

@router.get("/authenticate")
def authenticate(request: Request, db: Session = Depends(get_db)):
    auth_code = request.headers.get("X-Auth-Code")
    application = request.headers.get("X-Application")
    if UserService(db).validate_auth_code(auth_code, application):
        return {"status_code": status.HTTP_200_OK, "message": "Authentication successful"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication code")


@router.post("/forgot-password")
def forgot_password(
    request_data: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)
):
    application = request.headers.get("X-Application")
    return UserService(db).forgot_password(request_data.email, application)


@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    return UserService(db).reset_password(request.token, request.new_password)


@router.post("/verify-user")
def verify_user(user_id: str, verification_status: bool = True, db: Session = Depends(get_db)):
    return UserRepository(db).update_user_verification(user_id, verification_status)


@router.post("/get-user", response_model=UserInDB)
def get_current_user(user: UserBase, db: Session = Depends(get_db)):
    if user.email and user.user_id:
        user = UserRepository(db).get_user_by_id_and_email(user_id=user.user_id, email=user.email)
    elif user.username and user.user_id:
        user = UserRepository(db).get_user_by_id_and_username(user_id=user.user_id, username=user.username)
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email or Username or User ID not provided")
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
        consent=user.consent,
        roles=[role.name for role in user.roles]
    )


@router.post("/permissions", response_model=list[str])
def get_permissions(request: PermissionsRequest, db: Session = Depends(get_db)):
    return UserService(db).get_user_permissions(request.user_id)

@router.post('/create-permission')
def create_permission(permission: PermissionBase, db: Session = Depends(get_db)):
    return UserService(db).create_permission(permission.name, permission.description)

@router.post('/delete-permission')
def delete_permission(permission_name: str, db: Session = Depends(get_db)):
    return UserRepository(db).delete_permission(permission_name)


@router.post("/create-role", response_model=RoleInDB)
def create_role(role: RoleCreate, db: Session = Depends(get_db)):
    user_repo = UserRepository(db)
    user_service = UserService(db)
    # for permission in role.permissions:
    #     # if not user_repo.get_permission_by_name(permission_name=permission):
    #     permissions = user_repo.add_permission(permission=permission)
    #     print(permissions)
    role_exists = user_repo.get_role_by_name(role_name=role.name)
    if role_exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role already exists")
    role = user_service.create_role(role_name=role.name, permissions=role.permissions)
    return RoleInDB(
        id=role.id,
        name=role.name,
        permissions=user_service.format_permissions(role.permissions)
    )

@router.post("/get-roles", response_model=RoleInDB)
def get_roles(role: RoleBase, db: Session = Depends(get_db)):
    role = UserRepository(db).get_role_by_name(role_name=role.name)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return RoleInDB(
        id=role.id,
        name=role.name,
        permissions=UserService(db).format_permissions(role.permissions),
        # users=role.users
    )

@router.post('/delete-role')
def delete_role(role_name: str, db: Session = Depends(get_db)):
    return UserRepository(db).delete_role(role_name)

@router.post("/assign-role")
def assign_role(request: AssignRoleRequest, db: Session = Depends(get_db)):
    return UserService(db).assign_role(request.user_id, request.role_name)
    # return UserInDB(
    #     user_id=updated_user.id,
    #     email=updated_user.email,
    #     username=updated_user.username,
    #     first_name=updated_user.first_name,
    #     last_name=updated_user.last_name,
    #     is_active=updated_user.is_active,
    #     is_verified=updated_user.is_verified,
    #     roles=[role.name for role in updated_user.roles]
    # )


@router.post("/remove-role")
def remove_role(request: AssignRoleRequest, db: Session = Depends(get_db)):
    return UserService(db).remove_role(request.user_id, request.role_name)


@router.post("/add-permission-to-role")
def add_permission(request: FetchPermission, db: Session = Depends(get_db)):
    return UserService(db).add_permission_to_role(request.role_name, request.name)


@router.post("/remove-permission-from-role")
def remove_permission(request: FetchPermission, db: Session = Depends(get_db)):
    return UserService(db).remove_permission_from_role(request.role_name, request.name)


@router.post("/applications")
def get_applications(user: UserBase, db: Session = Depends(get_db)):
    return UserRepository(db).get_applications_by_user_id(user_id=user.user_id)

@router.post("/update-applications")
def update_applications(user: UserBase, application: str, db: Session = Depends(get_db)):
    try:
        if application is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Application not provided")
        if user.user_id:
            return UserService(db).update_application(user_id=user.user_id, application=application)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User ID not provided")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

@router.post('/enrol-application')
def enrol_application(application: str, description: str = None, db: Session = Depends(get_db)):
    try:
        return UserService(db).enrol_application(application, description)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post('/create-route-mapping')
def create_mapping(mappings: list[Map], db: Session = Depends(get_db)):
    for mapping in mappings:
        UserService(db).create_route_map(mapping.route, mapping.permission)
    return {"detail": "Route mapping created successfully."}

@router.post('/fetch-route-mapping')
def fetch_mapping(route: str, db: Session = Depends(get_db)):
    return UserService(db).fetch_route_map(route)

@router.post('/update-route-mapping')
def update_mapping(route: str, old_permission: str, new_permission: str, db: Session = Depends(get_db)):
    UserService(db).update_route_map_permission(route, old_permission, new_permission)
    return {"detail": "Route mapping updated successfully."}

@router.post('/delete-route-mapping')
def delete_mapping(route: str, db: Session = Depends(get_db)):
    UserService(db).delete_route_map(route)
    return {"detail": "Route mapping deleted successfully."}

@router.get('/fetch-all-route-mapping')
def fetch_all_mapping(db: Session = Depends(get_db)):
    return UserService(db).fetch_all_route_map()
