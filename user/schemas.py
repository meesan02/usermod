from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class UserBase(BaseModel):
    user_id: Optional[str] = Field(None, max_length=36)
    username: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = Field(None, max_length=100)
    roles: Optional[list[str]] = Field(None, max_length=255)


class UserCreate(BaseModel):
    first_name: str = Field(..., max_length=100)
    last_name: str = Field(..., max_length=100)
    username: str = Field(..., max_length=100)
    email: EmailStr = Field(..., max_length=100)
    password: str = Field(..., max_length=255)
    consent: bool = Field(False)

class UserInDB(UserBase):
    # user_id: str = Field(..., max_length=36)
    first_name: Optional[str] = Field(..., max_length=100)
    last_name: Optional[str] = Field(..., max_length=100)
    role: Optional[str] = Field(None, max_length=72)
    is_active: Optional[bool] = True
    is_verified: Optional[bool] = False
    consent: Optional[bool] = False
    # auth_code: Optional[str] = None
    # auth_code_expiry: Optional[datetime] = None

class UserUpdate(UserInDB):
    password: Optional[str] = Field(None, max_length=255)
    role_id: Optional[str] = Field(None, max_length=36)

class UserLogin(UserBase):
    user_id: Optional[str] = Field(None, max_length=36)
    password: str = Field(..., max_length=255)

class ForgotPasswordRequest(BaseModel):
    email: EmailStr = Field(..., max_length=100)

class ResetPasswordRequest(BaseModel):
    token: str = Field(..., max_length=255)
    new_password: str = Field(..., max_length=255)

class AssignRoleRequest(UserBase):
    # user_id: str = Field(..., max_length=36)
    role_name: str = Field(..., max_length=72)

class PermissionsRequest(UserBase):
    # user_id: str = Field(..., max_length=36)
    pass


# TODO: Check the requirement of below schemas and update / remove these.

# class UserOut(UserBase):
#     user_id: str = Field(..., max_length=36)
#     is_active: bool
#     is_verified: bool
#     role: Optional[str] = Field(None, max_length=72)

class RoleBase(BaseModel):
    name: str = Field(..., max_length=72)
    permissions: Optional[list[str]] = Field(None, max_length=255)

class RoleCreate(RoleBase):
    pass

class RoleInDB(RoleBase):
    id: str = Field(..., max_length=36)
    # users: Optional[list[UserInDB]] = []

class GetRole(RoleBase):
    user_id: str = Field(..., max_length=36)


class PermissionBase(BaseModel):
    name: str = Field(..., max_length=72)
    description: Optional[str] = Field(None, max_length=255)

class PermissionCreate(PermissionBase):
    pass

class PermissionInDB(PermissionBase): # TODO: Check this.
    id: str = Field(..., max_length=36)
    roles: Optional[list[RoleInDB]] = []

class GetPermission(PermissionBase):
    role_id: str = Field(..., max_length=36)


# class RoleOut(BaseModel):
#     user_id: str
#     name: str
#     permissions: str


class Role(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True

