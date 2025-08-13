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
    first_name: Optional[str] = Field(..., max_length=100)
    last_name: Optional[str] = Field(..., max_length=100)
    # role: Optional[str] = Field(None, max_length=72)
    is_active: Optional[bool] = True
    is_verified: Optional[bool] = False
    consent: Optional[bool] = False

class UserLogin(UserBase):
    user_id: Optional[str] = Field(None, max_length=36)
    password: str = Field(..., max_length=255)

class ForgotPasswordRequest(BaseModel):
    email: EmailStr = Field(..., max_length=100)

class ResetPasswordRequest(BaseModel):
    token: str = Field(..., max_length=255)
    new_password: str = Field(..., max_length=255)

class AssignRoleRequest(UserBase):
    role_name: str = Field(..., max_length=72)

class PermissionsRequest(UserBase):
    pass

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

class FetchPermission(PermissionBase):
    role_name: str = Field(..., max_length=72)

class Map(BaseModel):
    route: str = Field(..., max_length=255)
    permission: str = Field(..., max_length=255)
