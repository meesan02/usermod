from .models import User, Permission, Role
from .repository import UserRepository
from .helper import hash_password, verify_password
from fastapi import HTTPException, status
import secrets
import base64
from datetime import datetime, timedelta

class UserService:
    def __init__(self, db):
        self.repo = UserRepository(db)

    def register_user(self, user_data):
        if self.repo.get_by_email(user_data.email) or self.repo.get_by_username(user_data.username):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email or username already registered")
        hashed_pw = hash_password(user_data.password)
        new_user = User(
            username=user_data.username,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            email=user_data.email,
            hashed_password=hashed_pw,
            is_active=True,
            is_verified=False,
            consent=user_data.consent,
        )
        return self.repo.add_user(new_user)

    def authenticate_user(self, user_data):
        user = None
        # print(user_data)
        if hasattr(user_data, 'password'):
            # print(user)
            if user_data.email:
                print(user_data.email)
                user = self.repo.get_by_email(user_data.email)
                print(user)
            elif user_data.username:
                user = self.repo.get_by_username(user_data.username)

            if (not user or not verify_password(user_data.password, user.hashed_password)):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
        elif isinstance(user_data, User):
            print('______________')
            user = user_data

        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not authenticate user")
        
        # Generate expiry timestamp (UTC, hours since epoch)
        expiry = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        # Generate a secure random string
        rand_token = secrets.token_urlsafe(60)
        # Combine expiry and token, encode as base64
        raw_code = f"{user.id}:{expiry}:{rand_token}"
        auth_code = base64.urlsafe_b64encode(raw_code.encode()).decode()
        user.auth_code = auth_code
        self.repo.update_user(user)
        return {
            # "user_id": user.id,
            "auth_code": auth_code,
            "auth_code_expiry": datetime.utcfromtimestamp(expiry).isoformat(sep=' ')
        }

    def forgot_password(self, email: str):
        """
        Handles the forgot password request.
        Generates a password reset token and sends it to the user's email.
        (Email sending is mocked here by returning a success message).
        """
        user = self.repo.get_by_email(email)
        if user:
            # Generate a password reset token with a short expiry (e.g., 15 minutes)
            expiry = int((datetime.utcnow() + timedelta(minutes=15)).timestamp())
            rand_token = secrets.token_urlsafe(32)
            raw_code = f"{user.id}:{expiry}:{rand_token}"
            reset_token = base64.urlsafe_b64encode(raw_code.encode()).decode()

            # Store this token as the current auth_code. This invalidates any existing session.
            user.auth_code = reset_token
            self.repo.update_user(user)

            # In a real application, you would send an email here with the reset_token.
            # For example: send_password_reset_email(user.email, reset_token)
        
        # To prevent user enumeration, always return a success message.
        return {"message": "If an account with that email exists, a password reset link has been sent."}

    def reset_password(self, token: str, new_password: str):
        """
        Resets the user's password using a valid reset token.
        """
        try:
            decoded = base64.urlsafe_b64decode(token.encode()).decode()
            user_id, expiry_str, _ = decoded.split(":", 2)
            expiry = int(expiry_str)
        except Exception:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or malformed reset token.")

        if expiry < int(datetime.utcnow().timestamp()):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reset token has expired.")

        user = self.repo.get_user_by_id(user_id)
        if not user or not user.auth_code or user.auth_code != token:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or already used reset token.")

        user.hashed_password = hash_password(new_password)
        user.auth_code = None
        self.repo.update_user(user)

        return {"message": "Password has been reset successfully."}

    def validate_auth_code(self, auth_code: str):
        try:
            decoded = base64.urlsafe_b64decode(auth_code.encode()).decode()
            user_id, expiry_str, _ = decoded.split(":", 2)
            expiry = int(expiry_str)
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth code format")
        if expiry < int(datetime.utcnow().timestamp()):
            # Optionally reset user's auth_code here
            user = self.repo.get_user_by_id(user_id)
            if user:
                user.auth_code = None
                self.repo.update_user(user)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Auth code expired")
        user = self.repo.get_user_by_id(user_id)
        if not user or not user.auth_code or user.auth_code != auth_code:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid auth code")
        return user

    def assign_role(self, user_id: str, role_name: str):
        user = self.repo.get_user_by_id(user_id)
        role = self.repo.get_role_by_name(role_name)
        if not user or not role:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User or role not found")
        user.role_id = role.id
        self.repo.update_user(user)
        return user

    def get_user_permissions(self, user_id: str):
        user = self.repo.get_user_by_id(user_id)
        if not user or not user.role:
            return []
        return user.role.permissions.split(",")

    def get_or_create_oauth_user(self, email: str, username: str, first_name: str, last_name: str, provider: str):
        user = self.repo.get_by_email(email=email)
        if user:
            if not user.oauth_provider:
                user.oauth_provider = provider
                self.repo.update_user(user)
            return user
        if self.repo.get_by_username(username):
                # Handle potential username collision from a different account
                username = f"{username}_{secrets.token_hex(4)}"
        return self.repo.add_user_oauth(email=email, username=username, first_name=first_name, last_name=last_name, provider=provider)

    def get_or_create_permission(self, permission_name: str):
        permission = self.repo.get_permission_by_name(permission_name)
        if not permission:
            permission = Permission(name=permission_name)
            permission = self.repo.add_permission(permission)
        return permission
    
    def get_or_create_role(self, role_name: str, permissions: list[str] = None):
        role = self.repo.get_role_by_name(role_name)
        # print(role_name, permissions)
        if not role:
            role = Role(name=role_name)
            for i in permissions:
                permission = self.get_or_create_permission(i)
                role.permissions.append(permission)
            # print(role)
            role = self.repo.add_role(role)
        return role
    
    def format_permissions(self, permissions: list[Permission]) -> list[str]:
        return [permission.name for permission in permissions]

