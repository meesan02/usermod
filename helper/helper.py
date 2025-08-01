from passlib.context import CryptContext
from core import settings
import secrets

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_session_secret() -> str:
    return secrets.token_urlsafe(32)

def get_session_secret() -> str:
    if settings.SESSION_SECRET_KEY:
        secret = settings.SESSION_SECRET_KEY
    else:
        secret = generate_session_secret()
    return secret
