from pydantic_settings import BaseSettings
from pydantic import PostgresDsn, validator, Field
from typing import Optional, Dict, Any


class UserSettings(BaseSettings):

    # ===== SSO Configuration =====
    GOOGLE_CLIENT_ID: str = Field(..., env="GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET: str = Field(..., env="GOOGLE_CLIENT_SECRET")
    GITHUB_CLIENT_ID: str = Field(..., env="GITHUB_CLIENT_ID")
    GITHUB_CLIENT_SECRET: str = Field(..., env="GITHUB_CLIENT_SECRET")


    # ===== Security Configuration =====
    SESSION_SECRET_KEY: str = Field(..., env="SESSION_SECRET_KEY")
    # ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(60 * 24 * 8, env="ACCESS_TOKEN_EXPIRE_MINUTES")  # 8 days
    # JWT_ALGORITHM: str = Field("HS256", env="JWT_ALGORITHM")

    API_V1_STR: str = Field("/api/v1", env="API_V1_STR")


    # ===== Database Configuration =====
    USER_DB_ENGINE: str = Field("mysql", env="USER_DB_ENGINE")
    USER_DB_HOST: str = Field("localhost", env="USER_DB_HOST")
    USER_DB_PORT: str = Field("3306", env="USER_DB_PORT")
    USER_DB_USER: str = Field(..., env="USER_DB_USER")
    USER_DB_PASSWORD: str = Field(..., env="USER_DB_PASSWORD")
    USER_DB_NAME: str = Field(..., env="USER_DB_NAME")
    SQLALCHEMY_DATABASE_URI: Optional[str] = None
    
    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        if values.get("USER_DB_ENGINE") == "mysql":
            return f"mysql+pymysql://{values['USER_DB_USER']}:{values['USER_DB_PASSWORD']}@{values['USER_DB_HOST']}:{values['USER_DB_PORT']}/{values['USER_DB_NAME']}"
        return PostgresDsn.build(
            scheme=values.get("USER_DB_ENGINE"),
            user=values.get("USER_DB_USER"),
            password=values.get("USER_DB_PASSWORD"),
            host=values.get("USER_DB_HOST"),
            port=values.get("USER_DB_PORT"),
            path=f"/{values.get('USER_DB_NAME') or ''}",
        )

    # ===== Logging Configuration =====
    LOG_LEVEL: str = Field("INFO", env="LOG_LEVEL")  # DEBUG|INFO|WARNING|ERROR|CRITICAL



    class Config:
        extra = "allow"
        case_sensitive = True
        env_file = ".env"
        env_file_encoding = 'utf-8'

settings = UserSettings()