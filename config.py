from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost/soyuz"

    # JWT
    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    # Admin
    ADMIN_KEY: str = "change-admin-key-in-production"

    # CORS
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
    ]

    # Cloudflare R2
    CF_ACCOUNT_ID: str = ""
    CF_ACCESS_KEY_ID: str = ""
    CF_SECRET_ACCESS_KEY: str = ""
    CF_BUCKET_NAME: str = "soyuz-files"
    CF_PUBLIC_URL: str = "https://pub-xxxx.r2.dev"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
