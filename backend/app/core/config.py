from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    SECRET_KEY: str = "sahayog_ai_super_secret_jwt_key_change_in_production_min32chars!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    DATABASE_URL: str = "sqlite+aiosqlite:///./sahayog.db"
    FRONTEND_URL: str = "http://localhost:3000"

    AI_MODE: str = "demo"
    LLM_PROVIDER: str = "mock"
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gpt-4o-mini"
    AI_CONFIDENCE_THRESHOLD: float = 0.60

    VAPID_PUBLIC_KEY: str = "BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5NMPH84"
    VAPID_PRIVATE_KEY: str = "UUx12A6_03b_BvjY9YxW3pT7bM81-0-u6oF1eB2vW18"
    VAPID_CLAIM_EMAIL: str = "mailto:support@sahayog.test"

    SMS_GATEWAY_PROVIDER: str = "stub"
    SMS_GATEWAY_API_KEY: Optional[str] = None

    RUN_SEED_ON_STARTUP: bool = True
    UPLOAD_DIR: str = "uploads"
    MAX_IMAGE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB
    MAX_VIDEO_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

