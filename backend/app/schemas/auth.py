from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from app.models.user import UserRole
from app.schemas.user import UserResponse, validate_email_str


class LoginRequest(BaseModel):
    email: str
    password: str
    remember_me: bool = False

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_str(v)


class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=150)
    email: str
    password: str = Field(..., min_length=8)
    role: UserRole = Field(default=UserRole.CITIZEN)
    phone: Optional[str] = None
    preferred_language: str = "en"
    skills: Optional[List[str]] = None
    vehicle_type: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_str(v)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_str(v)


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)
