from datetime import datetime
from typing import List, Optional
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator
from app.models.user import ApprovalStatus, UserRole

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


def validate_email_str(v: str) -> str:
    v = v.strip().lower()
    if not EMAIL_REGEX.match(v):
        raise ValueError("Invalid email address format")
    return v


class VolunteerProfileBase(BaseModel):
    skills: List[str] = Field(default_factory=list)
    vehicle_type: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_available: bool = True
    capacity_notes: Optional[str] = None


class VolunteerProfileCreate(VolunteerProfileBase):
    pass


class VolunteerProfileResponse(VolunteerProfileBase):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    created_at: datetime
    updated_at: datetime


class UserBase(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=150)
    email: str
    phone: Optional[str] = None
    preferred_language: str = "en"

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_email_str(v)


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.CITIZEN
    department_id: Optional[str] = None


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=150)
    phone: Optional[str] = None
    preferred_language: Optional[str] = None
    is_active: Optional[bool] = None
    department_id: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)


class UserRoleUpdate(BaseModel):
    role: UserRole


class UserResponse(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    role: UserRole
    is_active: bool
    approval_status: ApprovalStatus
    department_id: Optional[str] = None
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    volunteer_profile: Optional[VolunteerProfileResponse] = None
