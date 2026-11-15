from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.deps import get_current_user
from app.core.security import (
    create_access_token, create_refresh_token, decode_token,
    get_password_hash, verify_password
)
from app.db.session import get_db
from app.models.user import ApprovalStatus, User, UserRole
from app.models.volunteer import VolunteerProfile
from app.schemas.auth import (
    ForgotPasswordRequest, LoginRequest, RefreshTokenRequest,
    RegisterRequest, ResetPasswordRequest, TokenResponse
)
from app.schemas.common import MessageResponse
from app.schemas.user import UserResponse
from app.services.audit import log_audit_event

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    # Enforce role restriction: only citizen and volunteer can self-register
    if payload.role not in [UserRole.CITIZEN, UserRole.VOLUNTEER]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Self-registration is permitted only for Citizen and Volunteer roles. Coordinators and Admins must be provisioned by an administrator."
        )

    # Check for existing email
    stmt = select(User).where(User.email == payload.email.lower().strip())
    existing = await db.execute(stmt)
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    # Determine approval status: Volunteers start as PENDING, citizens start as APPROVED
    approval_status = (
        ApprovalStatus.PENDING
        if payload.role == UserRole.VOLUNTEER
        else ApprovalStatus.APPROVED
    )

    new_user = User(
        full_name=payload.full_name.strip(),
        email=payload.email.lower().strip(),
        password_hash=get_password_hash(payload.password),
        role=payload.role,
        phone=payload.phone.strip() if payload.phone else None,
        preferred_language=payload.preferred_language or "en",
        approval_status=approval_status,
        is_active=True,
    )
    db.add(new_user)
    await db.flush()

    # If volunteer, create volunteer profile record
    if payload.role == UserRole.VOLUNTEER:
        vol_profile = VolunteerProfile(
            user_id=new_user.id,
            skills=payload.skills or [],
            vehicle_type=payload.vehicle_type,
            latitude=payload.latitude,
            longitude=payload.longitude,
            is_available=True,
        )
        db.add(vol_profile)

    await log_audit_event(
        db=db,
        action="user_register",
        entity_type="user",
        entity_id=new_user.id,
        actor_id=new_user.id,
        after={"email": new_user.email, "role": new_user.role, "status": approval_status},
        ip=request.client.host if request.client else None,
    )

    await db.commit()
    await db.refresh(new_user)

    # Re-fetch user with relationships
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == new_user.id)
    result = await db.execute(stmt)
    user_loaded = result.scalar_one()

    return user_loaded


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.email == payload.email.lower().strip())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    client_ip = request.client.host if request.client else None

    if not user or not verify_password(payload.password, user.password_hash):
        await log_audit_event(
            db=db,
            action="login_failure",
            entity_type="user",
            entity_id=payload.email,
            after={"reason": "invalid_credentials"},
            ip=client_ip,
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Please contact an administrator."
        )

    # Update last login time
    user.last_login_at = datetime.now(timezone.utc)

    # Token payload
    token_data = {
        "sub": user.id,
        "email": user.email,
        "role": user.role.value if isinstance(user.role, UserRole) else user.role,
        "approval_status": user.approval_status.value if isinstance(user.approval_status, ApprovalStatus) else user.approval_status,
    }

    expires_delta = timedelta(days=30) if payload.remember_me else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(token_data, expires_delta=expires_delta)
    refresh_token = create_refresh_token(token_data)

    # Set httpOnly cookies for access and refresh tokens
    cookie_max_age = int(timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="lax",
        max_age=cookie_max_age,
        path="/",
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="lax",
        max_age=cookie_max_age,
        path="/",
    )

    await log_audit_event(
        db=db,
        action="login_success",
        entity_type="user",
        entity_id=user.id,
        actor_id=user.id,
        ip=client_ip,
    )
    await db.commit()

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=int(expires_delta.total_seconds()),
        user=user,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    payload: Optional[RefreshTokenRequest] = None,
    refresh_token_cookie: Optional[str] = Cookie(None, alias="refresh_token"),
    response: Response = None,
    db: AsyncSession = Depends(get_db)
):
    token = (payload.refresh_token if payload and payload.refresh_token else None) or refresh_token_cookie
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )

    data = decode_token(token)
    if not data or data.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    user_id = data.get("sub")
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )

    token_data = {
        "sub": user.id,
        "email": user.email,
        "role": user.role.value if isinstance(user.role, UserRole) else user.role,
        "approval_status": user.approval_status.value if isinstance(user.approval_status, ApprovalStatus) else user.approval_status,
    }
    new_access_token = create_access_token(token_data)

    if response:
        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=settings.ENVIRONMENT == "production",
            samesite="lax",
            path="/",
        )

    return TokenResponse(
        access_token=new_access_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=user,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(response: Response):
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")
    return MessageResponse(message="Successfully logged out")


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == current_user.id)
    result = await db.execute(stmt)
    user = result.scalar_one()
    return user


@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    payload: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == payload.email.lower().strip())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user:
        reset_token = create_access_token(
            {"sub": user.id, "email": user.email, "type": "reset_password"},
            expires_delta=timedelta(hours=1),
        )
        # Log to development console behind mail sender interface
        print(f"\n[DEV MAIL SENDER] Password reset requested for {user.email}")
        print(f"[DEV MAIL SENDER] Reset Token: {reset_token}")
        print(f"[DEV MAIL SENDER] Link: {settings.FRONTEND_URL}/reset-password?token={reset_token}\n")

    # Consistent message to prevent email enumeration
    return MessageResponse(
        message="If an account with that email exists, password reset instructions have been dispatched."
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    data = decode_token(payload.token)
    if not data or data.get("type") != "reset_password":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )

    user_id = data.get("sub")
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.password_hash = get_password_hash(payload.new_password)
    await log_audit_event(
        db=db,
        action="password_reset",
        entity_type="user",
        entity_id=user.id,
        actor_id=user.id,
    )
    await db.commit()

    return MessageResponse(message="Password has been successfully updated. You may now log in.")

