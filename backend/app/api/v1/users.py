import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.deps import get_current_user
from app.core.rbac import require_roles
from app.core.security import get_password_hash
from app.db.session import get_db
from app.models.user import ApprovalStatus, User, UserRole
from app.models.volunteer import VolunteerProfile
from app.schemas.common import MessageResponse, PaginatedResponse
from app.schemas.user import UserCreate, UserResponse, UserRoleUpdate, UserUpdate
from app.services.audit import log_audit_event

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/profile", response_model=UserResponse)
async def get_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == current_user.id)
    result = await db.execute(stmt)
    return result.scalar_one()


@router.patch("/profile", response_model=UserResponse)
async def update_profile(
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == current_user.id)
    result = await db.execute(stmt)
    user = result.scalar_one()

    before = {"full_name": user.full_name, "phone": user.phone, "lang": user.preferred_language}

    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.phone is not None:
        user.phone = payload.phone.strip()
    if payload.preferred_language is not None:
        user.preferred_language = payload.preferred_language
    if payload.password is not None and len(payload.password) >= 8:
        user.password_hash = get_password_hash(payload.password)

    await log_audit_event(
        db=db,
        action="user_update_profile",
        entity_type="user",
        entity_id=user.id,
        actor_id=user.id,
        before=before,
        after={"full_name": user.full_name, "phone": user.phone, "lang": user.preferred_language},
    )

    await db.commit()
    await db.refresh(user)
    return user



@router.get("", response_model=PaginatedResponse[UserResponse])
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    q: Optional[str] = None,
    role: Optional[UserRole] = None,
    status: Optional[str] = None,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db)
):
    query = select(User).options(selectinload(User.volunteer_profile))

    if q:
        search = f"%{q.strip()}%"
        query = query.where(or_(User.full_name.ilike(search), User.email.ilike(search)))
    if role:
        query = query.where(User.role == role)
    if status == "active":
        query = query.where(User.is_active == True)
    elif status == "inactive":
        query = query.where(User.is_active == False)
    elif status == "pending":
        query = query.where(User.approval_status == ApprovalStatus.PENDING)

    # Count total
    count_stmt = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_stmt)
    total = total_res.scalar() or 0

    # Paginate
    query = query.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    items_res = await db.execute(query)
    items = items_res.scalars().all()

    total_pages = math.ceil(total / page_size) if total > 0 else 1

    return PaginatedResponse[UserResponse](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def admin_create_user(
    payload: UserCreate,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db)
):
    # Admins can create any role (Admin, Coordinator, Volunteer, Citizen)
    stmt = select(User).where(User.email == payload.email.lower().strip())
    existing = await db.execute(stmt)
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    # New users created directly by admin default to approved
    new_user = User(
        full_name=payload.full_name.strip(),
        email=payload.email.lower().strip(),
        password_hash=get_password_hash(payload.password),
        role=payload.role,
        phone=payload.phone.strip() if payload.phone else None,
        preferred_language=payload.preferred_language or "en",
        department_id=payload.department_id,
        approval_status=ApprovalStatus.APPROVED,
        is_active=True,
    )
    db.add(new_user)
    await db.flush()

    if payload.role == UserRole.VOLUNTEER:
        vol_profile = VolunteerProfile(
            user_id=new_user.id,
            skills=[],
            is_available=True,
        )
        db.add(vol_profile)

    await log_audit_event(
        db=db,
        action="admin_create_user",
        entity_type="user",
        entity_id=new_user.id,
        actor_id=current_user.id,
        after={"email": new_user.email, "role": new_user.role, "created_by": current_user.id},
    )

    await db.commit()
    await db.refresh(new_user)

    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == new_user.id)
    res = await db.execute(stmt)
    return res.scalar_one()


@router.patch("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    old_role = user.role
    user.role = payload.role

    # If promoting to volunteer and profile does not exist, create one
    if payload.role == UserRole.VOLUNTEER and not user.volunteer_profile:
        vol = VolunteerProfile(user_id=user.id, skills=[], is_available=True)
        db.add(vol)

    await log_audit_event(
        db=db,
        action="admin_change_role",
        entity_type="user",
        entity_id=user.id,
        actor_id=current_user.id,
        before={"role": old_role},
        after={"role": user.role},
    )

    await db.commit()
    await db.refresh(user)
    return user


@router.post("/{user_id}/approve", response_model=UserResponse)
async def approve_volunteer(
    user_id: str,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.role != UserRole.VOLUNTEER:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only volunteer accounts can be approved")

    user.approval_status = ApprovalStatus.APPROVED

    from app.services.notifications.service import dispatch_notification
    await dispatch_notification(
        db=db,
        user_id=user.id,
        type="volunteer_approved",
        title="Volunteer Application Approved!",
        body="Your responder credentials have been verified by the administrator. You are now cleared to accept field crisis missions.",
        link="/volunteer",
    )

    await log_audit_event(
        db=db,
        action="admin_approve_volunteer",
        entity_type="user",
        entity_id=user.id,
        actor_id=current_user.id,
        after={"approval_status": ApprovalStatus.APPROVED.value},
    )

    await db.commit()
    await db.refresh(user)
    return user


@router.post("/{user_id}/reject", response_model=UserResponse)
async def reject_volunteer(
    user_id: str,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.approval_status = ApprovalStatus.REJECTED

    from app.services.notifications.service import dispatch_notification
    await dispatch_notification(
        db=db,
        user_id=user.id,
        type="volunteer_rejected",
        title="Volunteer Application Update",
        body="Your volunteer registration could not be approved at this time. Please contact administration for details.",
        link="/volunteer",
    )

    await log_audit_event(
        db=db,
        action="admin_reject_volunteer",
        entity_type="user",
        entity_id=user.id,
        actor_id=current_user.id,
        after={"approval_status": ApprovalStatus.REJECTED.value},
    )

    await db.commit()
    await db.refresh(user)
    return user



@router.post("/{user_id}/toggle-active", response_model=UserResponse)
async def toggle_user_active(
    user_id: str,
    current_user: User = Depends(require_roles(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db)
):
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own account"
        )

    stmt = select(User).options(selectinload(User.volunteer_profile)).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.is_active = not user.is_active

    await log_audit_event(
        db=db,
        action="admin_toggle_active",
        entity_type="user",
        entity_id=user.id,
        actor_id=current_user.id,
        after={"is_active": user.is_active},
    )

    await db.commit()
    await db.refresh(user)
    return user



