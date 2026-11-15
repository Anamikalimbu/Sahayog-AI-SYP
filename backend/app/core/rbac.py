from typing import Callable, List, Union
from fastapi import Depends, HTTPException, status
from app.models.user import ApprovalStatus, User, UserRole


def require_roles(*allowed_roles: Union[UserRole, str]) -> Callable:
    """
    Returns a dependency callable that checks if current_user's role is in allowed_roles.
    Enforces active state and volunteer approval validation.
    """
    role_values = [r.value if isinstance(r, UserRole) else r for r in allowed_roles]

    async def role_checker(
        current_user: User = Depends(get_current_user)
    ) -> User:
        if not current_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated"
            )

        user_role_str = current_user.role.value if isinstance(current_user.role, UserRole) else str(current_user.role)

        if user_role_str not in role_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required role: {', '.join(role_values)}"
            )

        # If user is a volunteer, verify approval status
        if current_user.role == UserRole.VOLUNTEER and current_user.approval_status != ApprovalStatus.APPROVED:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Volunteer account is pending administrator approval"
            )

        return current_user

    return role_checker


# Forward reference to get_current_user imported in deps
from app.core.deps import get_current_user  # noqa: E402

