from datetime import datetime, timezone, timedelta
from email.policy import default
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.user_crud import UserService
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema
)
from schemas.accounts import (
    UserLoginRequestSchema,
    Token,
    UserActivationRequestSchema,
    TokenResponseSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, TokenRefreshResponseSchema,
    TokenRefreshRequestSchema, UserLoginResponseSchema
)
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)
    db_user = await user_service.get_user_by_email(user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )
    try:
        created_user = await user_service.create_user(user)
        return UserRegistrationResponseSchema.model_validate(created_user)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate_account(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)

    user = await user_service.get_user_by_email(data.email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == user.id)
        .where(ActivationTokenModel.token == data.token)
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    current_time = datetime.now(timezone.utc)
    if token.expires_at.tzinfo is None:
        token.expires_at = token.expires_at.replace(tzinfo=timezone.utc)

    if token.expires_at < current_time:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


# src/routes/accounts.py
@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)
    user = await user_service.get_user_by_email(data.email)

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        token = PasswordResetTokenModel(user_id=user.id)
        db.add(token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def reset_password(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    """
    Endpoint for resetting a user's password.
    """
    user_service = UserService(db)
    user = await user_service.get_user_by_email(data.email)

    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
        .where(PasswordResetTokenModel.token == data.token)
    )
    token = token.scalar_one_or_none()

    if not token:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    current_time = datetime.now(timezone.utc)
    if token.expires_at.tzinfo is None:
        token.expires_at = token.expires_at.replace(tzinfo=timezone.utc)

    if token.expires_at < current_time:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        # Hash the password before saving
        hashed_password = hash_password(data.password)
        user._hashed_password = hashed_password
        await db.delete(token)
        await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=TokenResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
):
    """
    Login user and return access and refresh tokens.
    """

    user_service = UserService(db)
    user = await user_service.get_user_by_email(data.email)

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(token)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def get_refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    """
     Returns:
        TokenRefreshResponseSchema: A new access token.

    Raises:
        HTTPException:
            - 400 Bad Request if the token is invalid or expired.
            - 401 Unauthorized if the refresh token is not found.
            - 404 Not Found if the user associated with the token does not exist.
    """
    try:
        decoded_token = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = decoded_token.get("user_id")

    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error))

    token_result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    db_token = token_result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema.model_validate({"access_token": access_token})
