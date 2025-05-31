from pydantic import EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel
from schemas.accounts import UserRegistrationRequestSchema
from security.passwords import hash_password


class UserService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_user(self, user: UserRegistrationRequestSchema):
        try:
            result = await self.db.execute(
                select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
            )
            group = result.scalar_one()
            hashed = hash_password(user.password)
            db_user = UserModel(email=str(user.email), _hashed_password=hashed, group_id=group.id)
            self.db.add(db_user)
            await self.db.commit()
            await self.db.refresh(db_user)

            # Create an activation token
            activation_token = ActivationTokenModel(user_id=db_user.id)
            self.db.add(activation_token)
            await self.db.commit()

            return db_user
        except Exception:
            await self.db.rollback()
            raise

    async def get_user_by_email(self, email: EmailStr):
        result = await self.db.execute(select(UserModel).where(UserModel.email == email))
        return result.scalar_one_or_none()
