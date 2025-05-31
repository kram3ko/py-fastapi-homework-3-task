from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class Token(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: EmailStr

    @field_validator("email")
    @classmethod
    def email_validator(cls, value) -> str:
        return value.lower()


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def password_validator(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int


class UserActivationRequestSchema(UserBase):
    token: str


class UserLoginRequestSchema(UserBase):
    password: str


class UserLoginResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str


class TokenResponseSchema(Token):
    pass

class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str



