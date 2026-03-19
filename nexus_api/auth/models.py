from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: str = "viewer"   # admin | operator | viewer

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str
    active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut

class TokenPayload(BaseModel):
    sub: str          # user id
    email: str
    role: str
    exp: int
    iat: int
    jti: Optional[str] = None   # para blacklist futura
