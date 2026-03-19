"""
Utilidades JWT y hashing de contraseñas.
"""
import os
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
SECRET_KEY = os.getenv("SECRET_KEY")
from passlib.context import CryptContext

SECRET_KEY  = os.getenv("JWT_SECRET_KEY", "nexus-super-secret-change-in-prod-2026")
ALGORITHM   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
