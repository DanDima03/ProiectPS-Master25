import os
import hmac
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

JWT_SECRET = os.environ.get("JWT_SECRET", "dev")
JWT_ALG = "HS256"
ACCESS_TTL_MIN = 60 * 24

bearer = HTTPBearer()

PBKDF2_ITERS = 200_000

def hash_password(pw: str) -> str:
    pw_bytes = pw.encode("utf-8")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, PBKDF2_ITERS, dklen=32)
    return f"pbkdf2${PBKDF2_ITERS}${salt.hex()}${dk.hex()}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_hex, dk_hex = stored.split("$", 3)
        if algo != "pbkdf2":
            return False
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
    except Exception:
        return False

    pw_bytes = pw.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", pw_bytes, salt, iters, dklen=len(expected))
    return hmac.compare_digest(dk, expected)

def create_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TTL_MIN)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user
