from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import Account, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def verify_password(plain: str, hashed: str) -> bool:
    """Return True if the plain-text password matches the stored bcrypt hash."""
    return pwd_context.verify(plain, hashed)


def hash_password(password: str) -> str:
    """Return a bcrypt hash of the given password."""
    return pwd_context.hash(password)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(data: dict) -> str:
    """Create a signed JWT containing *data*. Never set an expiry – the token
    is valid for ACCESS_TOKEN_EXPIRE_MINUTES minutes from issuance."""
    from datetime import timedelta

    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_token(token: str) -> str:
    """Decode *token* and return the login claim, or raise 401."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        login: str | None = payload.get("sub")
        if login is None:
            raise credentials_exception
        return login
    except JWTError:
        raise credentials_exception


# ---------------------------------------------------------------------------
# Subscription check
# ---------------------------------------------------------------------------

def _is_subscription_active(account: Account) -> bool:
    """Return True when the account has an active paid subscription."""
    if not account.is_paid:
        return False
    if account.subscription_expires is None:
        # Lifetime / no-expiry subscription
        return True
    now = datetime.now(timezone.utc)
    expires = account.subscription_expires
    if expires.tzinfo is None:
        # Make naive datetime timezone-aware for comparison
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > now


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_account(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Account:
    """Resolve the Bearer token to an Account, enforcing HWID binding and
    an active subscription.  Raises 401/403 on any failure."""
    login = verify_token(token)

    result = await db.execute(select(Account).where(Account.login == login))
    account: Account | None = result.scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account not found")

    if not _is_subscription_active(account):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Subscription expired or inactive",
        )

    return account


async def get_current_account_no_sub_check(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Account:
    """Like get_current_account but does NOT enforce subscription status.
    Used for /api/auth/me so users can always query their own info."""
    login = verify_token(token)

    result = await db.execute(select(Account).where(Account.login == login))
    account: Account | None = result.scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account not found")

    return account


# ---------------------------------------------------------------------------
# Admin dependency
# ---------------------------------------------------------------------------

async def require_admin(x_admin_key: Annotated[str | None, Header()] = None) -> None:
    """Validate the X-Admin-Key header against ADMIN_KEY env var."""
    if x_admin_key != settings.ADMIN_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid admin key")
