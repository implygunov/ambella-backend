"""
Soyuz backend – FastAPI application.

Routes
------
Auth
  POST /api/auth/login        Login, bind HWID, get JWT
  GET  /api/auth/me           Current user info (JWT required)

Products  (JWT + active subscription required)
  GET  /api/products                        List active products
  GET  /api/products/{product_id}/versions  List versions for a product
  GET  /api/versions/{version_id}/download  Download DLL via presigned URL redirect

Admin  (X-Admin-Key header required)
  POST   /api/admin/products                    Create product
  POST   /api/admin/versions                    Upload new version with DLL
  POST   /api/admin/accounts/{login}/extend     Extend subscription
  DELETE /api/admin/accounts/{login}/reset_hwid Reset HWID
"""

from __future__ import annotations

import os
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from auth import (
    _is_subscription_active,
    create_access_token,
    get_current_account,
    get_current_account_no_sub_check,
    hash_password,
    require_admin,
    verify_password,
)
from config import settings
from database import Account, AsyncSessionLocal, Product, Version, get_db, init_db
from storage import (
    delete_file,
    generate_presigned_url,
    get_local_file_path,
    is_r2_configured,
    upload_file,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lifespan: create tables + seed default product
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await init_db()
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Product).limit(1))
            if result.scalar_one_or_none() is None:
                session.add(
                    Product(
                        name="RustMe",
                        slug="rustme",
                        description="Premium Rust cheat loader",
                        is_active=True,
                    )
                )
                await session.commit()
                logger.info("Seeded default product 'RustMe'.")
    except Exception as exc:
        logger.exception(f"Database initialization warning / error: {exc}")
    yield


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Soyuz Cheat Loader API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global Exception Handler (returns detailed error in JSON instead of blank 500)
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled error during {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "detail": str(exc),
            "type": type(exc).__name__,
            "path": str(request.url.path),
        },
    )


# ---------------------------------------------------------------------------
# Health & Keep-Alive endpoints (UptimeRobot / cron-job.org / Render 24/7)
# ---------------------------------------------------------------------------

@app.get("/api/health", tags=["system"])
@app.get("/ping", tags=["system"])
async def health_check() -> dict:
    """Health check endpoint used by uptime monitors (UptimeRobot, cron-job.org) to keep Render awake 24/7."""
    return {
        "status": "online",
        "service": "Ambella Backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "storage": "Cloudflare R2" if is_r2_configured() else "Database (PostgreSQL BYTEA - 100% Free Persistent)",
    }


@app.get("/api/diag", tags=["system"])
async def diagnostic_check(db: Annotated[AsyncSession, Depends(get_db)]) -> dict:
    """Diagnostic endpoint to inspect DB health, tables, and connection status."""
    from sqlalchemy import text
    try:
        res = await db.execute(text("SELECT 1;"))
        db_ok = bool(res.scalar() == 1)
    except Exception as e:
        return {"status": "error", "database_connected": False, "error": str(e)}

    # Check columns in versions table
    try:
        cols_res = await db.execute(text(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'versions';"
        ))
        versions_cols = [f"{r[0]} ({r[1]})" for r in cols_res.fetchall()]
    except Exception as e:
        versions_cols = [f"Error checking columns: {e}"]

    return {
        "status": "online",
        "database_connected": db_ok,
        "versions_columns": versions_cols,
    }

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    login: str
    password: str
    hwid: str


class LoginResponse(BaseModel):
    token: str
    login: str
    uid: int | None = None
    subscription_expires: str | None
    is_active: bool


class MeResponse(BaseModel):
    login: str
    hwid: str
    is_paid: bool
    subscription_expires: str | None


class ProductOut(BaseModel):
    id: int
    name: str
    slug: str
    description: str

    class Config:
        from_attributes = True


class VersionOut(BaseModel):
    id: int
    version_string: str
    changelog: str
    created_at: str

    class Config:
        from_attributes = True


class CreateProductRequest(BaseModel):
    name: str
    slug: str
    description: str = ""


class ProductCreatedResponse(BaseModel):
    id: int
    name: str
    slug: str
    description: str


class ExtendRequest(BaseModel):
    days: int | None = None  # None = lifetime / no expiry


class MessageResponse(BaseModel):
    message: str


class AdminProductOut(BaseModel):
    id: int
    name: str
    slug: str
    description: str
    is_active: bool
    versions_count: int = 0
    created_at: str

    class Config:
        from_attributes = True


class AdminVersionOut(BaseModel):
    id: int
    product_id: int
    product_name: str = ""
    version_string: str
    changelog: str
    is_active: bool
    storage_type: str
    has_file: bool
    created_at: str

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Helper: format optional datetime as ISO string or None
# ---------------------------------------------------------------------------

def _fmt_dt(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


# ===========================================================================
# Auth routes
# ===========================================================================


@app.post("/api/auth/login", response_model=LoginResponse, tags=["auth"])
async def login(
    body: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """Authenticate with login + password + HWID.

    * If the account has no HWID yet, the provided HWID is bound permanently.
    * If the account already has an HWID that differs from the request, the
      login is rejected with 403.
    * Subscription status is enforced; expired accounts get 403.
    """
    # 1. Find account
    result = await db.execute(select(Account).where(func.lower(Account.login) == func.lower(body.login)))
    account: Account | None = result.scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # 2. Verify password
    if not verify_password(body.password, account.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Auto-migrate legacy SHA-256 hash to bcrypt
    if len(account.password_hash) == 64:
        account.password_hash = hash_password(body.password)
        await db.flush()

    # 3. HWID check / bind
    if not account.hwid:
        account.hwid = body.hwid
        await db.flush()
    elif account.hwid != body.hwid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="HWID mismatch – contact support to reset",
        )

    # 4. Subscription check
    if not _is_subscription_active(account):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Subscription expired or inactive",
        )

    # 5. Issue JWT
    token = create_access_token({"sub": account.login})

    return LoginResponse(
        token=token,
        login=account.login,
        uid=account.id,
        subscription_expires=_fmt_dt(account.subscription_expires),
        is_active=_is_subscription_active(account),
    )


@app.get("/api/auth/me", response_model=MeResponse, tags=["auth"])
async def me(
    account: Annotated[Account, Depends(get_current_account_no_sub_check)],
) -> MeResponse:
    """Return basic info for the authenticated account. Does not enforce
    subscription so users can always see their own status."""
    return MeResponse(
        login=account.login,
        hwid=account.hwid,
        is_paid=account.is_paid,
        subscription_expires=_fmt_dt(account.subscription_expires),
    )


# ===========================================================================
# Product routes  (JWT + active subscription)
# ===========================================================================


@app.get("/api/products", response_model=list[ProductOut], tags=["products"])
async def list_products(
    _account: Annotated[Account, Depends(get_current_account)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[ProductOut]:
    """Return all active products."""
    result = await db.execute(select(Product).where(Product.is_active.is_(True)))
    products = result.scalars().all()
    return [ProductOut(id=p.id, name=p.name, slug=p.slug, description=p.description) for p in products]


@app.get("/api/products/{product_id}/versions", response_model=list[VersionOut], tags=["products"])
async def list_versions(
    product_id: int,
    _account: Annotated[Account, Depends(get_current_account)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[VersionOut]:
    """Return all active versions for a product, newest first."""
    prod_result = await db.execute(
        select(Product).where(Product.id == product_id, Product.is_active.is_(True))
    )
    if prod_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

    result = await db.execute(
        select(Version)
        .where(Version.product_id == product_id, Version.is_active.is_(True))
        .order_by(Version.created_at.desc())
    )
    versions = result.scalars().all()
    return [
        VersionOut(
            id=v.id,
            version_string=v.version_string,
            changelog=v.changelog,
            created_at=_fmt_dt(v.created_at) or "",
        )
        for v in versions
    ]


@app.get("/api/versions/latest/download", tags=["products"])
async def download_latest_version(
    _account: Annotated[Account, Depends(get_current_account)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Serve the latest active client version directly."""
    result = await db.execute(
        select(Version).where(Version.is_active.is_(True)).order_by(Version.created_at.desc()).limit(1)
    )
    version: Version | None = result.scalar_one_or_none()
    
    if version is not None:
        # 1. Pure database storage (Free, persistent forever in PostgreSQL)
        if version.file_data:
            return Response(
                content=version.file_data,
                media_type="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename="payload_{version.version_string}.dll"'}
            )
        
        # 2. Local uploads folder fallback
        if not is_r2_configured():
            local_path = get_local_file_path(version.file_key)
            if os.path.exists(local_path):
                return FileResponse(local_path, media_type="application/octet-stream", filename=f"payload_{version.version_string}.dll")

        # 3. Cloudflare R2 redirect
        if is_r2_configured():
            presigned_url = generate_presigned_url(version.file_key, expires=3600)
            return RedirectResponse(url=presigned_url, status_code=status.HTTP_302_FOUND)

    # 4. Fallback to local built ambella.dll if in repository
    repo_dll = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin", "Release", "x64", "ambella.dll"))
    if not os.path.exists(repo_dll):
        repo_dll = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ambella.dll"))
    if os.path.exists(repo_dll):
        return FileResponse(repo_dll, media_type="application/octet-stream", filename="ambella.dll")

    if version is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active versions found")
    
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found on server")


@app.get("/api/versions/{version_id}/download", tags=["products"])
async def download_version(
    version_id: int,
    _account: Annotated[Account, Depends(get_current_account)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Serve DLL directly from database, local disk, or redirect to Cloudflare R2 presigned URL."""
    result = await db.execute(
        select(Version).where(Version.id == version_id, Version.is_active.is_(True))
    )
    version: Version | None = result.scalar_one_or_none()
    if version is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")

    # 1. Pure database storage (Free, persistent forever in PostgreSQL)
    if version.file_data:
        return Response(
            content=version.file_data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="payload_{version.version_string}.dll"'}
        )

    # 2. Cloudflare R2 redirect
    if is_r2_configured():
        presigned_url = generate_presigned_url(version.file_key, expires=3600)
        return RedirectResponse(url=presigned_url, status_code=status.HTTP_302_FOUND)
    else:
        # 3. Local disk fallback
        local_path = get_local_file_path(version.file_key)
        if os.path.exists(local_path):
            return FileResponse(
                local_path,
                filename=f"payload_{version.version_string}.dll",
                media_type="application/octet-stream",
            )
        # 4. Check repo bin or root
        repo_dll = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bin", "Release", "x64", "ambella.dll"))
        if not os.path.exists(repo_dll):
            repo_dll = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ambella.dll"))
        if os.path.exists(repo_dll):
            return FileResponse(repo_dll, media_type="application/octet-stream", filename="ambella.dll")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found on server")


# ===========================================================================
# Admin routes  (X-Admin-Key header)
# ===========================================================================


@app.post(
    "/api/admin/products",
    response_model=ProductCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["admin"],
)
async def admin_create_product(
    body: CreateProductRequest,
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ProductCreatedResponse:
    """Create a new product."""
    existing = await db.execute(select(Product).where(Product.slug == body.slug))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Product with this slug already exists"
        )

    product = Product(name=body.name, slug=body.slug, description=body.description)
    db.add(product)
    await db.flush()
    await db.refresh(product)

    return ProductCreatedResponse(
        id=product.id, name=product.name, slug=product.slug, description=product.description
    )


@app.post(
    "/api/admin/versions",
    response_model=VersionOut,
    status_code=status.HTTP_201_CREATED,
    tags=["admin"],
)
async def admin_create_version(
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    product_id: int = Form(...),
    version_string: str = Form(...),
    changelog: str = Form(""),
    file: UploadFile = File(...),
) -> VersionOut:
    """Upload a DLL and register a new version.
    - If Cloudflare R2 is configured, uploads to R2 bucket.
    - If R2 is NOT configured, stores binary directly in PostgreSQL (BYTEA column) — 100% Free & Persistent!
    """
    prod_result = await db.execute(select(Product).where(Product.id == product_id))
    if prod_result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

    file_bytes = await file.read()
    content_type = file.content_type or "application/octet-stream"

    if is_r2_configured():
        file_key, public_url = upload_file(file_bytes, file.filename or "ambella.dll", content_type)
        file_data = None
    else:
        # Free Database Storage (PostgreSQL BYTEA) - persists across Render restarts
        file_key = f"db:{file.filename or 'ambella.dll'}"
        public_url = f"/api/versions/{version_string}/download"
        file_data = file_bytes
        try:
            upload_file(file_bytes, file.filename or "ambella.dll", content_type)
        except Exception:
            pass

    version = Version(
        product_id=product_id,
        version_string=version_string,
        changelog=changelog,
        file_key=file_key,
        file_url=public_url,
        file_data=file_data,
        is_active=True,
    )
    db.add(version)
    await db.flush()
    await db.refresh(version)

    return VersionOut(
        id=version.id,
        version_string=version.version_string,
        changelog=version.changelog,
        created_at=_fmt_dt(version.created_at) or "",
    )


@app.post(
    "/api/admin/accounts/{login}/extend",
    response_model=MessageResponse,
    tags=["admin"],
)
async def admin_extend_subscription(
    login: str,
    body: ExtendRequest,
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponse:
    """Extend a user subscription.

    * body.days = None  → lifetime (subscription_expires set to NULL)
    * body.days = N     → extends from now (or existing expiry if in the
                          future) by N days
    """
    result = await db.execute(select(Account).where(Account.login == login))
    account: Account | None = result.scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    account.is_paid = True
    account.payment_date = datetime.now(timezone.utc)

    if body.days is None:
        account.subscription_expires = None
        msg = f"Account '{login}' granted lifetime subscription."
    else:
        # Extend from the later of now or existing expiry
        now = datetime.now(timezone.utc)
        base = now
        if account.subscription_expires is not None:
            exp = account.subscription_expires
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp > now:
                base = exp
        account.subscription_expires = base + timedelta(days=body.days)
        msg = f"Account '{login}' subscription extended by {body.days} days (expires {account.subscription_expires.isoformat()})."

    await db.flush()
    return MessageResponse(message=msg)


@app.delete(
    "/api/admin/accounts/{login}/reset_hwid",
    response_model=MessageResponse,
    tags=["admin"],
)
async def admin_reset_hwid(
    login: str,
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponse:
    """Clear the stored HWID for an account so the next login binds a new one."""
    result = await db.execute(select(Account).where(Account.login == login))
    account: Account | None = result.scalar_one_or_none()
    if account is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    account.hwid = ""
    await db.flush()
    return MessageResponse(message=f"HWID reset for account '{login}'.")


@app.get(
    "/api/admin/products",
    response_model=list[AdminProductOut],
    tags=["admin"],
)
async def admin_list_products(
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[AdminProductOut]:
    """List all products with version count (useful for finding product IDs to delete or update in /docs)."""
    result = await db.execute(select(Product).order_by(Product.id.asc()))
    products = result.scalars().all()
    out = []
    for p in products:
        v_res = await db.execute(select(func.count(Version.id)).where(Version.product_id == p.id))
        v_count = v_res.scalar() or 0
        out.append(AdminProductOut(
            id=p.id,
            name=p.name,
            slug=p.slug,
            description=p.description,
            is_active=p.is_active,
            versions_count=v_count,
            created_at=_fmt_dt(p.created_at) or "",
        ))
    return out


@app.delete(
    "/api/admin/products/{product_id}",
    response_model=MessageResponse,
    tags=["admin"],
)
async def admin_delete_product(
    product_id: int,
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponse:
    """Delete a product and all its versions from the database and storage."""
    result = await db.execute(select(Product).where(Product.id == product_id))
    product = result.scalar_one_or_none()
    if product is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

    # Clean up associated files if in R2 or disk
    v_res = await db.execute(select(Version).where(Version.product_id == product_id))
    for v in v_res.scalars().all():
        if v.file_key and not v.file_key.startswith("db:"):
            try:
                delete_file(v.file_key)
            except Exception:
                pass

    await db.delete(product)
    await db.flush()
    return MessageResponse(message=f"Product '{product.name}' (ID: {product_id}) and all its versions were deleted successfully.")


@app.get(
    "/api/admin/versions",
    response_model=list[AdminVersionOut],
    tags=["admin"],
)
async def admin_list_versions(
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    product_id: int | None = None,
) -> list[AdminVersionOut]:
    """List all registered versions (useful for finding version IDs to delete or manage in /docs)."""
    query = select(Version).order_by(Version.id.desc())
    if product_id is not None:
        query = query.where(Version.product_id == product_id)
    result = await db.execute(query)
    versions = result.scalars().all()
    out = []
    for v in versions:
        prod = await db.execute(select(Product.name).where(Product.id == v.product_id))
        p_name = prod.scalar_one_or_none() or ""
        storage_type = "Database (BYTEA - Free)" if v.file_data is not None else ("Cloudflare R2" if is_r2_configured() else "Local Disk")
        has_file = (v.file_data is not None) or (bool(v.file_key) and not v.file_key.startswith("db:"))
        out.append(AdminVersionOut(
            id=v.id,
            product_id=v.product_id,
            product_name=p_name,
            version_string=v.version_string,
            changelog=v.changelog,
            is_active=v.is_active,
            storage_type=storage_type,
            has_file=has_file,
            created_at=_fmt_dt(v.created_at) or "",
        ))
    return out


@app.delete(
    "/api/admin/versions/{version_id}",
    response_model=MessageResponse,
    tags=["admin"],
)
async def admin_delete_version(
    version_id: int,
    _: Annotated[None, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponse:
    """Delete a specific version and its stored DLL file."""
    result = await db.execute(select(Version).where(Version.id == version_id))
    version = result.scalar_one_or_none()
    if version is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Version not found")

    if version.file_key and not version.file_key.startswith("db:"):
        try:
            delete_file(version.file_key)
        except Exception:
            pass

    await db.delete(version)
    await db.flush()
    return MessageResponse(message=f"Version '{version.version_string}' (ID: {version_id}) was deleted successfully.")

