from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

def _normalize_db_url(url: str) -> str:
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if "?" in url:
        base, query = url.split("?", 1)
        params = [p for p in query.split("&") if not p.startswith("sslmode=")]
        url = base + ("?" + "&".join(params) if params else "")
    return url


db_url = _normalize_db_url(settings.DATABASE_URL)
engine_kwargs = {"echo": False, "pool_pre_ping": True}
if "localhost" not in db_url and "127.0.0.1" not in db_url:
    import ssl
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    engine_kwargs["connect_args"] = {"ssl": ssl_ctx}

engine = create_async_engine(db_url, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    login: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    hwid: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    is_paid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payment_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    subscription_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Product(Base):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    versions: Mapped[list["Version"]] = relationship(
        "Version", back_populates="product", cascade="all, delete-orphan"
    )


class Version(Base):
    __tablename__ = "versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    product_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("products.id", ondelete="CASCADE"), nullable=False, index=True
    )
    version_string: Mapped[str] = mapped_column(String(64), nullable=False)
    changelog: Mapped[str] = mapped_column(Text, nullable=False, default="")
    file_key: Mapped[str] = mapped_column(String(512), nullable=False)
    file_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    file_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    product: Mapped["Product"] = relationship("Product", back_populates="versions")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


from sqlalchemy import text


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Run non-destructive column additions for PostgreSQL
        migrations = [
            "ALTER TABLE versions ADD COLUMN IF NOT EXISTS file_data BYTEA;",
            "ALTER TABLE versions ADD COLUMN IF NOT EXISTS changelog TEXT DEFAULT '';",
            "ALTER TABLE versions ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;",
            "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS user_id VARCHAR(64);",
            "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS hwid VARCHAR(256) DEFAULT '';",
            "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS is_paid BOOLEAN DEFAULT FALSE;",
            "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS payment_date TIMESTAMPTZ;",
            "ALTER TABLE accounts ADD COLUMN IF NOT EXISTS subscription_expires TIMESTAMPTZ;",
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS description TEXT DEFAULT '';",
            "ALTER TABLE products ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;",
        ]
        for stmt in migrations:
            try:
                await conn.execute(text(stmt))
            except Exception:
                pass
