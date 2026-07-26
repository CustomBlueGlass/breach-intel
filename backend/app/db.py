"""
Async DB engine + session factory. Every write path in this app uses
explicit transactions (see correlation/matcher.py) so a partial ingestion
batch can never leave breaches half-linked to their source records.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

logger = logging.getLogger("breach_intel.db")

engine = create_async_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    # Cap how long a single connection attempt waits before giving up, so a
    # transient pooler blip fails fast into the retry loop below instead of
    # hanging on asyncpg's 60s default.
    connect_args={"timeout": 30},
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@asynccontextmanager
async def get_session():
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db():
    """FastAPI dependency."""
    async with get_session() as session:
        yield session


# A transient connectivity failure — a Supabase pooler blip, a cold start, a DNS
# hiccup — surfaces at connect time as a raw asyncpg/asyncio TimeoutError, an
# OSError, or a SQLAlchemy Operational/Interface error. A once-a-day scheduled
# job (news_watch, threat_radar) or the 6-hourly ingest should ride these out
# with a short backoff rather than failing the whole run, as news_watch did on
# 2026-07-26 when its very first connection timed out. Data errors
# (IntegrityError, etc.) are deliberately NOT retried — they will not self-heal.
_TRANSIENT_DB_ERRORS = (
    OperationalError,
    InterfaceError,
    ConnectionError,
    TimeoutError,  # builtin; asyncio.TimeoutError is an alias on Python 3.11+
    OSError,
)


async def run_resiliently(coro_factory, *, attempts: int = 4, base_delay: float = 5.0):
    """Await coro_factory() with exponential backoff on transient DB-connectivity
    errors. `coro_factory` must be a zero-arg callable returning a FRESH
    coroutine each call, since a coroutine can only be awaited once (pass the
    async function itself, e.g. run_resiliently(run), not run())."""
    last_exc: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            return await coro_factory()
        except _TRANSIENT_DB_ERRORS as exc:
            last_exc = exc
            if attempt == attempts:
                break
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "DB-touching run failed (attempt %d/%d): %s: %s - retrying in %.0fs",
                attempt, attempts, type(exc).__name__, exc, delay,
            )
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc
