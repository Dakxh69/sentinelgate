"""Alembic migration environment (spec section 22).

The database URL always comes from app.core.config (env/.env) — never hardcoded.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context

from app.core.config import get_settings
from app.models import Base  # imports every model for autogenerate

config = context.config

if config.config_file_name is not None:
    import logging.config
    logging.config.fileConfig(config.config_file_name)

target_metadata = Base.metadata


def include_object(obj, name, type_, reflected, compare_to):  # type: ignore[no-untyped-def]
    return True


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DB connection).

    Reads the URL from app settings (env/.env), matching the spec (section 22:
    migrations use the app-configured DATABASE_URL).
    """
    url = get_settings().sync_database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_object=include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the live database.

    The URL comes from app settings (never hardcoded). A new engine is created
    for the migration session so the migration runner is independent of any
    app-level engine lifecycle.
    """
    from sqlalchemy import create_engine

    url = get_settings().sync_database_url()
    connectable = create_engine(url, pool_pre_ping=True)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_object=include_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
