"""
Gestión de base de datos SQLite para usuarios (async).
"""
import databases
import sqlalchemy
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "nexus_users.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()

users_table = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id",       sqlalchemy.Integer, primary_key=True, autoincrement=True),
    sqlalchemy.Column("username", sqlalchemy.String(64), unique=True, nullable=False),
    sqlalchemy.Column("email",    sqlalchemy.String(128), unique=True, nullable=False),
    sqlalchemy.Column("hashed_password", sqlalchemy.String(256), nullable=False),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean, default=True),
    sqlalchemy.Column("role",     sqlalchemy.String(32), default="user"),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, default=sqlalchemy.func.now()),
)

engine = sqlalchemy.create_engine(DATABASE_URL.replace("+aiosqlite", ""))

def init_db():
    """Crea las tablas si no existen."""
    metadata.create_all(engine)
