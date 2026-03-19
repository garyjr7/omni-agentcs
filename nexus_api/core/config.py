import os

# --- Configuración de la Base de Datos ---
# Usa la variable de entorno DB_PATH, o un valor por defecto.
DB_PATH = os.getenv("DB_PATH", "nexus_db.sqlite")

# --- Configuración del Modelo de IA ---
# Usa la variable de entorno DEFAULT_MODEL, o un valor por defecto.
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gemini-2.5-flash")

# --- Configuración del Servidor ---
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))

print(f"[Config] Cargando configuración: DB={DB_PATH}, Model={DEFAULT_MODEL}")
