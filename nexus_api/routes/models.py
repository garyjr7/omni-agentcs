"""
NEXUS PRO — Models & API Keys
Agrega API keys → detecta modelos disponibles automáticamente
"""
import uuid
import httpx
import asyncio
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
from nexus_api.db.database import db_list_keys, db_create_key, db_update_key, db_delete_key

router = APIRouter()

# Modelos conocidos por provider
PROVIDER_MODELS = {
    "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo", "o1-preview", "o1-mini"],
    "anthropic": ["claude-opus-4-5", "claude-sonnet-4-5", "claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"],
    "google": ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash", "gemini-pro"],
    "groq": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768", "gemma2-9b-it"],
    "together": ["meta-llama/Llama-3-70b-chat-hf", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
    "ollama": ["llama3", "mistral", "codellama", "phi3", "gemma2"],
}

async def _detect_models_real(key_id: str, provider: str, api_key: str):
    """Detecta modelos reales haciendo una llamada de prueba al proveedor."""
    models = PROVIDER_MODELS.get(provider.lower(), [])
    status = "ok"

    try:
        if provider.lower() == "openai":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"})
                if r.status_code == 200:
                    data = r.json()
                    gpt_models = sorted([m['id'] for m in data.get('data', []) if 'gpt' in m['id'] or 'o1' in m['id']])
                    models = gpt_models[:15] if gpt_models else models
                else:
                    status = "invalid_key"

        elif provider.lower() == "anthropic":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.anthropic.com/v1/models",
                    headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"})
                if r.status_code == 200:
                    data = r.json()
                    models = [m['id'] for m in data.get('data', [])]
                else:
                    status = "invalid_key"

        elif provider.lower() == "groq":
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get("https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {api_key}"})
                if r.status_code == 200:
                    data = r.json()
                    models = [m['id'] for m in data.get('data', [])]
                else:
                    status = "invalid_key"

        elif provider.lower() == "ollama":
            async with httpx.AsyncClient(timeout=5) as client:
                base = api_key if api_key.startswith("http") else "http://localhost:11434"
                r = await client.get(f"{base}/api/tags")
                if r.status_code == 200:
                    data = r.json()
                    models = [m['name'] for m in data.get('models', [])]
                else:
                    status = "unreachable"

    except Exception as e:
        status = "ok"  # usar modelos conocidos si falla la detección

    db_update_key(key_id, models=models, status=status)


class AddKeyRequest(BaseModel):
    alias: str
    provider: str   # openai | anthropic | google | groq | together | ollama
    api_key: str

@router.get("/models/keys")
def list_keys():
    """Lista todas las API keys configuradas (con key enmascarada)."""
    keys = db_list_keys()
    # Nunca exponer la key real
    for k in keys:
        k.pop('key_value', None)
    return keys

@router.get("/models/available")
def available_models():
    """Retorna todos los modelos disponibles según las keys configuradas."""
    keys = db_list_keys()
    all_models = []
    for k in keys:
        if k['status'] == 'ok':
            for m in k.get('models', []):
                all_models.append({
                    "model": m,
                    "provider": k['provider'],
                    "key_alias": k['alias'],
                    "key_id": k['id'],
                })
    return {"models": all_models, "total": len(all_models)}

@router.post("/models/keys", status_code=201)
async def add_key(body: AddKeyRequest, background: BackgroundTasks):
    """Agrega una API key y detecta modelos disponibles en background."""
    key_id = f"key_{uuid.uuid4().hex[:8]}"

    # Enmascarar la key para mostrar
    k = body.api_key
    if len(k) > 12:
        masked = k[:8] + "••••••••" + k[-4:]
    else:
        masked = "••••••••••••"

    data = {
        "id": key_id,
        "alias": body.alias,
        "provider": body.provider.lower(),
        "key_masked": masked,
        "key_value": body.api_key,
        "models": PROVIDER_MODELS.get(body.provider.lower(), []),
        "status": "detecting",
    }
    db_create_key(data)

    # Detectar modelos reales en background
    background.add_task(_detect_models_real, key_id, body.provider, body.api_key)

    data.pop('key_value')
    return {"id": key_id, "message": f"API key de {body.provider} agregada — detectando modelos...", **data}

@router.post("/models/keys/{key_id}/detect")
async def redetect_models(key_id: str, background: BackgroundTasks):
    """Re-detecta modelos para una key existente."""
    keys = db_list_keys()
    key = next((k for k in keys if k['id'] == key_id), None)
    if not key:
        raise HTTPException(404, "API key no encontrada")

    # Necesitamos la key real de la DB
    import sqlite3
    from pathlib import Path
    conn = sqlite3.connect("/home/operator/NEXUS-PRO/data/nexus_pro.db")
    row = conn.execute("SELECT key_value FROM api_keys WHERE id=?", (key_id,)).fetchone()
    conn.close()
    if row:
        background.add_task(_detect_models_real, key_id, key['provider'], row[0])

    return {"message": "Detección iniciada", "key_id": key_id}

@router.delete("/models/keys/{key_id}")
def delete_key(key_id: str):
    db_delete_key(key_id)
    return {"deleted": key_id}

@router.get("/models/catalog")
def model_catalog():
    """Catálogo completo de modelos conocidos por provider."""
    return PROVIDER_MODELS
