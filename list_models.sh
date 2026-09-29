#!/bin/bash
# Cargar variables desde el archivo .env local
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | xargs)
else
    echo "❌ Error: No se encontró el archivo .env"
    exit 1
fi

echo "🔍 Consultando modelos disponibles en Groq..."

# Realizar la petición
curl -s -X GET "https://api.groq.com/openai/v1/models" \
  -H "Authorization: Bearer $GROQ_API_KEY" \
  -H "Content-Type: application/json" | jq -r '.data[].id'
