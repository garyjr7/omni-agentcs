# Claude y NEXUS MCP

## Opción recomendada ahora: Claude Desktop en Windows

Claude Desktop se instala en la laptop Windows, no en la VM Ubuntu. El proceso
MCP puede ejecutarse en Ubuntu a través de SSH. La VM debe aceptar SSH desde el
host (adaptador NAT con port-forward o, preferiblemente, Host-only/Bridged con
firewall limitado a la IP del host).

Ejemplo para `claude_desktop_config.json` en Windows:

```json
{
  "mcpServers": {
    "nexus": {
      "command": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
      "args": [
        "-T",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-i", "C:\\Users\\TU_USUARIO\\.ssh\\nexus_ed25519",
        "operator@IP_DE_LA_VM",
        "cd /home/operator/NEXUS && NEXUS_MCP_TENANT=bajioware-demo .venv/bin/python -m nexus_mcp.server"
      ]
    }
  }
}
```

Use una llave SSH dedicada, sin contraseña incrustada, y restrinja su acceso en
la VM. Pruebe primero el comando `ssh` desde PowerShell. Reinicie Claude Desktop
después de modificar la configuración.

## Claude web: MCP remoto

Claude web se conecta desde infraestructura de Anthropic. La URL debe ser
pública, HTTPS y accesible sin VPN. NEXUS exige OIDC y validación de audiencia;
el servicio MCP no publica puertos directamente y solo el gateway TLS es visible.

Requisitos previos:

1. Dominio, por ejemplo `mcp.example.com`.
2. Certificado TLS válido en un directorio con `tls.crt` y `tls.key`.
3. Proveedor OAuth/OIDC con PKCE, discovery, JWKS y tokens con `tenant_id`.
4. Audience exclusiva para NEXUS MCP y scopes `nexus:read`/`nexus:write`.
5. Port-forward del router o un túnel HTTPS autenticado hacia el gateway.

Variables mínimas:

```dotenv
NEXUS_ENV=production
NEXUS_MCP_PUBLIC_URL=https://mcp.example.com/mcp
NEXUS_MCP_SERVER_NAME=mcp.example.com
NEXUS_MCP_TLS_DIR=/ruta/absoluta/tls
OIDC_ISSUER=https://identity.example.com
OIDC_AUDIENCE=https://mcp.example.com/mcp
NEXUS_MCP_ENABLE_WRITE_TOOLS=false
```

Arranque:

```bash
docker compose --profile mcp-remote config
docker compose --profile mcp-remote up -d mcp-remote mcp-gateway
```

No habilite herramientas de escritura hasta completar pruebas de autorización,
auditoría, revocación, límites y aprobación humana. Nunca use
`NEXUS_MCP_TRUST_LOCAL_CONTAINER=true` en producción.
