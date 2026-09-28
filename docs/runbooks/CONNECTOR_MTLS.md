# Desktop Connector con mTLS

El backend no debe exponerse directamente a Internet. En Compose queda ligado a `127.0.0.1`; el perfil `connector` publica únicamente el gateway TLS de `docker/connector-mtls.conf`.

El directorio indicado por `NEXUS_CONNECTOR_PKI_DIR` debe contener `server.crt`, `server.key` y `client-ca.crt`. La CA de clientes debe ser distinta de la CA pública del servidor. Defina además un `NEXUS_CONNECTOR_PROXY_SECRET` aleatorio de al menos 32 bytes e inicie con `docker compose --profile connector up -d`. Nginx valida el certificado y reemplaza el fingerprint y secreto enviados al backend; el frontend limpia ambos headers. El backend compara el secreto en tiempo constante antes de confiar en el fingerprint.

Cada instalación recibe token de enrolamiento de un solo uso, credencial propia y certificado individual. Revocación, rotación y heartbeat validan credencial más fingerprint. La CRL/OCSP y emisión de certificados pertenecen al PKI empresarial. Las actualizaciones del binario requieren checksum SHA-256 y firma Ed25519; una firma inválida no modifica el ejecutable y se conserva una versión para rollback.
