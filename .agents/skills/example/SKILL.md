---
name: port-sweep-baseline
description: Procedimiento base para un barrido de puertos y servicios (solo lectura).
---

# Barrido de puertos y servicios (solo lectura)

Usa esta skill como guía cuando el objetivo incluya un CIDR o una lista de hosts
y aún no haya servicios confirmados.

1. Confirma que cada host está dentro del scope firmado del engagement; si no,
   no lo toques.
2. Para cada host, ejecuta `nexus.recon.nmap` con descubrimiento de puertos y
   detección de servicio/versión. No uses modos intrusivos en esta fase.
3. Anota en el blackboard cada servicio abierto como endpoint, con host, puerto
   y producto/versión.
4. Si encuentras un servicio web, pasa a la fase de enumeración web con
   `nexus.recon.httpx` y `nexus.recon.whatweb`.
5. No lances credenciales ni explotación desde este procedimiento: es solo
   reconocimiento.
