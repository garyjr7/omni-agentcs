# ADR-001: Kernel independiente y gateways

Estado: aceptado (2026-08-04)

NEXUS será un control plane empresarial de agentes, no una interfaz conversacional. Los contratos, identidad, políticas, tareas, auditoría y ejecución pertenecen al Kernel. REST, MCP, CLI y A2A son gateways sin lógica de negocio propia.

Los proveedores de modelos son adaptadores intercambiables. `fake` es el proveedor obligatorio de desarrollo y CI; OpenAI-compatible, Groq, Ollama y futuros proveedores no deben alterar agentes ni workflows.

Consecuencia: ChatGPT puede ser una interfaz excelente para NEXUS mediante MCP, pero desconectarlo no impide operar por REST o CLI.
