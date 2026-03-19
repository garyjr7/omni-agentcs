# NEXUS Core Alpha — BajioWare AI Orchestration Engine

![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)

NEXUS es un motor de orquestación de agentes de IA ligero, asíncrono y extensible. Su propósito es simplificar la creación, gestión y comunicación de múltiples agentes inteligentes que colaboran para resolver tareas complejas.

**¿Qué problema resuelve?** A medida que los sistemas de IA crecen, la lógica para enrutar tareas, gestionar el estado, manejar la concurrencia y asegurar la comunicación entre agentes se vuelve un caos. NEXUS proporciona una infraestructura centralizada y desacoplada que maneja estos problemas, permitiendo a los desarrolladores centrarse en la lógica de negocio de sus agentes.

---

## 🚀 Quick Start

En 3 comandos, tendrás NEXUS funcionando localmente.

```bash
# 1. Clona el repositorio
git clone https://github.com/your-repo/nexus_core.git
cd nexus_core

# 2. Ejecuta el script de instalación
# (Crea venv, instala dependencias, prepara .env)
bash setup_nexus.sh

# 3. Inicia el motor de orquestación
bash run_nexus.sh
```

---

## 🏛️ Arquitectura

NEXUS utiliza una arquitectura de bus de eventos para desacoplar sus componentes principales. Esto permite una alta cohesión y un bajo acoplamiento, facilitando la extensibilidad y el mantenimiento.

```ascii
+-----------------------------------------------------------------+
|                        User / API Request                       |
+-----------------------------------------------------------------+
                           |
                           v
+-----------------------------------------------------------------+
|                      Security Middleware                        |
| (Input Validation, Rate Limiting, Audit)                        |
+-----------------------------------------------------------------+
                           |
                           v
+-----------------------------------------------------------------+
|                      Orchestrator (Core)                        |
| (Task Reception, Prioritization, Dispatching)                   |
+-----------------------------------------------------------------+
      ^                    |                    ^
      | (Subscribe)        | (Publish Events)   | (Query Agents)
      |                    v                    |
+-----------------------------------------------------------------+
|                       Event Bus (Async)                         |
| (task.received, task.completed, agent.registered)               |
+-----------------------------------------------------------------+
      |                    ^                    |
      | (Agent Events)     | (Task Events)      | (State Changes)
      v                    |                    v
+----------------------+   |   +---------------------------------+
|    Agent Registry    |   |   |          State Manager          |
| (Agent Discovery,    |<--+-->| (Persistence, Checkpoints,      |
|  Capability Mapping) |       |  Task Status Tracking)          |
+----------------------+       +---------------------------------+
      |
      | (Assign Task)
      v
+-----------------------------------------------------------------+
|                          LLM Layer                              |
| (Abstraction for OpenAI, Gemini, Ollama)                        |
+-----------------------------------------------------------------+
```

### Módulos Principales

*   **Orchestrator**: El cerebro del sistema. Recibe nuevas tareas, las prioriza según las reglas de negocio y las despacha a los agentes adecuados a través del `EventBus`. No conoce a los agentes directamente, solo sabe qué capacidades se necesitan.
*   **EventBus**: El sistema nervioso central. Es un bus de mensajes asíncrono que permite la comunicación desacoplada entre componentes. El Orquestador publica eventos como `task.dispatched`, y otros módulos (como el `StateManager` o los `Agents`) se suscriben a ellos.
*   **AgentRegistry**: El directorio de agentes. Mantiene un registro de todos los agentes disponibles, sus metadatos y sus capacidades (ej. `DATA_ANALYSIS`, `CODE_EXECUTION`). El Orquestador lo consulta para encontrar un agente compatible con una tarea.
*   **StateManager**: La memoria persistente. Guarda y carga el estado del sistema (tareas, resultados, checkpoints) en un archivo JSON (o futuro backend como Redis). Garantiza que el sistema pueda reanudar su trabajo después de un reinicio.
*   **LLM Layer**: Una capa de abstracción que unifica la comunicación con diferentes modelos de lenguaje (OpenAI, Gemini, Ollama). Los agentes interactúan con esta capa en lugar de hacerlo directamente con las APIs de los LLM.
*   **SecurityMiddleware**: Una capa de protección que intercepta las entradas al sistema. Valida rutas de archivos, URLs y contenido para prevenir ataques comunes como Path Traversal o la ejecución de código malicioso.

---

## 🤖 Cómo Crear tu Primer Agente

Crear un agente es trivial. Solo necesitas heredar de la clase `Agent` base y definir sus metadatos y su lógica de ejecución.

```python
# agents/my_first_agent.py
from nexus_core.agents.base import Agent, AgentMetadata, Capability
from nexus_core.models.task import Task

class MyFirstAgent(Agent):
    """Un agente simple que saluda."""

    def __init__(self):
        super().__init__(
            metadata=AgentMetadata(
                agent_id="greeter-001",
                name="GreeterAgent",
                version="1.0",
                description="Un agente que saluda al mundo.",
                capabilities=[Capability.TEXT_GENERATION] # Define su capacidad
            )
        )

    async def execute_task(self, task: Task) -> dict:
        """La lógica principal del agente."""
        name = task.payload.get("name", "Mundo")
        return {"status": "completed", "result": f"Hola, {name}!"}

# ¡Eso es todo! El AgentRegistry lo descubrirá automáticamente.
```

---

## ⚙️ Variables de Entorno

Copia `.env.example` a `.env` y configura las siguientes variables:

| Variable              | Descripción                                                 | Requerido/Opcional |
| --------------------- | ----------------------------------------------------------- | ------------------ |
| `OPENAI_API_KEY`      | Tu clave de API para OpenAI.                                | Opcional           |
| `OPENAI_MODEL`        | Modelo de OpenAI a utilizar (ej. `gpt-4o`).                 | Opcional           |
| `GEMINI_API_KEY`      | Tu clave de API para Google Gemini.                         | Opcional           |
| `GEMINI_MODEL`        | Modelo de Gemini a utilizar (ej. `gemini-1.5-pro`).         | Opcional           |
| `OLLAMA_BASE_URL`     | URL de tu instancia local de Ollama.                        | Opcional           |
| `OLLAMA_MODEL`        | Modelo local de Ollama a utilizar (ej. `llama3`).           | Opcional           |
| `NEXUS_DEBUG`         | Activa el modo debug (`1` o `0`).                           | Opcional           |
| `NEXUS_STATE_FILE`    | Ruta del archivo para guardar el estado.                    | Requerido          |
| `NEXUS_MAX_CONCURRENT`| Número máximo de tareas concurrentes.                       | Requerido          |
| `NEXUS_LOG_LEVEL`     | Nivel de logs (`INFO`, `DEBUG`, etc.).                      | Requerido          |

---

## 🛠️ Comandos Útiles

Usamos `make` para simplificar las tareas comunes de desarrollo.

*   **`make test`**: Ejecuta toda la suite de pruebas (unitarias y de integración) y muestra un reporte de cobertura de código.
*   **`make lint`**: Revisa la sintaxis de los archivos Python principales para detectar errores antes de la ejecución.
*   **`make clean`**: Elimina archivos temporales como `__pycache__`, `.pytest_cache` y logs.

---

## 🗺️ Roadmap

*   [✅] **v1.0 (Alpha)**: Núcleo funcional con Orchestrator, EventBus, StateManager (JSON), y registro de agentes.
*   [ ] **v1.1**: Implementación de un backend de estado en Redis para mejorar la escalabilidad y resiliencia.
*   [ ] **v2.0**: Soporte para agentes distribuidos que se ejecutan en diferentes máquinas o contenedores.

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.
