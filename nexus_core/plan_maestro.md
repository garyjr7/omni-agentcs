# NEXUS: Plan Maestro de Arquitectura

## ¿Qué es NEXUS?

NEXUS es el motor propietario de orquestación de agentes de IA de BajioWare. Ha sido diseñado desde cero para reemplazar y superar las limitaciones de frameworks existentes como CrewAI y LangChain. NEXUS proporciona una arquitectura robusta, segura, escalable y de alto rendimiento para construir, desplegar y gestionar sistemas multi-agente complejos. Es la base sobre la cual construiremos la próxima generación de soluciones de IA.

## Stack Tecnológico

La elección del stack está orientada a la máxima eficiencia, seguridad y modernidad.

- **Lenguaje**: Python 3.11+ (aprovechando `asyncio` nativo, `match-case`, y mejoras de tipado).
- **Concurrencia**: `asyncio` para operaciones I/O no bloqueantes, permitiendo alta concurrencia con un solo hilo.
- **Validación de Datos**: Pydantic v2 para un parseo y validación de datos riguroso, rápido y explícito.
- **Persistencia (Opcional)**: Redis para un bus de eventos escalable y un gestor de estado persistente en entornos distribuidos.

## Principios de Diseño

NEXUS se construye sobre cuatro pilares fundamentales:

1.  **Event-Driven (Dirigido por Eventos)**: Los componentes del sistema (módulos y agentes) están desacoplados. Se comunican de forma asíncrona a través de un bus de eventos central, lo que permite una mayor flexibilidad, escalabilidad y facilidad para añadir nuevas funcionalidades.
2.  **Self-Healing (Auto-reparación)**: El sistema está diseñado para ser resiliente. Con un gestor de estado persistente, NEXUS puede reanudar operaciones desde el último punto de control en caso de fallos de agentes individuales o del sistema, garantizando la finalización de las tareas.
3.  **Agnostic LLM (Agnóstico al LLM)**: NEXUS no está atado a ningún proveedor de modelos de lenguaje. Una capa de abstracción (LLM Abstraction Layer) permite conectar y intercambiar fácilmente diferentes LLMs (OpenAI, Anthropic, Llama, modelos locales) sin alterar la lógica de los agentes.
4.  **Security-First (Seguridad Primero)**: La seguridad no es una ocurrencia tardía. Incluye sandboxing para la ejecución de herramientas, validación estricta de todas las entradas y salidas, y un sistema centralizado para la gestión de secretos y credenciales.

## Diagrama de Arquitectura

```ascii
   [ User Goal / API Call ]
             |
             v
+---------------------------+
|   Core: Orchestrator      |
| (Decomposes Goal, Runs    |
|  Task Loop)               |
+---------------------------+
             | ^
(Dispatch Task) | (Task Result, System Events)
             v |
+---------------------------+
|   Core: Event Bus         |
| (Redis or In-Memory)      |
+---------------------------+
   ^         |         ^
   |         |         |
(Register)   | (Execute) | (Update State)
   |         v         |
+----------------+  +----------------+  +----------------+
| Agent Registry |  | Agent Instances|  | State Manager  |
| (Knows Agents' |  | [A1] [A2]..[An]|  | (Saves Progress|
|  Capabilities) |  | (Execute Tasks)|  |  & Results)    |
+----------------+  +----------------+  +----------------+
                        |
                        v (LLM Calls)
                    +---------------------+
                    |   LLM Abstraction   |
                    | (Handles Prompts,   |
                    |  Retries, Parsing)  |
                    +---------------------+
                             |
                             v
                  [ OpenAI / Anthropic / etc. ]
```

## Responsabilidad de los Módulos

- **Orchestrator (`core/orchestrator.py`)**: Es el cerebro del sistema. Recibe el objetivo de alto nivel, lo descompone en una secuencia de tareas ejecutables y gestiona el ciclo de vida de la misión. Despacha tareas al `Event Bus` y reacciona a los resultados para decidir los siguientes pasos, manejando la lógica de éxito, fallo o reintento.

- **Event Bus (`core/event_bus.py`)**: Es el sistema nervioso central. Permite la comunicación asíncrona y desacoplada entre todos los módulos. Un componente publica un evento (ej. `TASK_COMPLETED`) y otros componentes suscritos a ese evento reaccionan. Esto elimina dependencias directas y mejora la modularidad.

- **Agent Registry (`agents/registry.py`)**: Actúa como un directorio de servicios para los agentes. Sabe qué agentes están disponibles, cuáles son sus capacidades, herramientas y cómo instanciarlos de forma segura. El `Orchestrator` consulta este registro para encontrar el agente adecuado para una tarea específica.

- **State Manager (`state/manager.py`)**: Es la memoria persistente del sistema. Guarda y recupera el estado completo de una ejecución: tareas pendientes, resultados intermedios, estado interno de los agentes, etc. Esto es crucial para la resiliencia (`Self-Healing`), ya que permite reanudar el trabajo desde el último punto guardado.

- **LLM Abstraction (`llm/abstraction.py`)**: Proporciona una interfaz unificada para interactuar con diferentes modelos de lenguaje. Se encarga del formateo de prompts, la gestión de reintentos ante fallos de la API, el parseo estandarizado de las respuestas y el manejo de la lógica específica de cada proveedor, manteniendo a los agentes agnósticos al modelo subyacente.

- **Security (`core/security.py`)**: Es el guardián del sistema. Proporciona mecanismos para la ejecución segura de código o herramientas (sandboxing), valida y sanitiza todas las entradas y salidas para prevenir inyecciones, y gestiona el acceso a secretos y claves de API de forma centralizada y segura.

## Guía de Onboarding para Nuevos Desarrolladores

Sigue estos 5 pasos para empezar a contribuir a NEXUS:

1.  **Clonar y Entorno Virtual**:
    ```bash
    git clone <repository_url> nexus_core
    cd nexus_core
    python3.11 -m venv .venv
    source .venv/bin/activate
    ```
2.  **Instalar Dependencias**:
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configurar Credenciales**:
    Copia el archivo de ejemplo `.env.example` a `.env` y añade tus claves de API (ej. `OPENAI_API_KEY`).
    ```bash
    cp .env.example .env
    nano .env
    ```
4.  **Verificar Instalación**:
    Ejecuta la suite de tests unitarios para asegurar que todos los componentes base funcionan correctamente.
    ```bash
    pytest nexus_core/tests/unit
    ```
5.  **Crear tu Primer Agente**:
    Crea un nuevo archivo en `nexus_core/agents/mi_agente.py`. Define una clase que herede de `BaseAgent`, implementa el método `run()` y regístralo en el `AgentRegistry`. ¡Ya estás listo para integrarlo en una orquestación!

## ¿Por qué NEXUS > CrewAI / LangChain / AutoGPT?

- **Control Total y Cero Dependencias**: A diferencia de LangChain o CrewAI que son wrappers sobre otros servicios, NEXUS es nuestro propio motor. No estamos limitados por las decisiones de diseño, bugs o el roadmap de terceros. Esto nos da control absoluto sobre la optimización, la seguridad y las funcionalidades.

- **Rendimiento Superior con `asyncio`**: NEXUS utiliza `asyncio` de forma nativa y profunda, no como un añadido. Esto permite una concurrencia real y un manejo de operaciones I/O (llamadas a APIs, acceso a ficheros) mucho más eficiente que los modelos basados en hilos o ejecuciones síncronas de muchos frameworks existentes.

- **Seguridad como Pilar Central**: Mientras que otros frameworks delegan la seguridad al desarrollador, NEXUS la integra en su núcleo. El sandboxing de herramientas y la validación estricta de datos con Pydantic v2 no son opcionales, son parte del flujo de trabajo estándar, reduciendo drásticamente la superficie de ataque.

- **Diseñado para Producción**: AutoGPT es un experimento, LangChain es un conjunto de herramientas y CrewAI es una capa de orquestación simple. NEXUS está diseñado desde el principio con principios de ingeniería de software para sistemas en producción: resiliencia (`Self-Healing`), escalabilidad (arquitectura `Event-Driven`) y mantenibilidad (código desacoplado y modular).