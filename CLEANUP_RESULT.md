# Resultado del cleanup

**Bloqueado en la auditoría previa.** Rama `chore/final-cleanup`.

Se creó la rama y se completó el diagnóstico de imports, DB y tests/.
No se borraron archivos ni carpetas, no se movieron reportes, no se modificaron
rutas protegidas, README o configuración, y no se migró la DB.
Solo se añaden CLEANUP_AUDIT.md y CLEANUP_RESULT.md en un commit documental.
Sin push.

Ruff ya falla con 29 errores; seis requieren modificar nexus_core/utils/,
prohibido por la regla 4. Se detuvo el trabajo antes de cualquier limpieza.
Para continuar debe resolverse esa restricción. Los criterios de raíz limpia,
470 tests posteriores, 8 imports posteriores, README actualizado y migración
quedan pendientes; no se presentan como completados. No se volvió a ejecutar
la suite porque no se realizaron cambios de código.

La DB activa sigue en data/nexus_pro.db y el CLI lista eng-scanme (scanme-lab),
válido hasta 2030-01-01. El destino XDG predeterminado todavía no existe.
Detalles y salida de engagements en [CLEANUP_AUDIT.md](CLEANUP_AUDIT.md).

## Salida exacta de Ruff antes del cleanup

```text
F401 [*] `nexus_core.agents.base.AgentMetadata` imported but unused
 --> nexus_core/agents/generated/dataanalysisagent.py:1:47
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
  |                                               ^^^^^^^^^^^^^
2 | import asyncio
3 | import json
  |
help: Remove unused import: `nexus_core.agents.base.AgentMetadata`
  |
  - from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
1 + from nexus_core.agents.base import BaseAgent, AgentCapability
2 | import asyncio
  |

F401 [*] `asyncio` imported but unused
 --> nexus_core/agents/generated/dataanalysisagent.py:2:8
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
2 | import asyncio
  |        ^^^^^^^
3 | import json
  |
help: Remove unused import: `asyncio`
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
  - import asyncio
2 | import json
  |

F401 [*] `json` imported but unused
 --> nexus_core/agents/generated/dataanalysisagent.py:3:8
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
2 | import asyncio
3 | import json
  |        ^^^^
4 |
5 | class DataAnalysisAgent(BaseAgent):
  |
help: Remove unused import: `json`
  |
2 | import asyncio
  - import json
3 |
  |

F401 [*] `subprocess` imported but unused
  --> nexus_core/agents/generated/doc_agent.py:9:8
   |
 7 | import json
 8 | import uuid
 9 | import subprocess
   |        ^^^^^^^^^^
10 | from datetime import datetime
11 | from pathlib import Path
   |
help: Remove unused import: `subprocess`
  |
8 | import uuid
  - import subprocess
9 | from datetime import datetime
  |

F401 [*] `pathlib.Path` imported but unused
  --> nexus_core/agents/generated/doc_agent.py:11:21
   |
 9 | import subprocess
10 | from datetime import datetime
11 | from pathlib import Path
   |                     ^^^^
12 | from nexus_core.config import NEXUS_ROOT, NEXUS_DATA_PATH, CHROMA_PATH as CONFIG_CHROMA_PATH, LEGACY_DATABASE_PATH
   |
help: Remove unused import: `pathlib.Path`
   |
10 | from datetime import datetime
   - from pathlib import Path
11 | from nexus_core.config import NEXUS_ROOT, NEXUS_DATA_PATH, CHROMA_PATH as CONFIG_CHROMA_PATH, LEGACY_DATABASE_PATH
   |

F401 [*] `os` imported but unused
 --> nexus_core/agents/generated/guardian_agent.py:4:35
  |
2 | GuardianAgent v1.0 — Seguridad continua BajioWare
3 | """
4 | import subprocess, sqlite3, json, os, re, uuid
  |                                   ^^
5 | from datetime import datetime
6 | from pathlib import Path
  |
help: Remove unused import: `os`
  |
3 | """
  - import subprocess, sqlite3, json, os, re, uuid
4 + import subprocess, sqlite3, json, re, uuid
5 | from datetime import datetime
  |

F401 [*] `pathlib.Path` imported but unused
  --> nexus_core/agents/generated/kill_switch_agent.py:9:21
   |
 7 | import uuid
 8 | from datetime import datetime
 9 | from pathlib import Path
   |                     ^^^^
10 | from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH
   |
help: Remove unused import: `pathlib.Path`
  |
8 | from datetime import datetime
  - from pathlib import Path
9 | from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH
  |

F401 [*] `asyncio` imported but unused
  --> nexus_core/agents/generated/plan_agent.py:8:8
   |
 6 | import json
 7 | import uuid
 8 | import asyncio
   |        ^^^^^^^
 9 | import httpx
10 | from datetime import datetime
   |
help: Remove unused import: `asyncio`
  |
7 | import uuid
  - import asyncio
8 | import httpx
  |

F401 [*] `pathlib.Path` imported but unused
  --> nexus_core/agents/generated/plan_agent.py:11:21
   |
 9 | import httpx
10 | from datetime import datetime
11 | from pathlib import Path
   |                     ^^^^
12 | from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH
   |
help: Remove unused import: `pathlib.Path`
   |
10 | from datetime import datetime
   - from pathlib import Path
11 | from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH
   |

F541 [*] f-string without any placeholders
   --> nexus_core/agents/generated/plan_agent.py:142:44
    |
140 |     if not row or row[6] != "approved":
141 |         conn.close()
142 |         return {"success": False, "error": f"Plan no aprobado o no encontrado"}
    |                                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
143 |
144 |     steps = json.loads(row[3] or "[]")
    |
help: Remove extraneous `f` prefix
    |
141 |         conn.close()
    -         return {"success": False, "error": f"Plan no aprobado o no encontrado"}
142 +         return {"success": False, "error": "Plan no aprobado o no encontrado"}
143 |
    |

F401 [*] `nexus_core.agents.base.AgentMetadata` imported but unused
 --> nexus_core/agents/generated/reportgenerationagent.py:1:47
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
  |                                               ^^^^^^^^^^^^^
2 | import asyncio
3 | import json
  |
help: Remove unused import
  |
  - from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
1 + from nexus_core.agents.base import BaseAgent
2 | import asyncio
  |

F401 [*] `nexus_core.agents.base.AgentCapability` imported but unused
 --> nexus_core/agents/generated/reportgenerationagent.py:1:62
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
  |                                                              ^^^^^^^^^^^^^^^
2 | import asyncio
3 | import json
  |
help: Remove unused import
  |
  - from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
1 + from nexus_core.agents.base import BaseAgent
2 | import asyncio
  |

F401 [*] `asyncio` imported but unused
 --> nexus_core/agents/generated/reportgenerationagent.py:2:8
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
2 | import asyncio
  |        ^^^^^^^
3 | import json
  |
help: Remove unused import: `asyncio`
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
  - import asyncio
2 | import json
  |

F401 [*] `json` imported but unused
 --> nexus_core/agents/generated/reportgenerationagent.py:3:8
  |
1 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
2 | import asyncio
3 | import json
  |        ^^^^
4 |
5 | class ReportGenerationAgent(BaseAgent):
  |
help: Remove unused import: `json`
  |
2 | import asyncio
  - import json
3 |
  |

F401 [*] `shutil` imported but unused
  --> nexus_core/agents/generated/test_agent.py:10:8
   |
 8 | import json
 9 | import uuid
10 | import shutil
   |        ^^^^^^
11 | from datetime import datetime
12 | from pathlib import Path
   |
help: Remove unused import: `shutil`
   |
9  | import uuid
   - import shutil
10 | from datetime import datetime
   |

F401 [*] `uuid` imported but unused
 --> nexus_core/core/agent_factory.py:5:8
  |
3 | """
4 | import importlib
5 | import uuid
  |        ^^^^
6 | from pathlib import Path
7 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
  |
help: Remove unused import: `uuid`
  |
4 | import importlib
  - import uuid
5 | from pathlib import Path
  |

F401 [*] `nexus_core.agents.base.BaseAgent` imported but unused
 --> nexus_core/core/agent_factory.py:7:36
  |
5 | import uuid
6 | from pathlib import Path
7 | from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
  |                                    ^^^^^^^^^
8 |
9 | class AgentFactory:
  |
help: Remove unused import: `nexus_core.agents.base.BaseAgent`
  |
6 | from pathlib import Path
  - from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
7 + from nexus_core.agents.base import AgentMetadata, AgentCapability
8 |
  |

F401 [*] `pathlib` imported but unused
  --> nexus_core/core/orchestrator.py:10:8
   |
 8 | import time
 9 | import logging
10 | import pathlib
   |        ^^^^^^^
11 | import random
   |
help: Remove unused import: `pathlib`
   |
9  | import logging
   - import pathlib
10 | import random
   |

F401 [*] `copy` imported but unused
  --> nexus_core/state/manager.py:11:8
   |
 9 | import uuid
10 | import hashlib
11 | import copy
   |        ^^^^
12 | import dataclasses
13 | import logging
   |
help: Remove unused import: `copy`
   |
10 | import hashlib
   - import copy
11 | import dataclasses
   |

F401 [*] `asyncio` imported but unused
 --> nexus_core/team_orchestrator.py:5:8
  |
3 | Gestiona el ciclo de vida completo de equipos: crear, ejecutar, monitorear, destruir
4 | """
5 | import asyncio
  |        ^^^^^^^
6 | import json
7 | import sqlite3
  |
help: Remove unused import: `asyncio`
  |
4 | """
  - import asyncio
5 | import json
  |

F401 [*] `datetime.datetime` imported but unused
  --> nexus_core/team_orchestrator.py:11:22
   |
 9 | import re
10 | import uuid
11 | from datetime import datetime
   |                      ^^^^^^^^
12 | from pathlib import Path
13 | from typing import Optional
   |
help: Remove unused import: `datetime.datetime`
   |
10 | import uuid
   - from datetime import datetime
11 | from pathlib import Path
   |

F841 Local variable `task` is assigned to but never used
  --> nexus_core/tests/unit/test_sovereign_runtime.py:38:5
   |
36 |     store.initialize()
37 |     run = store.create_run("system", {})
38 |     task = store.enqueue_task(tenant_id="system", run_id=run["id"],
   |     ^^^^
39 |                               task_type="unknown.execute", payload={})
40 |     claimed = store.claim_task("worker-test")
   |
help: Remove assignment to unused variable `task`

F841 Local variable `task` is assigned to but never used
  --> nexus_core/tests/unit/test_sovereign_runtime.py:78:5
   |
76 |     store.initialize()
77 |     run = store.create_run("system", {"kind": "agent"})
78 |     task = store.enqueue_task(
   |     ^^^^
79 |         tenant_id="system", run_id=run["id"], task_type="brain.run",
80 |         payload={
   |
help: Remove assignment to unused variable `task`

F401 [*] `contextlib` imported but unused
  --> nexus_core/utils/logger.py:9:8
   |
 7 | import pathlib
 8 | from typing import Optional, Dict
 9 | import contextlib
   |        ^^^^^^^^^^
10 |
11 | # ANSI color codes
   |
help: Remove unused import: `contextlib`
  |
8 | from typing import Optional, Dict
  - import contextlib
9 |
  |

F401 [*] `typing` imported but unused
 --> nexus_core/utils/security.py:4:8
  |
2 | import dataclasses
3 | import enum
4 | import typing
  |        ^^^^^^
5 | import re
6 | import os
  |
help: Remove unused import: `typing`
  |
3 | import enum
  - import typing
4 | import re
  |

F401 [*] `re` imported but unused
 --> nexus_core/utils/security.py:5:8
  |
3 | import enum
4 | import typing
5 | import re
  |        ^^
6 | import os
7 | import pathlib
  |
help: Remove unused import: `re`
  |
4 | import typing
  - import re
5 | import os
  |

F401 [*] `pathlib` imported but unused
 --> nexus_core/utils/security.py:7:8
  |
5 | import re
6 | import os
7 | import pathlib
  |        ^^^^^^^
8 | import datetime
9 | import json
  |
help: Remove unused import: `pathlib`
  |
6 | import os
  - import pathlib
7 | import datetime
  |

F401 [*] `json` imported but unused
  --> nexus_core/utils/security.py:9:8
   |
 7 | import pathlib
 8 | import datetime
 9 | import json
   |        ^^^^
10 | import time
11 | import functools
   |
help: Remove unused import: `json`
  |
8 | import datetime
  - import json
9 | import time
  |

F401 [*] `functools` imported but unused
  --> nexus_core/utils/security.py:11:8
   |
 9 | import json
10 | import time
11 | import functools
   |        ^^^^^^^^^
12 | import logging
13 | import ipaddress
   |
help: Remove unused import: `functools`
   |
10 | import time
   - import functools
11 | import logging
   |

Found 29 errors.
[*] 27 fixable with the `--fix` option (2 hidden fixes can be enabled with the `--unsafe-fixes` option).
```

## ls -la de la raíz al detener el cleanup

Capturado antes de escribir estos dos informes; los únicos archivos añadidos
posteriormente son CLEANUP_AUDIT.md y CLEANUP_RESULT.md.

```text
total 1408
drwxrwxr-x 26 operator operator   4096 Sep 29 22:31 .
drwxr-x--- 12 operator operator   4096 Sep 29 22:43 ..
drwxr-xr-x  2 operator operator   4096 Aug  4 22:52 .agents
drwxrwxr-x  4 operator operator   4096 Aug  4 23:03 .backups
drwxr-xr-x  2 operator operator   4096 Aug  4 22:52 .codex
-rw-rw-r--  1 operator operator    272 Aug  4 22:17 .dockerignore
-rw-------  1 operator operator   4353 Sep 29 20:18 .env
-rw-rw-r--  1 operator operator   4590 Sep 29 20:21 .env.example
drwx------  2 operator operator   4096 Sep 28 00:35 .freebuff
drwxrwxr-x  8 operator operator   4096 Sep 29 22:43 .git
drwxrwxr-x  3 operator operator   4096 Aug  4 21:54 .github
-rw-rw-r--  1 operator operator    435 Sep 29 05:56 .gitignore
drwxrwxr-x  3 operator operator   4096 Sep 27 23:43 .mypy_cache
-rw-rw-r--  1 operator operator      3 Aug  5 20:50 .nvmrc
drwxrwxr-x  3 operator operator   4096 Sep 28 00:30 .pytest_cache
drwxrwxr-x  3 operator operator   4096 Aug  4 22:50 .ruff_cache
drwxrwxr-x  5 operator operator   4096 Sep 29 06:11 .sandbox_home
drwx------  3 operator operator   4096 Sep 29 05:31 .uncover-config
drwxrwxr-x  5 operator operator   4096 Aug  4 22:49 .venv
-rw-rw-r--  1 operator operator  15250 Aug  4 23:22 AUDITORIA_NEXUS_2026-08-04.md
-rw-rw-r--  1 operator operator   1412 Jun  9 14:13 CHANGELOG.md
-rw-rw-r--  1 operator operator   1412 Sep 29 02:24 CHANGELOG.txt
-rw-rw-r--  1 operator operator   6320 Sep 29 04:30 CLI_RECON.md
-rw-rw-r--  1 operator operator  10133 Sep 29 04:43 CLI_RESULT.md
-rw-rw-r--  1 operator operator  57900 Jun  9 14:55 CODEBASE_MAP.md
-rw-rw-r--  1 operator operator   1894 Aug  4 23:02 Dockerfile.backend
-rw-rw-r--  1 operator operator    969 Aug  4 22:17 Dockerfile.frontend
-rw-rw-r--  1 operator operator   5665 Sep 29 06:02 FIX_SANDBOX_RECON.md
-rw-rw-r--  1 operator operator   7001 Sep 29 06:15 FIX_SANDBOX_RESULT.md
-rw-rw-r--  1 operator operator  22206 Aug  8 00:17 INFORME_ARQUITECTONICO_NEXUS_2026-08-08.md
-rw-rw-r--  1 operator operator   5040 Sep 29 20:26 MSF_DAEMON_DIAG.md
-rw-rw-r--  1 operator operator   2584 Sep 29 20:26 MSF_DAEMON_RESULT.md
-rw-rw-r--  1 operator operator   4107 Sep 29 20:26 MSF_RESULT.md
-rw-rw-r--  1 operator operator   1749 Aug  5 20:56 Makefile
-rw-rw-r--  1 operator operator   5517 Sep 29 03:00 NMAP_RECON.md
-rw-rw-r--  1 operator operator   7043 Sep 29 03:02 NMAP_RESULT.md
-rw-rw-r--  1 operator operator 469634 Sep 28 00:10 OMNIAGENT_CONTEXT.md
-rw-rw-r--  1 operator operator   1932 Sep 29 22:17 ONBOARDING_RECON.md
-rw-rw-r--  1 operator operator   9362 Sep 29 22:31 ONBOARDING_RESULT.md
-rw-rw-r--  1 operator operator  16307 Aug  4 23:22 PLAN_IMPLEMENTACION_NEXUS.md
-rw-rw-r--  1 operator operator   5527 Aug  8 00:42 PLAN_MAESTRO_BAJIOWARE.md
-rw-rw-r--  1 operator operator   3148 Jun  9 14:13 PRICING.md
-rw-rw-r--  1 operator operator   2804 Sep 28 00:25 PURGE_RECON.md
-rw-rw-r--  1 operator operator   9356 Sep 28 00:44 PURGE_RESULT.md
-rw-rw-r--  1 operator operator   9094 Sep 29 04:03 REACT_RECON.md
-rw-rw-r--  1 operator operator  10474 Sep 29 04:09 REACT_RESULT.md
-rw-rw-r--  1 operator operator  21680 Sep 29 22:23 README.md
-rw-rw-r--  1 operator operator   3407 Aug  4 23:22 REPORTE_IMPLEMENTACION_NEXUS_2026-08-04.md
-rw-rw-r--  1 operator operator   2823 Sep 28 00:55 RESIDUALS_DIAG.md
-rw-rw-r--  1 operator operator   3435 Sep 28 00:56 RESIDUALS_RESULT.md
-rw-rw-r--  1 operator operator   6518 Sep 29 02:37 SCOPE_RECON.md
-rw-rw-r--  1 operator operator   5300 Sep 29 02:39 SCOPE_RESULT.md
-rw-rw-r--  1 operator operator   4317 Sep 29 02:51 SCOPE_WIRE_RESULT.md
-rw-rw-r--  1 operator operator   9348 Sep 29 05:43 TOOLKIT_RECON.md
-rw-rw-r--  1 operator operator   9988 Sep 29 05:45 TOOLKIT_RESULT.md
drwxrwxr-x  2 operator operator   4096 Sep 29 21:31 __pycache__
drwxrwxr-x  2 operator operator   4096 Jun  9 14:13 bajioware_landing
drwxrwxr-x  4 operator operator   4096 Sep 29 22:43 data
drwxrwxr-x  3 operator operator   4096 Aug  4 21:52 departments
drwxrwxr-x  2 operator operator   4096 Aug  5 00:46 docker
-rw-rw-r--  1 operator operator   7777 Aug  5 00:47 docker-compose.yml
drwxrwxr-x  4 operator operator   4096 Aug  5 20:53 docs
-rwxrwxr-x  1 operator operator   8985 Jun  9 14:13 factory_runner.py
-rw-rw-r--  1 operator operator   1226 Aug  4 23:21 install.sh
-rwxrwxr-x  1 operator operator  15692 Jun  9 15:15 junior_jarvis.py
-rwxrwxr-x  1 operator operator    440 Sep 29 03:58 list_models.sh
drwxrwxr-x 10 operator operator   4096 Aug  4 22:51 nexus_api
-rwxrwxr-x  1 operator operator    257 Aug  4 23:04 nexus_backup.sh
-rw-rw-r--  1 operator operator   2856 Aug  4 22:04 nexus_cli.py
-rw-rw-r--  1 operator operator   3943 Aug  4 23:12 nexus_connector.py
drwxrwxr-x 24 operator operator   4096 Sep 29 21:17 nexus_core
drwxrwxr-x  6 operator operator   4096 Aug  4 23:09 nexus_frontend
-rwxrwxr-x  1 operator operator   2893 Jun  9 14:13 nexus_healthcheck.sh
-rwxrwxr-x  1 operator operator  69278 Jun  9 14:13 nexus_junior_jarvis.sh
drwxrwxr-x  4 operator operator   4096 Aug  4 23:14 nexus_mcp
-rw-rw-r--  1 operator operator   4002 Aug  4 23:04 nexus_ops.py
-rwxrwxr-x  1 operator operator    258 Aug  4 23:04 nexus_restore.sh
-rwxrwxr-x  1 operator operator   3329 Jun  9 14:13 nexus_start.sh
-rwxrwxr-x  1 operator operator  12727 Jun  9 14:13 nexus_upgrade.sh
-rw-rw-r--  1 operator operator   2040 Aug  5 20:56 nexus_worker.py
-rwxrwxr-x  1 operator operator   2464 Sep 29 21:31 omni.py
-rw-rw-r--  1 operator operator   1839 Sep 29 04:19 react_e2e_manual.py
-rw-rw-r--  1 operator operator    106 Aug  4 21:54 requirements-dev.txt
-rw-rw-r--  1 operator operator     61 Aug  4 23:02 requirements-prod.in
-rw-rw-r--  1 operator operator 125780 Aug  4 23:16 requirements-prod.lock
-rw-rw-r--  1 operator operator 152699 Aug  4 23:16 requirements.lock
-rw-rw-r--  1 operator operator     99 Aug  4 22:50 ruff.toml
drwxrwxr-x  3 operator operator   4096 Sep 29 19:58 scripts
drwxrwxr-x  3 operator operator   4096 Sep 29 04:52 tests
```
