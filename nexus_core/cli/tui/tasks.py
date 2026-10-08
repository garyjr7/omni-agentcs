"""Bounded projection of task events; no scheduling or I/O in the renderer."""
from collections import OrderedDict
import threading
import time

TERMINAL = {'ok','failed','cancelled','released'}

class TaskPanel:
    def __init__(self, max_tasks=128):
        self.tasks = OrderedDict()
        self.max_tasks = max_tasks
        self.selected = None
        self._lock = threading.RLock()

    @property
    def running(self):
        with self._lock:
            return any(t['status']=='running' for t in self.tasks.values())

    def consume(self, event):
        kind = event.get('event_type') or event.get('action')
        payload = event.get('payload') or {}
        run = str(event.get('run_id') or payload.get('run_id') or '')
        if kind in {'orchestrator.subagent','react.finished'}:
            with self._lock:
                event_key = f"{run}:profile:{payload.get('subagent_id')}:{event.get('sequence',len(self.tasks))}"
                if kind == 'orchestrator.subagent' and event_key in self.tasks:
                    return
                for key, task in self.tasks.items():
                    if key.startswith(run+':profile:') and task['status']=='running':
                        task['status'] = 'released' if kind=='orchestrator.subagent' else (
                            'ok' if payload.get('status')=='completed' else
                            'cancelled' if payload.get('status')=='cancelled' else 'failed')
                if kind=='react.finished':
                    return
                payload = {**payload,'task_id':f"profile:{payload.get('subagent_id')}:{event.get('sequence',len(self.tasks))}"}
                kind = 'subagent.started'
        if kind not in {'subagent.started','subagent.ended','fanout.task.started','fanout.task.ended'}:
            return
        run = str(event.get('run_id') or payload.get('run_id') or '')
        identifier = str(payload.get('task_id') or payload.get('subagent_id') or '')
        if not identifier:
            return
        key = run + ':' + identifier
        with self._lock:
            old = self.tasks.get(key)
            if old and old['status'] in TERMINAL:
                return  # duplicate or late event cannot resurrect a finished task
            if not old and len(self.tasks)>=self.max_tasks:
                removable = next((k for k,t in self.tasks.items() if t['status'] in TERMINAL),None)
                if removable is None:
                    return  # producer concurrency is already bounded below this limit
                del self.tasks[removable]
            status = 'running' if kind.endswith('started') else str(payload.get('status','ok'))
            if status not in TERMINAL | {'running'}:
                status = 'failed'
            self.tasks[key] = {'status':status, 'label':str(payload.get('subagent_id') or identifier),
                               'target':str(payload.get('target') or (old or {}).get('target','')),
                               'started':(old or {}).get('started',time.monotonic())}
            if self.selected not in self.tasks:
                self.selected = key

    def select_next(self):
        with self._lock:
            keys=list(self.tasks)
            if keys:
                index=keys.index(self.selected) if self.selected in keys else -1
                self.selected=keys[(index+1)%len(keys)]

    def render(self, *, no_color=False):
        with self._lock:
            if not self.tasks:
                return []
            keys = list(self.tasks)
            start = max(0,keys.index(self.selected)-4) if self.selected in keys else 0
            rows = [('', 'Tareas · F6 seleccionar · F7 cancelar fan-out\n')]
            for key in keys[start:start+5]:
                task=self.tasks[key]; status=task['status']
                icon = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'[int((time.monotonic()-task['started'])*8)%10] if status=='running' else {'ok':'✓','failed':'✗','cancelled':'–','released':'·'}[status]
                style = 'ansiyellow' if status=='running' else 'ansigreen' if status=='ok' else 'dim' if status=='released' else 'ansired'
                text=f"{'>' if key==self.selected else ' '} {icon} {status} · {task['label']} {task['target']}"
                text=''.join(c if c.isprintable() else ' ' for c in text)
                rows.append(('' if no_color else style,text[:100]+'\n'))
            if len(keys)>5:
                rows.append(('',f'{len(keys)} tareas · F6 para recorrer\n'))
            return rows
