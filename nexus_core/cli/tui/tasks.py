"""Bounded projection of task events; no scheduling or I/O in the renderer."""
from collections import OrderedDict
import threading
import time

TERMINAL = {'ok','failed','cancelled','timeout','released'}

#: The coordinator's background calls (``spawn_subagent``) publish these. They
#: are the only place a long scan's *liveness* reaches the UI: without the row
#: the operator sees a still terminal and cannot tell a running ``nmap -p-``
#: from a stalled loop.
BACKGROUND_EVENTS = frozenset({
    'react.background_started', 'react.background_finished',
    'react.background_delivered', 'react.background_reconciled',
})
BACKGROUND_KIND = 'background'
#: TaskManager status -> row status. ``succeeded`` is the manager's word for a
#: call that finished and verified; the row keeps the panel's own vocabulary.
BACKGROUND_STATUS = {
    'running': 'running', 'succeeded': 'ok', 'failed': 'failed',
    'cancelled': 'cancelled', 'timeout': 'timeout',
}


def elapsed_label(started: float, finished: float | None = None) -> str:
    """``MM:SS`` (``H:MM:SS`` past an hour) of a task's wall clock."""
    end = time.monotonic() if finished is None else finished
    seconds = max(0, int(end - started))
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"


def tool_label(tool_id) -> str:
    """Short tool name for the row: ``nexus.recon.nmap`` -> ``nmap``."""
    return str(tool_id or '').rsplit('.', 1)[-1] or 'tool'


class TaskPanel:
    def __init__(self, max_tasks=128):
        self.tasks = OrderedDict()
        self.max_tasks = max_tasks
        self.selected = None
        self._lock = threading.RLock()
        #: Keys whose result already reached the transcript. A late duplicate
        #: event must not bring a retired row back.
        self._retired = set()

    @property
    def running(self):
        with self._lock:
            return any(t['status']=='running' for t in self.tasks.values())

    def consume(self, event):
        kind = event.get('event_type') or event.get('action')
        payload = event.get('payload') or {}
        run = str(event.get('run_id') or payload.get('run_id') or '')
        if kind in BACKGROUND_EVENTS:
            self._consume_background(str(kind), run, payload)
            return
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
                    # The run cancels every task it spawned before returning, so
                    # a background row cannot outlive it: retiring it here keeps
                    # the dock honest instead of showing a scan that is gone.
                    self._retire_background(run)
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
            if not old and not self._make_room():
                return
            status = 'running' if kind.endswith('started') else str(payload.get('status','ok'))
            if status not in TERMINAL | {'running'}:
                status = 'failed'
            self.tasks[key] = {'status':status, 'label':str(payload.get('subagent_id') or identifier),
                               'target':str(payload.get('target') or (old or {}).get('target','')),
                               'started':(old or {}).get('started',time.monotonic())}
            if self.selected not in self.tasks:
                self.selected = key

    def _consume_background(self, kind, run, payload):
        """Track one ``bg-*`` call until its result is on screen.

        ``started`` opens the row, ``finished`` freezes its clock, and
        ``delivered`` removes it: from then on the result lives in the existing
        tool card, so the dock is not a second copy of the transcript.
        """
        identifier = str(payload.get('task_id') or '')
        if not identifier:
            return
        key = f"{run}:{identifier}"
        with self._lock:
            if kind == 'react.background_delivered':
                self._retired.add(key)
                self.tasks.pop(key, None)
                if self.selected == key:
                    self.selected = next(iter(self.tasks), None)
                return
            if key in self._retired:
                return
            if kind == 'react.background_reconciled':
                return  # the turn was answered with the task already in flight
            old = self.tasks.get(key)
            if old is not None and old['status'] in TERMINAL:
                return
            if kind == 'react.background_finished':
                if old is None:
                    return  # a finish whose start this UI never saw: no phantom timer
                old['status'] = BACKGROUND_STATUS.get(
                    str(payload.get('status') or ''), 'failed')
                old['finished'] = time.monotonic()
                return
            if old is not None:
                return  # the start is the row; a repeat cannot restart it
            if not self._make_room():
                return
            self.tasks[key] = {
                'status': 'running', 'kind': BACKGROUND_KIND,
                'label': str(payload.get('label') or ''),
                'tool': tool_label(payload.get('tool_id')),
                'target': '', 'started': time.monotonic(),
            }
            if self.selected not in self.tasks:
                self.selected = key

    def _retire_background(self, run):
        """Drop this run's background rows; its tasks were cancelled with it."""
        for key in [key for key, task in self.tasks.items()
                    if task.get('kind') == BACKGROUND_KIND and key.startswith(run + ':')]:
            self.tasks.pop(key, None)
            self._retired.add(key)
        if self.selected not in self.tasks:
            self.selected = next(iter(self.tasks), None)

    def _make_room(self):
        """Evict the oldest finished row; producers are bounded below this cap."""
        if len(self.tasks) < self.max_tasks:
            return True
        removable = next((key for key, task in self.tasks.items() if task['status'] in TERMINAL), None)
        if removable is None:
            return False
        del self.tasks[removable]
        self._retired.add(removable)
        return True

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
            rows = [('', self._header(keys))]
            for key in keys[start:start+5]:
                task=self.tasks[key]
                rows.append(self._background_row(key, task, no_color)
                            if task.get('kind') == BACKGROUND_KIND
                            else self._task_row(key, task, no_color))
            if len(keys)>5:
                rows.append(('',f'{len(keys)} tareas · F6 para recorrer\n'))
            return rows

    def _header(self, keys):
        """Static hints, claiming only the keys this selection can use."""
        if any(self.tasks[key].get('kind') != BACKGROUND_KIND for key in keys):
            return 'Tareas · F6 seleccionar · F7 cancelar fan-out\n'
        return 'Background · F6 seleccionar\n'

    def _task_row(self, key, task, no_color):
        status=task['status']
        icon = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'[int((time.monotonic()-task['started'])*8)%10] if status=='running' else {'ok':'✓','failed':'✗','cancelled':'–','timeout':'!','released':'·'}[status]
        style = 'ansiyellow' if status=='running' else 'ansigreen' if status=='ok' else 'dim' if status=='released' else 'ansired'
        text=f"{'>' if key==self.selected else ' '} {icon} {status} · {task['label']} {task['target']}"
        return self._line(style, text, no_color)

    def _background_row(self, key, task, no_color):
        """``Background · bg-1 · nmap · running · 01:24``: alive, and for how long."""
        status=task['status']
        icon = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'[int((time.monotonic()-task['started'])*8)%10] if status=='running' else {'ok':'✓','failed':'✗','cancelled':'–','timeout':'!','released':'·'}[status]
        style = 'ansiyellow' if status=='running' else 'ansigreen' if status=='ok' else 'dim' if status=='released' else 'ansired'
        clock = elapsed_label(task['started'], task.get('finished'))
        label = task.get('label') or ''
        text=(f"{'>' if key==self.selected else ' '} {icon} Background · {key.rsplit(':',1)[-1]} · "
              f"{task.get('tool') or 'tool'} · {status} · {clock}")
        if label and label != task.get('tool'):
            text += f" · {label}"
        return self._line(style, text, no_color)

    @staticmethod
    def _line(style, text, no_color):
        text=''.join(c if c.isprintable() else ' ' for c in text)
        return ('' if no_color else style, text[:100]+'\n')
