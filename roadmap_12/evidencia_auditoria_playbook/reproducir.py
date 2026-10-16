import asyncio
import copy
import json
import tempfile
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch
import yaml
from nexus_core.playbooks.loader import load_package_text, load_packages, validate_against_catalog, PACKAGE_DIR
from nexus_core.agent.playbooks import match_playbook
from nexus_core.agent.turn_telemetry import TurnTelemetryRecorder, flag_for_error
from nexus_core.agent.subagents import SUBAGENTS, SUBAGENTS_BY_ID, permits
from nexus_core.agent.react_coordinator import ReActCoordinator, Transition
from nexus_core.tools.registry import durable_tool_definitions
from nexus_core.tools.handlers import jobs
from nexus_core.kernel.models import RunContext, Identity
base = yaml.safe_load((PACKAGE_DIR/'red_team_base.yaml').read_text())
results: dict[str, Any] = {}
bad = copy.deepcopy(base)
bad['phases'][0]['steps'][0]['tool_id'] = 'nexus.nonexistent'
p = load_package_text(yaml.safe_dump(bad))
results['unknown_tool_loads'] = p.phases[0].playbook.steps[0].tool_id
results['separate_catalog_check'] = validate_against_catalog((p,), durable_tool_definitions())
bad = copy.deepcopy(base)
for step in bad['phases'][0]['steps']:
    step['produces'] = None
results['phase_without_produces_loads'] = len(load_package_text(yaml.safe_dump(bad)).phases)
results['duplicate_yaml_key_loads'] = load_package_text('schema_version: 99\n'+yaml.safe_dump(base)).playbook_id
bad = copy.deepcopy(base)
bad['phases'][0]['gate'] = {'always': True, 'all_fact_types': ['privilege']}
results['mixed_gate_passes_empty_facts'] = load_package_text(yaml.safe_dump(bad)).phases[0].predicate([])
with tempfile.TemporaryDirectory() as d:
    root = Path(d)
    (root/'good.yaml').write_text(yaml.safe_dump(base))
    (root/'bad.yaml').write_text('schema_version: 1\n')
    results['one_bad_disables_all_packages'] = len(load_packages(root))
p = load_package_text(yaml.safe_dump(base))
phase = p.phases[2]
results['command_phase_complete_from_existing_session'] = match_playbook(phase.playbook, [{'fact_type':'session'}]).next_step is None
class SlowSink:
    def append_run_event(self, *args):
        time.sleep(.08)
rec = TurnTelemetryRecorder(store=SlowSink(), tenant_id='t', run_id='r')
rec.begin_turn(iteration=1, phase='recon', subagent_id='recon', facts_total=8, counts={'service':8})
start=time.perf_counter()
r=rec.finish(outcome='ok')
results['synchronous_finish_ms'] = round((time.perf_counter()-start)*1000)
results['first_turn_delta_without_new_facts'] = r.blackboard_delta if r else None
rec = TurnTelemetryRecorder(emit=False)
invalid_counts: Any = {'service': 'bad'}  # adverse input: a non-int counter
rec.begin_turn(iteration=1,phase='recon',subagent_id='recon',counts=invalid_counts)
try:
    rec.finish(outcome='ok')
except Exception as e:
    results['invalid_count_raises_and_loses_draft'] = [type(e).__name__,rec.has_open_turn]
c=ReActCoordinator.__new__(ReActCoordinator)
c.status='max_iterations'
results['normal_turn_outcome'] = c._turn_outcome(Transition.NEXT_TURN)
results['cancelled_classification'] = flag_for_error('CancelledError').value
ids=['nexus.web.request','nexus.web.upload','nexus.post.shell_exec','nexus.post.job','nexus.web.git_dump']
results['mapping']={s.id:[i for i in ids if i in s.tools] for s in SUBAGENTS if any(i in s.tools for i in ids)}
profile=SUBAGENTS_BY_ID['privesc']
catalog=durable_tool_definitions('t')
inner=next(i for i in ('nexus.web.upload','nexus.web.git_dump','nexus.recon.nmap') if not permits(profile,i,catalog[i]))
store=Mock()
store.enqueue_task.return_value={'id':'mock-task'}
args={'url':'https://fixture.invalid', 'upload':{'field':'file','path':'fixture'}} if inner=='nexus.web.upload' else {'url':'https://fixture.invalid/.git'} if inner=='nexus.web.git_dump' else {'target':'192.0.2.1'}
with patch.object(jobs,'validate_session_scope',return_value=None):
    result=asyncio.run(jobs.jobs_handler({'action':'start','tool_id':inner,'arguments':args},RunContext('t',Identity('test','t',roles=('operator',)),store=store)))
results['delegation_profile_gap']={'profile':profile.id,'wrapper_allowed':permits(profile,'nexus.post.job',catalog['nexus.post.job']),'inner':inner,'inner_allowed_directly':permits(profile,inner,catalog[inner]),'mock_job_queued':result.verified}
print(json.dumps(results,indent=2))
