"""Trusted, narrow semantic parsers. Model/extension metadata is never promoted.

New parsers must establish the claimed post-condition, not merely successful
execution. Unsupported outputs remain inventory; they cannot advance phases.
"""
import re
from .blackboard import Blackboard


def derive_assertions(tool_id, arguments, result, context):
    if not result.success or not context.invocation_id:
        return []
    output = result.output
    rows = []

    def add(kind, target, value, key=None):
        if not target:
            return
        rows.append(dict(fact_type=kind, target=str(target), key=str(key or target),
                         value=value, verified=True, asserted_by='verifier',
                         verification_method=result.verification_method,
                         invocation_id=context.invocation_id, run_id=context.run_id))

    if tool_id == 'nexus.recon.nmap' and result.verification_method == 'nmap_xml_parsed':
        for host in output.get('scan', {}).get('hosts', []):
            if host.get('state') != 'up':
                continue
            target = host.get('ip')
            add('host', target, {'state': 'up'})
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    add('service', target, port, f"{target}:{port.get('port')}:{port.get('protocol')}")
    elif tool_id == 'nexus.recon.httpx' and result.verification_method == 'httpx_jsonl_parsed':
        for probe in output.get('probes', []):
            if probe.get('status_code'):
                add('endpoint', probe.get('url'), probe)
    elif tool_id == 'nexus.recon.gobuster' and result.verification_method == 'gobuster_text_parsed':
        for hit in output.get('hits', []):
            if hit.get('status_code'):
                add('endpoint', hit.get('url') or output.get('target'), hit, hit.get('path'))
    elif tool_id == 'nexus.post.ssh_exec' and result.verification_method == 'ssh_exec_completed':
        target = output.get('target')
        add('access', target, {'transport': 'ssh', 'username': arguments.get('username')})
        command = output.get('command', '').strip()
        stdout = output.get('stdout', '').strip()
        if output.get('exit_status') == 0 and (
            (command == 'id' and re.fullmatch(r'uid=0\(root\) gid=\d+[^\n]*', stdout))
            or (command == 'id -u' and stdout == '0')
            or (command == 'whoami' and stdout == 'root')
        ):
            add('privilege', target, {'uid': 0, 'user': 'root'})
    elif tool_id == 'nexus.c2.sliver_loot' and result.verification_method == 'sliver_loot_recorded':
        loot = output.get('loot') or {}
        if loot.get('sha256'):
            add('loot', loot.get('loot_id') or loot.get('name'),
                {'sha256': loot['sha256'], 'size': loot.get('size')},loot.get('name'))
    return rows


def persist_assertions(assertions, context, tool_id):
    scope = context.scope
    if not scope or not context.store:
        return
    board = Blackboard(context.store)
    for item in assertions:
        board.record(tenant_id=context.tenant_id, engagement_id=scope.engagement_id,
                     fact_type=item['fact_type'], key=item['key'], value=item['value'],
                     source=tool_id, created_by='deterministic-verifier', verified=True,
                     asserted_by='verifier', verification_method=item['verification_method'],
                     invocation_id=item['invocation_id'])
