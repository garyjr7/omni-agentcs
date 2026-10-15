"""Trusted, narrow semantic parsers. Model/extension metadata is never promoted.

New parsers must establish the claimed post-condition, not merely successful
execution. Unsupported outputs remain inventory; they cannot advance phases.
"""
import re
from .blackboard import Blackboard

#: Flag-shaped tokens (``flag{fake_flag}``, ``flag{fake_flag}``, ``flag{fake_flag}``) found in the
#: output of a verified command execution. Keeping the prefixes explicit avoids
#: turning any brace-wrapped text into "loot".
FLAG_RE = re.compile(r"(?:THM|HTB|FLAG|flag|CTF|ctf)\{[^}\s\x00]{4,200}\}")

#: ``verification_method`` of the facts an accepted MSF session asserts (V1-24).
#: Distinct from the handler's ``session_established``: that one is the *result's*
#: method, this one is the *fact's*, so the planner can tell a session this engine
#: proved (window + target) from any other ``session`` fact.
MSF_SESSION_METHOD = "msf_session_established"

#: ``verification_method`` of the msf_exploit result that owns a provenanced
#: session (the only one this module promotes).
_MSF_SESSION_RESULT_METHOD = "session_established"

#: Separator of MSF's canonical session descriptor, ``<USER> @ <HOST>``
#: (``NT AUTHORITY\SYSTEM @ WIN-JO6REVNMMMP``).
_SESSION_INFO_SEPARATOR = " @ "

#: Windows identity queries whose output states the *invoking* account's own
#: group membership. ``whoami; hostname`` deliberately does not match: the marker
#: must come from an identity query, not from whatever else shares the line.
_WIN_IDENTITY_RE = re.compile(r"^whoami(\s|$)", re.IGNORECASE)

#: Markers of an administrative Windows group. The well-known SIDs are the
#: reliable half (names are localized); a wrong answer would need the querying
#: account to be in one of these groups, which is exactly the claim.
_WIN_ADMIN_RE = re.compile(
    r"(BUILTIN\\Administrators|Domain Admins|Enterprise Admins|Schema Admins|"
    r"S-1-5-32-544|S-1-5-21-\d+-\d+-\d+-512|S-1-5-21-\d+-\d+-\d+-519)",
    re.IGNORECASE,
)

#: ``net (local)group <group> /domain`` — a listing of the accounts inside an
#: administrative group. Only the domain database is consulted: a local group on
#: a member host proves nothing about the domain.
_WIN_GROUP_QUERY_RE = re.compile(
    r"^\s*net\s+(?:localgroup|group)\s+(?P<group>\"[^\"]+\"|'[^']+'|[^\s]+)\s+[^|;]*/domain\b",
    re.IGNORECASE,
)

#: Group names that, when listed by ``net … /domain``, mean "domain-level admin".
_WIN_ADMIN_GROUPS = frozenset(
    {
        "administrators",
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administradores",
        "administrateurs",
        "administratoren",
    }
)

#: A single-token Windows account name, e.g. ``tom`` or ``WINDOMAIN\\tom``.
_WIN_ACCOUNT_RE = re.compile(r"^[^\s()]{1,64}$")

#: ``Get-Content <path>`` / ``type <path>`` / ``cat <path>`` reading exactly one
#: literal file: no pipes, no wildcards, no loops, no redirections. Only this
#: shape lets the verifier attribute a flag to the path that was read.
_WIN_READ_RE = re.compile(
    r"^\s*(?:get-content|gc|type|cat)\s+(?P<path>\"[^\"]+\"|'[^']+'|[^\s|;<>]+)\s*$",
    re.IGNORECASE,
)


def _net_group_members(text):
    """Return the account rows of a ``net ... /domain`` group listing.

    Members live in the dashed block after ``Members``; the footer
    (``The command completed successfully.``) and anything after it are ignored.
    """
    members = []
    in_block = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            if in_block:
                break
            continue
        if len(line) >= 3 and set(line) <= {"-"}:
            in_block = True
            continue
        if not in_block:
            continue
        if line.lower().startswith("the command completed"):
            break
        account = line.lstrip("*").strip()
        if _WIN_ACCOUNT_RE.match(account):
            members.append(account)
    return members


def _session_owner(record):
    """Account named by an MSF session descriptor, or ``""`` when it names none.

    Only the canonical ``<USER> @ <HOST>`` shape counts. A record whose ``info``
    is a bare product word (``Meterpreter``) names no account, and an empty
    ``info`` -what msfrpcd answered when the session had just opened, measured in
    rerun 6- must never be read as a username.
    """
    if not isinstance(record, dict):
        return ""
    info = str(record.get("info") or "").strip()
    account, separator, _host = info.rpartition(_SESSION_INFO_SEPARATOR)
    if not separator:
        return ""
    return account.strip()


def _session_sid(result):
    """Numeric sid of the session, when the result exposes it.

    The sid is the ``session.list`` key; the handler's result carries the RPC
    ``job_id`` instead (a different number: 9 vs 2 in the measured run), so the
    key is read from the evidence when present and left null when not. Inventing
    it from the job id would be a lie about which session this is.
    """
    evidence = result.evidence if isinstance(result.evidence, dict) else {}
    sid = evidence.get("sid")
    return sid if isinstance(sid, int) and not isinstance(sid, bool) else None


def derive_assertions(tool_id, arguments, result, context):
    if not result.success or not context.invocation_id:
        return []
    output = result.output
    rows = []

    def add(kind, target, value, key=None, method=None):
        if not target:
            return
        rows.append(dict(fact_type=kind, target=str(target), key=str(key or target),
                         value=value, verified=True, asserted_by='verifier',
                         verification_method=method or result.verification_method,
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
    elif tool_id == 'nexus.pwn.ret2libc' and result.verification_method == 'ret2libc_root_command':
        target = output.get('target')
        add('privilege', target, {'uid': 0, 'user': 'root'})
        flag = output.get('flag')
        if flag:
            add('loot', flag, {'flag': flag, 'libc_base': output.get('libc_base')}, flag)
    elif tool_id == 'nexus.web.wp_enum' and result.verification_method == 'wp_enum_completed':
        findings = output.get('findings') or {}
        url = output.get('url')
        if findings.get('version'):
            add('web_app', url, {'product': 'wordpress', 'version': findings['version'],
                                 'source': findings.get('version_source')})
        for user in findings.get('users') or ():
            slug = user.get('slug')
            if slug:
                add('user', slug, {'username': slug, 'id': user.get('id'),
                                   'service': 'wordpress'}, f'wp:{slug}')
        for entry in findings.get('interesting') or ():
            if entry.get('id'):
                add('vulnerability', url, {'id': entry['id'], 'severity': entry.get('severity'),
                                           'detail': entry.get('detail')}, entry['id'])
        for probe in output.get('probes') or ():
            if probe.get('status') and probe.get('path'):
                add('endpoint', probe.get('path'), {'status': probe.get('status'),
                                                    'length': probe.get('length')},
                    f"{url}{probe.get('path')}")
    elif tool_id == 'nexus.post.pivot_bruteforce' and result.verification_method == 'pivot_credential_validated':
        # The credential was validated from the authorized host, against a form
        # that provably rejects a wrong password (both re-checked twice by the
        # remote harness). The pivoted endpoint itself is never in scope, so the
        # access fact is keyed on the SSH host that the scope really covers.
        host = output.get('target')
        for credential in output.get('valid_credentials') or ():
            username = credential.get('username')
            add('credential', host, {'username': username,
                                     'password': credential.get('password'),
                                     'service': 'http-pivot'},
                f"pivot:{username}@{output.get('form_url')}")
            add('access', host, {'transport': 'http-pivot', 'username': username,
                                 'endpoint': output.get('form_url')},
                f"http-pivot:{host}")
    elif tool_id == 'nexus.web.wp_bruteforce' and result.verification_method == 'wp_credential_validated':
        username = output.get('username')
        for credential in output.get('valid_credentials') or ():
            add('credential', username, {'username': credential.get('username'),
                                         'password': credential.get('password'),
                                         'service': 'wordpress'},
                f"wordpress:{username}")
            add('access', output.get('url'), {'transport': 'wp-admin', 'username': username},
                f"wp-admin:{username}")
    elif tool_id == 'nexus.web.wp_exec' and result.verification_method == 'wp_command_executed':
        target = output.get('url')
        add('access', target, {'transport': 'http', 'service': 'wordpress',
                               'theme': output.get('theme'), 'file': output.get('file')})
        for entry in output.get('outputs') or ():
            stdout = (entry.get('stdout') or '').strip()
            command = (entry.get('command') or '').strip()
            if command in ('id', 'id -u', 'whoami') and (
                re.search(r'uid=0\(root\)', stdout) or stdout in ('0', 'root')
            ):
                add('privilege', target, {'uid': 0, 'user': 'root'})
            for flag in FLAG_RE.findall(stdout):
                add('loot', flag, {'flag': flag, 'command': command, 'service': 'wordpress'}, flag)
    elif tool_id == 'nexus.win.winrm_exec' and result.verification_method == 'winrm_command_executed':
        # The channel itself is proven: the harness only reports
        # ``winrm_command_executed`` after NetExec authenticated *and* printed its
        # "Executed command" marker, so the credential used is an access fact.
        target = output.get('target')
        domain = arguments.get('domain') or ''
        username = arguments.get('username')
        add('access', target, {'transport': 'winrm', 'username': username,
                               'domain': domain or None})
        command = (output.get('command') or '').strip()
        stdout = (output.get('stdout') or '').strip()
        # Privilege is only claimed from an identity query that names an
        # administrative group; a listing of *other* accounts never promotes the
        # operator's own session.
        if _WIN_IDENTITY_RE.match(command) and _WIN_ADMIN_RE.search(stdout):
            add('privilege', target, {'username': username, 'domain': domain or None,
                                      'source': 'winrm:whoami'})
        # ``net (local)group <admin group> /domain`` names the accounts inside a
        # domain-administrative group; each member is privileged *in the domain*,
        # so the fact is keyed on the account, not on the host that enumerated it.
        query = _WIN_GROUP_QUERY_RE.match(command)
        if query:
            group = query.group('group').strip('"\'')
            if group.lower() in _WIN_ADMIN_GROUPS:
                for account in _net_group_members(stdout):
                    if account.lower() in _WIN_ADMIN_GROUPS:
                        continue
                    key = f"domain-admin:{account}@{domain}" if domain else f"domain-admin:{account}"
                    add('privilege', target, {'account': account, 'domain': domain or None,
                                              'group': group, 'source': 'winrm:net-group'},
                        key)
        # Loot is only attributed when the command read exactly one literal file.
        read = _WIN_READ_RE.match(command)
        if read:
            path = read.group('path').strip('"\'')
            for flag in FLAG_RE.findall(stdout):
                add('loot', flag, {'flag': flag, 'path': path, 'command': command,
                                   'service': 'winrm'}, path)
    elif tool_id == 'nexus.post.dpapi' and result.verification_method == 'dpapi_unwrapped':
        # The blob's own signature was verified before the material was released, so
        # the recovered key material is a proven fact (never the AP itself: only its
        # hash and the masterkey it belongs to).
        add('credential', output.get('master_key_guid') or 'dpapi-material',
            {'service': 'dpapi', 'master_key_guid': output.get('master_key_guid'),
             'material_sha256': output.get('material_sha256'),
             'crypt_algo': output.get('crypt_algo')},
            f"dpapi:{output.get('master_key_guid') or 'material'}")
    elif tool_id == 'nexus.post.dpapi' and result.verification_method == 'kdbx_opened':
        # ``kdbx_opened`` is only reported after the DPAPI-recovered material derived
        # the database key and every payload block hash was checked, so an entry's
        # secret is a verified credential and a flag-shaped one is loot.
        for entry in output.get('entries') or ():
            title = entry.get('title') or entry.get('group') or 'entry'
            password = entry.get('password') or ''
            if entry.get('username') or password:
                add('credential', title,
                    {'username': entry.get('username') or None,
                     'password': password or None, 'group': entry.get('group'),
                     'service': 'keepass'},
                    f"keepass:{entry.get('group')}/{title}")
            for flag in FLAG_RE.findall(password):
                add('loot', flag,
                    {'flag': flag, 'title': title, 'group': entry.get('group'),
                     'service': 'keepass'}, title)
    elif tool_id == 'nexus.recon.dns' and result.verification_method == 'dns_response_parsed':
        # A DNS answer is a server-provided record set, not an operator guess. Only
        # a flag-shaped token inside an observed record value is promoted to loot
        # (measured: the room's flag lived in a TXT record of the domain).
        server = output.get('server')
        for flag in output.get('flags') or ():
            add('loot', flag, {'flag': flag, 'record_type': output.get('record_type'),
                               'name': output.get('name'), 'server': server}, flag)
    elif (tool_id == 'nexus.exploit.msf_exploit'
          and result.verification_method == _MSF_SESSION_RESULT_METHOD):
        # A session the provenance verifier accepted (V1-24): the exploit really
        # ran against the engaged target and the session that appeared while the
        # job ran reports that same host. Measured in rerun 6
        # (run_66eb363ed2fd42bf9d30985b76bf3248): ms17_010_psexec opened a SYSTEM
        # Meterpreter, the handler verified it and `kernel_sessions` got its
        # first row -and the planner never saw any of it, because this function
        # asserted nothing for the tool and `exploitation` could not close.
        #
        # Only `session_established` promotes: `session_provenance_ambiguous`
        # (zero or several candidates in the window) and
        # `session_provenance_unverified` (a session reporting another host)
        # describe a session whose origin is not proven to be this job, so they
        # assert nothing about the engagement -the 9A verifier already decided
        # that, this module only stops contradicting it.
        record = output.get('session') if isinstance(output.get('session'), dict) else {}
        session_uuid = str(output.get('session_uuid') or record.get('uuid') or '')
        target = str(output.get('target') or record.get('session_host') or '')
        if session_uuid and target:
            via_exploit = str(record.get('via_exploit') or output.get('module') or '')
            owner = _session_owner(record)
            sid = _session_sid(result)
            add('session', target,
                {'session_uuid': session_uuid, 'via_exploit': via_exploit,
                 'target': target, 'user': owner or None, 'sid': sid},
                f'{target}:{session_uuid}', method=MSF_SESSION_METHOD)
            if owner:
                # Only a descriptor that names an account can substantiate the
                # access claim: the fact is keyed on that account, and without
                # one there is no identity to key it on.
                add('access', target,
                    {'kind': str(record.get('type') or ''), 'user': owner,
                     'via_exploit': via_exploit},
                    f'{target}:{owner}@{session_uuid}', method=MSF_SESSION_METHOD)
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
