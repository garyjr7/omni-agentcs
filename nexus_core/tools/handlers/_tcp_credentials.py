"""Bounded prompt/response credential probe executed only inside the sandbox.

TCP has no universal authentication protocol. Callers must specify literal
prompts and a positive success marker; absence of failure is never success.
"""
TCP_CREDENTIAL_SCRIPT = r'''
import json, socket, sys, time
host, port, username, wordlist, password_prompt, success, login_prompt, telnet = sys.argv[1:9]
found = []
attempts = 0
errors = 0

def receive(sock, marker):
    data = bytearray()
    deadline = time.monotonic() + 5
    pending = bytearray()
    while marker not in data:
        if time.monotonic() >= deadline or len(data) >= 16384:
            raise TimeoutError('prompt unavailable')
        chunk = sock.recv(1024)
        if not chunk:
            raise EOFError('connection closed')
        pending.extend(chunk)
        while pending:
            if telnet == '1' and pending[0] == 255:
                if len(pending) < 2:
                    break
                command = pending[1]
                if command == 255:
                    data.append(255)
                    del pending[:2]
                elif command in (251, 252, 253, 254):
                    if len(pending) < 3:
                        break
                    if command in (251, 253):
                        sock.sendall(bytes([255, 254 if command == 251 else 252, pending[2]]))
                    del pending[:3]
                elif command == 250:
                    end = pending.find(b'\xff\xf0', 2)
                    if end < 0:
                        if len(pending) > 4096:
                            raise ValueError('oversized telnet negotiation')
                        break
                    del pending[:end+2]
                else:
                    del pending[:2]
            else:
                data.append(pending.pop(0))
    return bytes(data)

with open(wordlist, encoding='utf-8') as stream:
    for line in stream:
        password = line.rstrip('\r\n')
        attempts += 1
        try:
            with socket.create_connection((host, int(port)), timeout=5) as sock:
                if login_prompt:
                    receive(sock, login_prompt.encode())
                    sock.sendall(username.encode() + b'\r\n')
                receive(sock, password_prompt.encode())
                sock.sendall(password.encode() + b'\r\n')
                receive(sock, success.encode())
                found.append({'host': host, 'username': username, 'password': password})
                break
        except (OSError, EOFError, ValueError):
            errors += 1
        time.sleep(0.2)
print(json.dumps({'valid_credentials': found, 'attempts': attempts, 'errors': errors}))
'''
