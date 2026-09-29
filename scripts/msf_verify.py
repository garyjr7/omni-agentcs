"""Verify the local MessagePack service through curl without printing secrets."""

import os
import subprocess
import sys

import msgpack


def normalize(value):
    # Ruby encodes binary strings as MessagePack bin, including map keys.
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {normalize(key): normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value


def rpc(arguments):
    response = subprocess.run(
        [
            "curl", "--silent", "--show-error", "--include", "--noproxy", "*",
            "--max-time", "10", "--header", "Content-Type: binary/message-pack",
            "--data-binary", "@-", "http://127.0.0.1:55552/api/",
        ],
        input=msgpack.packb(arguments, use_bin_type=True),
        capture_output=True,
        check=False,
    )
    if response.returncode:
        sys.exit(f"ERROR: curl terminó con código {response.returncode}; comprobar servicio y puerto.")
    headers, separator, body = response.stdout.partition(b"\r\n\r\n")
    if not separator or headers.split(b"\r\n", 1)[0].split()[1:2] != [b"200"]:
        sys.exit("ERROR: el servicio no devolvió HTTP 200.")
    try:
        result = normalize(msgpack.unpackb(body, raw=False))
    except (ValueError, TypeError, msgpack.UnpackException):
        sys.exit("ERROR: respuesta MessagePack inválida.")
    if not isinstance(result, dict) or result.get("error"):
        sys.exit("ERROR: RPC devolvió un error; respuesta omitida para proteger credenciales.")
    return result


def main():
    password = os.environ.get("MSFRPC_PASSWORD") or os.environ.get("MSF_RPC_PASSWORD")
    if not password:
        sys.exit("ERROR: falta MSFRPC_PASSWORD o MSF_RPC_PASSWORD.")
    login = rpc(["auth.login", "msf", password])
    if login.get("result") != "success" or not login.get("token"):
        sys.exit("ERROR: auth.login no devolvió success y token.")
    print("curl: HTTP 200; transporte: MessagePack; endpoint: /api/")
    print("auth.login: success; token: [REDACTED]")
    version = rpc(["core.version", login["token"]])
    print(f"core.version: {version.get('version', 'sin versión')}")
    # The temporary login token expires under the daemon's default timeout.


if __name__ == "__main__":
    main()
