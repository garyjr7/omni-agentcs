"""SEC-01: the bwrap + socat egress bridge and its cleanup contract."""

from __future__ import annotations

import asyncio
import shutil

import pytest

from nexus_core.kernel import egress_bridge as bridge_module
from nexus_core.kernel.egress_bridge import (
    PROXYCHAINS_CONFIG,
    SANDBOX_SOCKET,
    EgressBridge,
    EgressBridgeUnavailable,
    bridge_available,
)

pytestmark = pytest.mark.unit

requires_bridge = pytest.mark.skipif(
    not bridge_available(), reason="bwrap/socat not installed"
)
requires_socat = pytest.mark.skipif(
    shutil.which("socat") is None, reason="socat not installed"
)
requires_nmap = pytest.mark.skipif(
    not all(shutil.which(name) for name in ("bwrap", "socat", "proxychains4", "nmap")),
    reason="bwrap/socat/proxychains4/nmap not installed",
)


def test_bwrap_command_isolates_the_network_and_binds_one_socket(tmp_path):
    bridge = EgressBridge(proxy_port=9050, socket_path=tmp_path / "egress.sock")
    argv = bridge.build_bwrap_cmd("nmap -sV 10.0.0.5")
    assert argv[0] == shutil.which("bwrap")
    assert "--unshare-net" in argv and "--unshare-pid" in argv
    assert "--die-with-parent" in argv
    bind = argv.index("--bind")
    assert argv[bind + 1] == str(tmp_path / "egress.sock")
    assert argv[bind + 2] == SANDBOX_SOCKET
    mounts = [argv[index + 1] for index, value in enumerate(argv) if value == "--tmpfs"]
    # /run must be writable or bwrap cannot create the socket mount point.
    assert "/run" in mounts and "/tmp" in mounts
    assert argv[argv.index("ALL_PROXY") + 1] == bridge.proxy_url
    assert bridge.proxy_url.startswith("socks5h://127.0.0.1:")
    # The command is the sandbox's foreground process, so its code is bwrap's.
    assert argv[-3] == "bash" and argv[-2] == "-c"
    assert argv[-1].rstrip().endswith("nmap -sV 10.0.0.5")
    assert "trap 'kill $spid" in argv[-1]


def test_building_the_command_requires_a_started_bridge():
    with pytest.raises(EgressBridgeUnavailable):
        EgressBridge().build_bwrap_cmd("true")


async def test_start_fails_closed_without_socat(monkeypatch, tmp_path):
    real_which = shutil.which
    monkeypatch.setattr(
        bridge_module.shutil,
        "which",
        lambda name: None if name == "socat" else real_which(name),
    )
    bridge = EgressBridge(socket_path=tmp_path / "egress.sock")
    with pytest.raises(EgressBridgeUnavailable, match="socat"):
        await bridge.start()
    assert bridge.socket_path is None or not bridge.socket_path.exists()


def test_proxychains_command_writes_the_conf_and_wraps(tmp_path):
    bridge = EgressBridge(socket_path=tmp_path / "egress.sock")
    argv = bridge.build_bwrap_cmd("nmap -sT 10.0.0.5", proxychains=True)
    script = argv[-1]
    assert "[ProxyList]" in PROXYCHAINS_CONFIG and "socks5 127.0.0.1 1080" in PROXYCHAINS_CONFIG
    assert "quiet_mode" in PROXYCHAINS_CONFIG
    assert "cat > /tmp/omni-proxychains.conf" in script
    assert "proxychains4 -f /tmp/omni-proxychains.conf" in script
    assert "bash -c" in script and "nmap -sT 10.0.0.5" in script


def test_workspace_is_bound_read_write(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    bridge = EgressBridge(socket_path=tmp_path / "egress.sock")
    argv = bridge.build_bwrap_cmd("true", workspace=workspace)
    pairs = [
        (argv[index + 1], argv[index + 2])
        for index, value in enumerate(argv) if value == "--bind"
    ]
    assert (str(workspace), str(workspace)) in pairs
    assert argv[argv.index("HOME") + 1] == "/tmp/omni-home"


@requires_nmap
async def test_nmap_connect_scan_travels_through_the_scope_proxy():
    from nexus_core.kernel import egress

    async def banner(reader, writer):
        writer.write(b"SSH-2.0-test\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(banner, "127.0.0.1", 0)
    target_port = int(server.sockets[0].getsockname()[1])

    class _Allow:
        def __init__(self) -> None:
            self.calls: list[tuple[str, int]] = []

        def authorize(self, host, port):
            self.calls.append((host, port))
            return egress.EgressDecision(
                allowed=True, host=host, port=port,
                connect_ip="127.0.0.1", matched_rule="test",
            )

    authorizer = _Allow()
    proxy = egress.Socks5EgressProxy(authorizer, bind_host="127.0.0.1", bind_port=0)
    await proxy.start()
    bridge = EgressBridge(proxy_port=proxy.address[1])
    try:
        async with bridge:
            stdout, stderr, code = await bridge.run(
                # Nested ``bash -c`` on purpose: the preload must reach the
                # grandchild, or the egress mode has a trivial bypass.
                # ``-n`` avoids nmap's internal resolver: proxychains intercepts
                # UDP DNS and nmap's massdns asserts when it cannot complete it.
                f"bash -c 'nmap -sT -Pn -n -p {target_port} 192.0.2.1'",
                proxychains=True,
                timeout=90,
            )
        assert code == 0, stderr
        assert f"{target_port}/tcp" in stdout and "open" in stdout
        assert ("192.0.2.1", target_port) in authorizer.calls
    finally:
        await proxy.close()
        server.close()
        await server.wait_closed()


@requires_socat
async def test_stop_is_idempotent_and_removes_the_socket():
    bridge = EgressBridge(proxy_port=1)
    await bridge.start()
    socket = bridge.socket_path
    assert socket is not None and socket.exists()
    await bridge.stop()
    await bridge.stop()
    assert not socket.exists()
    assert bridge.socket_path is None


@requires_bridge
async def test_bridge_tunnels_to_the_host_and_blocks_direct_egress():
    async def upper_echo(reader, writer):
        try:
            while chunk := await reader.read(1024):
                writer.write(chunk.upper())
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(upper_echo, "127.0.0.1", 0)
    proxy_port = int(server.sockets[0].getsockname()[1])
    bridge = EgressBridge(proxy_port=proxy_port)
    try:
        async with bridge:
            assert bridge.socket_path is not None
            directory = bridge.socket_path.parent
            token = directory.name
            tunneled = (
                "python3 -c 'import socket; "
                's=socket.create_connection(("127.0.0.1",1080),timeout=5); '
                's.sendall(b"ping"); print(s.recv(64).decode()); s.close()\''
            )
            stdout, stderr, code = await bridge.run(tunneled, timeout=30)
            assert code == 0, stderr
            assert "PING" in stdout

            blocked = (
                "python3 -c 'import socket; "
                'socket.create_connection(("1.1.1.1",80),timeout=3)\''
            )
            _, error, blocked_code = await bridge.run(blocked, timeout=30)
            assert blocked_code != 0
            assert "Network is unreachable" in error

            _, _, exit_code = await bridge.run("exit 7", timeout=30)
            assert exit_code == 7
        assert not directory.exists()
        probe = await asyncio.create_subprocess_exec(
            "pgrep", "-af", token,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        remaining, _ = await probe.communicate()
        assert token not in remaining.decode()
    finally:
        await bridge.stop()
        server.close()
        await server.wait_closed()
