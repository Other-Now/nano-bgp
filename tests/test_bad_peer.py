"""A scripted, misbehaving peer against one nano-bgp node.

Checks RFC 7606 behaviour on the wire: a malformed *attribute* withdraws the
routes in that UPDATE and keeps the session; a malformed *message* (NLRI can't
be located) resets the session with the right NOTIFICATION.
"""
import socket
import subprocess
import time

import pytest

import bgp_raw as raw
from lab import Lab, Node

PEER_IP, NANO_IP = "10.9.0.1", "10.9.0.0"


@pytest.fixture
def lone(nbgpd):
    nodes = {"dut": Node("dut", "nano", 65000, "10.255.9.1", networks=["192.168.9.0/24"],
                         neighbors=[(PEER_IP, 4200000099)])}
    lab = Lab(nodes, nbgpd)
    lab.build()
    subprocess.run(["ip", "netns", "add", "evil"], check=True)
    subprocess.run(["ip", "link", "add", "e0", "netns", "dut", "type", "veth", "peer", "name", "e0", "netns", "evil"],
                   check=True)
    for ns, ip in (("dut", NANO_IP), ("evil", PEER_IP)):
        subprocess.run(["ip", "-n", ns, "addr", "add", f"{ip}/31", "dev", "e0"], check=True)
        subprocess.run(["ip", "-n", ns, "link", "set", "e0", "up"], check=True)
        subprocess.run(["ip", "-n", ns, "link", "set", "lo", "up"], check=True)
    lab.start()
    yield lab
    lab.stop()
    subprocess.run(["ip", "netns", "del", "evil"])


def evil_socket():
    """A TCP connection to the DUT, opened from inside the 'evil' namespace."""
    import ctypes
    import os
    libc = ctypes.CDLL(None, use_errno=True)
    own = os.open("/proc/self/ns/net", os.O_RDONLY)
    tgt = os.open("/run/netns/evil", os.O_RDONLY)
    assert libc.setns(tgt, 0) == 0
    try:
        for _ in range(50):
            try:
                s = socket.create_connection((NANO_IP, 179), timeout=5, source_address=(PEER_IP, 0))
                return s
            except ConnectionRefusedError:  # nbgpd not listening yet
                time.sleep(0.1)
        raise TimeoutError("DUT never listened")
    finally:
        libc.setns(own, 0)
        os.close(own)
        os.close(tgt)


def connect(lab):
    """Open a session from the 'evil' namespace. Returns the socket once Established."""
    s = evil_socket()
    s.sendall(raw.open_msg(4200000099, 3, "10.255.9.99"))
    t, _ = raw.read_msg(s)
    assert t == 1  # their OPEN
    s.sendall(raw.keepalive())
    lab.wait(lambda: lab.sessions("dut")[PEER_IP] == "Established", timeout=5, what="Established")
    return s


def drain_until(s, want_type, timeout=5):
    s.settimeout(timeout)
    while True:
        t, body = raw.read_msg(s)
        if t == want_type:
            return body


def test_good_update_installs_route(lone):
    s = connect(lone)
    s.sendall(raw.update(["172.20.0.0/16"], as_path=[4200000099], next_hop=PEER_IP))
    lone.wait(lambda: "172.20.0.0/16" in lone.fib("dut"), timeout=5, what="route in FIB")
    assert lone.rib("dut")["172.20.0.0/16"] == [PEER_IP]
    s.close()


def test_bad_origin_is_treat_as_withdraw_and_session_survives(lone):
    s = connect(lone)
    s.sendall(raw.update(["172.20.0.0/16"], as_path=[4200000099], next_hop=PEER_IP))
    lone.wait(lambda: "172.20.0.0/16" in lone.rib("dut"), timeout=5, what="route")
    s.sendall(raw.update(["172.20.0.0/16"], origin=9, as_path=[4200000099], next_hop=PEER_IP))
    lone.wait(lambda: "172.20.0.0/16" not in lone.rib("dut"), timeout=5, what="withdrawn")
    time.sleep(0.3)
    peer = lone.nano("dut", "summary")["peers"][0]
    assert peer["state"] == "Established" and peer["treat_as_withdraw"] == 1
    assert "172.20.0.0/16" not in lone.fib("dut")
    s.close()


def test_first_as_mismatch_is_rejected(lone):
    s = connect(lone)
    s.sendall(raw.update(["172.21.0.0/16"], as_path=[64512, 4200000099], next_hop=PEER_IP))
    time.sleep(0.5)
    assert "172.21.0.0/16" not in lone.rib("dut")
    assert lone.sessions("dut")[PEER_IP] == "Established"
    s.close()


def test_as_loop_is_dropped_silently(lone):
    s = connect(lone)
    s.sendall(raw.update(["172.22.0.0/16"], as_path=[4200000099, 65000], next_hop=PEER_IP))
    time.sleep(0.5)
    assert "172.22.0.0/16" not in lone.rib("dut")
    peer = lone.nano("dut", "summary")["peers"][0]
    assert peer["state"] == "Established" and peer["treat_as_withdraw"] == 0
    s.close()


def test_unlocatable_nlri_resets_with_notification(lone):
    s = connect(lone)
    # withdrawn-routes length says 200 bytes, the message has 0
    s.sendall(raw.msg(2, b"\x00\xc8\x00\x00"))
    body = drain_until(s, 3)
    assert (body[0], body[1]) == (3, 1)  # UPDATE error / malformed attribute list
    lone.wait(lambda: lone.sessions("dut")[PEER_IP] != "Established", timeout=3, what="session down")


def test_bad_peer_as_in_open(lone):
    s = evil_socket()
    s.sendall(raw.open_msg(4200000098, 3, "10.255.9.99"))
    body = drain_until(s, 3)
    assert (body[0], body[1]) == (2, 2)  # OPEN error / bad peer AS
    s.close()


def test_hold_timer_expiry(lone):
    s = connect(lone)
    # Say nothing more. Negotiated hold is 3s; expect HoldTimerExpired (4/0).
    t0 = time.monotonic()
    body = drain_until(s, 3, timeout=6)
    elapsed = time.monotonic() - t0
    assert body[0] == 4
    assert 2.0 < elapsed < 4.5, elapsed
