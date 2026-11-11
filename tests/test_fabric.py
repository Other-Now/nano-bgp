"""Interop tests on the mixed nano-bgp / FRR leaf-spine fabric.

Each test leaves the fabric as it found it (all links up, all prefixes announced),
and checks convergence the same way: every node's BGP table equals the table
computed from the topology, and on every node the kernel FIB equals the table.
"""
import signal
import subprocess
import time

import pytest


# The kernel FIB is checked on nano-bgp nodes always, and on FRR nodes only where
# asked: FRR 8.4.4's zebra loses an ECMP member after a link flap (see
# test_frr_zebra_fib_after_link_flap), which is not what these tests are about.
def problems(lab, down=frozenset(), frr_fib=False):
    out = []
    for n in lab.nodes:
        want = lab.expected_rib(n, down)
        got = lab.rib(n)
        if got != want:
            out.append(f"{n} rib: got {got} want {want}")
        if lab.nodes[n].kind == "frr" and not frr_fib:
            continue
        fib_want = {p: nh for p, nh in want.items() if nh != ["local"]}
        fib = lab.fib(n)
        if fib != fib_want:
            out.append(f"{n} fib: got {fib} want {fib_want}")
    return out


def converged(lab, down=frozenset(), frr_fib=False):
    return not problems(lab, down, frr_fib)


def wait_converged(lab, down=frozenset(), timeout=20, frr_fib=False):
    try:
        lab.wait(lambda: converged(lab, down, frr_fib), timeout=timeout, what="convergence")
    except TimeoutError:
        pytest.fail("not converged:\n" + "\n".join(problems(lab, down, frr_fib)))


def test_all_sessions_established(fabric):
    for n in fabric.nodes:
        st = fabric.sessions(n)
        assert set(st.values()) == {"Established"}, (n, st)


def test_tables_and_fib_match_topology(fabric):
    assert converged(fabric, frr_fib=True), problems(fabric, frr_fib=True)


def test_four_octet_asns_in_paths(fabric):
    # leaf1 (nano) learns leaf2's prefix through FRR spine1 and nano spine2.
    r = fabric.nano("leaf1", "route 192.168.2.0/24")["192.168.2.0/24"]
    assert r["as_path"] == "65000 4200000002"
    # FRR leaf2 learns leaf1's prefix with nano-bgp's 4-octet AS intact.
    j = fabric.frr_json("leaf2", "show bgp ipv4 unicast 192.168.1.0/24")
    assert {p["aspath"]["string"] for p in j["paths"]} == {"65000 4200000001"}


def test_ecmp_dataplane_uses_both_spines(fabric):
    def tx(ifname):
        r = subprocess.run(["ip", "netns", "exec", "leaf1", "cat", f"/sys/class/net/{ifname}/statistics/tx_packets"],
                           capture_output=True, text=True, check=True)
        return int(r.stdout)
    # ping across: nano leaf1 -> FRR leaf2 and nano leaf3, sourced from the server subnet
    for dst in ("192.168.2.1", "192.168.3.1", "192.168.4.1"):
        r = subprocess.run(["ip", "netns", "exec", "leaf1", "ping", "-c", "1", "-W", "2", "-I", "192.168.1.1", dst],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"ping {dst}: {r.stdout}{r.stderr}"
    before = (tx("s1"), tx("s2"))
    code = ("import socket\n"
            "for port in range(20000, 20128):\n"
            "  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "  s.bind(('192.168.1.1', port)); s.sendto(b'x', ('192.168.3.1', 9)); s.close()\n")
    subprocess.run(["ip", "netns", "exec", "leaf1", "python3", "-c", code], check=True)
    after = (tx("s1"), tx("s2"))
    d1, d2 = after[0] - before[0], after[1] - before[1]
    assert d1 + d2 >= 128
    assert d1 > 16 and d2 > 16, f"128 flows split {d1}/{d2} over spine1/spine2"


@pytest.mark.parametrize("spine,leaf", [("spine1", "leaf3"), ("spine2", "leaf2")])
def test_link_failure_and_recovery(fabric, spine, leaf):
    """Link down: the sessions over it die (hold timer, or fast failover), the
    other leaves drop to one next hop. Link up: back to two."""
    fabric.link(spine, leaf, up=False)
    wait_converged(fabric, down={(spine, leaf)}, timeout=15)
    fabric.link(spine, leaf, up=True)
    wait_converged(fabric, timeout=20)


@pytest.mark.parametrize("failover", ["on", "off"])
def test_link_flap_shorter_than_hold_time(fabric, failover):
    """A flap shorter than the hold time. The kernel deletes every route through
    the downed device. With fast-failover on, the sessions over the link reset
    and re-learn everything; with it off, the session survives and only the FIB
    resync on link-up can bring the kernel routes back. Either way the FIB must
    end up complete (before the fix it never did: README, Findings)."""
    for n in ("spine2", "leaf1"):
        fabric.nano(n, f"fast-failover {failover}")
    flaps_before = {p["addr"]: p["flaps"] for p in fabric.nano("spine2", "summary")["peers"]}
    try:
        fabric.link("spine2", "leaf1", up=False)
        time.sleep(0.5)
        fabric.link("spine2", "leaf1", up=True)
        time.sleep(1.0)
        wait_converged(fabric, timeout=15)
        flaps = {p["addr"]: p["flaps"] for p in fabric.nano("spine2", "summary")["peers"]}
        reset = flaps["10.2.1.1"] > flaps_before["10.2.1.1"]
        assert reset == (failover == "on")
    finally:
        for n in ("spine2", "leaf1"):
            fabric.nano(n, "fast-failover on")


def test_withdraw_from_nano_reaches_frr(fabric):
    fabric.nano("leaf1", "withdraw 192.168.1.0/24")
    fabric.wait(lambda: "192.168.1.0/24" not in fabric.rib("leaf2") and
                "192.168.1.0/24" not in fabric.rib("spine1"), timeout=10, what="withdraw at FRR")
    fabric.nano("leaf1", "announce 192.168.1.0/24")
    wait_converged(fabric)


def test_withdraw_from_frr_reaches_nano(fabric):
    fabric.vtysh("leaf2", "configure terminal\nrouter bgp 4200000002\naddress-family ipv4 unicast\n"
                          "no network 192.168.2.0/24")
    fabric.wait(lambda: "192.168.2.0/24" not in fabric.rib("leaf1") and
                "192.168.2.0/24" not in fabric.fib("leaf1"), timeout=10, what="withdraw at nano")
    fabric.vtysh("leaf2", "configure terminal\nrouter bgp 4200000002\naddress-family ipv4 unicast\n"
                          "network 192.168.2.0/24")
    wait_converged(fabric)


def test_admin_shutdown_sends_cease_to_frr(fabric):
    fabric.nano("leaf3", "peer-down 10.1.3.0")
    fabric.wait(lambda: fabric.sessions("spine1")["10.1.3.1"] != "Established", timeout=5, what="spine1 sees down")
    j = fabric.frr_json("spine1", "show bgp neighbors 10.1.3.1")["10.1.3.1"]
    assert "Cease" in j.get("lastNotificationReason", "") or "Administrative" in str(j), j.get("lastNotificationReason")
    wait_converged(fabric, down={("spine1", "leaf3")})
    fabric.nano("leaf3", "peer-up 10.1.3.0")
    wait_converged(fabric)


def test_nano_kill9_and_restart(fabric):
    """kill -9: no NOTIFICATION, the kernel closes the TCP connections. The spines
    must drop leaf3's prefix; after restart, stale kernel routes are cleaned up
    and everything comes back."""
    n = fabric.nodes["leaf3"]
    fabric.stop_node(n, signal.SIGKILL)
    fabric.wait(lambda: "192.168.3.0/24" not in fabric.rib("spine1") and
                "192.168.3.0/24" not in fabric.rib("spine2"), timeout=10, what="spines drop leaf3")
    fabric.start_node(n)
    wait_converged(fabric, timeout=20)


@pytest.mark.xfail(reason="FRR 8.4.4 zebra: kernel shrinks the nexthop group on link down, "
                          "zebra never re-pushes it on link up (README, Findings)", strict=False)
def test_frr_zebra_fib_after_link_flap(fabric):
    fabric.link("spine2", "leaf2", up=False)
    wait_converged(fabric, down={("spine2", "leaf2")}, timeout=15)
    fabric.link("spine2", "leaf2", up=True)
    wait_converged(fabric, timeout=20)
    try:
        wait_converged(fabric, timeout=10, frr_fib=True)
    finally:
        # Put leaf2's FIB back for any later test: restarting zebra+bgpd re-pushes everything.
        n = fabric.nodes["leaf2"]
        fabric.stop_node(n)
        subprocess.run(["ip", "-n", "leaf2", "route", "flush", "proto", "bgp"])
        subprocess.run(["ip", "-n", "leaf2", "nexthop", "flush"])
        fabric.start_node(n)
        wait_converged(fabric, timeout=30, frr_fib=True)


@pytest.mark.xfail(reason="FRR 8.4.4 zebra: the kernel shrinks the nexthop group on link down and "
                          "zebra never re-pushes it on link up (README, Findings)", strict=False)
def test_frr_zebra_fib_after_link_flap(fabric):
    fabric.link("spine2", "leaf2", up=False)
    wait_converged(fabric, down={("spine2", "leaf2")}, timeout=15)
    fabric.link("spine2", "leaf2", up=True)
    wait_converged(fabric, timeout=20)
    try:
        wait_converged(fabric, timeout=10, frr_fib=True)
    finally:
        # Put leaf2's FIB back for any later test: restarting zebra+bgpd re-pushes everything.
        n = fabric.nodes["leaf2"]
        fabric.stop_node(n)
        subprocess.run(["ip", "-n", "leaf2", "route", "flush", "proto", "bgp"])
        subprocess.run(["ip", "-n", "leaf2", "nexthop", "flush"])
        fabric.start_node(n)
        wait_converged(fabric, timeout=30, frr_fib=True)
