"""Measurements on the mixed fabric. Writes JSON + a text table to OUT_DIR.

    scripts/run.sh python3 tools/bench.py build/nbgpd results/local [reps]

1. link-failure convergence: spine1<->leaf3 goes down; how long until the
   *kernel FIB* on other leaves drops to one next hop for 192.168.3.0/24.
   With fast-external-failover on (nano + FRR default) and off (hold timer, 3 s).
2. withdrawal propagation: a leaf stops announcing its prefix; how long until
   the route is gone from the kernel FIB of the other leaves. nano -> FRR and
   FRR -> nano.
3. route scale: FRR originates N prefixes to a nano-bgp node (and the reverse);
   time from Established until all N are in the receiver's table.

Timing source for 1 and 2 is `ip -ts monitor route` in each observer namespace,
i.e. the kernel's own route events, identical for FRR and nano-bgp nodes.
"""
import json
import os
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
from lab import Lab, Node, sh, spine_leaf  # noqa: E402

NBGPD, OUT = sys.argv[1], sys.argv[2]
REPS = int(sys.argv[3]) if len(sys.argv) > 3 else 5
SCALE_N = int(os.environ.get("SCALE_N", "100000"))
os.makedirs(OUT, exist_ok=True)


class Monitor:
    """`ip -ts monitor route` in one namespace; find the first event matching a regex after t0."""

    def __init__(self, ns):
        self.p = subprocess.Popen(["ip", "-n", ns, "-ts", "monitor", "route"], stdout=subprocess.PIPE, text=True)
        os.set_blocking(self.p.stdout.fileno(), False)
        self.lines = []
        time.sleep(0.2)

    def poll(self):
        while True:
            line = self.p.stdout.readline()
            if not line:
                break
            m = re.match(r"\[(\d{4}-\d\d-\d\dT[\d:.]+)\]\s*(.*)", line)
            if m:
                ts = datetime.fromisoformat(m.group(1)).timestamp()
                self.lines.append((ts, m.group(2)))

    def first_after(self, t0, pattern, timeout=15):
        rx = re.compile(pattern)
        end = time.time() + timeout
        while time.time() < end:
            self.poll()
            for ts, text in self.lines:
                if ts >= t0 and rx.search(text):
                    return ts - t0
            time.sleep(0.01)
        return None

    def close(self):
        self.p.kill()


def summarize(xs):
    xs = [x * 1000 for x in xs if x is not None]
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "median_ms": round(statistics.median(xs), 1), "min_ms": round(min(xs), 1),
            "max_ms": round(max(xs), 1)}


def fabric_converged(lab):
    return all(lab.rib(n) == lab.expected_rib(n) for n in lab.nodes)


def single_nh_via(lab, node, pfx):
    r = lab.fib(node).get(pfx)
    return r is not None and len(r) == 1


def set_silent(spine, leaf, on):
    """Drop everything both ways on the link but keep carrier up: what a hung
    line card or a one-way fibre fault looks like. Only the hold timer sees it."""
    s, l = spine[5:], leaf[4:]
    for ns, dev in ((spine, f"l{l}"), (leaf, f"s{s}")):
        if on:
            sh("tc", "qdisc", "add", "dev", dev, "clsact", ns=ns)
            sh("tc", "filter", "add", "dev", dev, "egress", "matchall", "action", "drop", ns=ns)
        else:
            sh("tc", "qdisc", "del", "dev", dev, "clsact", ns=ns)


def link_failure(lab, spine, mode):
    """Fail spine<->leaf3 ('down' = carrier loss, 'silent' = packets dropped).
    Observers: until 192.168.3.0/24 is single-path via the other spine."""
    other = "2" if spine == "spine1" else "1"
    obs = {"leaf1 (nano)": "leaf1", "leaf2 (FRR)": "leaf2", "leaf4 (FRR)": "leaf4"}
    res = {k: [] for k in obs}
    for rep in range(REPS):
        mons = {k: Monitor(ns) for k, ns in obs.items()}
        t0 = time.time()
        if mode == "down":
            lab.link(spine, "leaf3", up=False)
        else:
            set_silent(spine, "leaf3", True)
        for k, m in mons.items():
            ns = obs[k]
            gw = f"10.{other}.{ns[4:]}.0"
            res[k].append(m.first_after(t0, rf"^192\.168\.3\.0/24 .*via {re.escape(gw)} dev s{other}"))
            m.close()
        if mode == "down":
            lab.link(spine, "leaf3", up=True)
        else:
            set_silent(spine, "leaf3", False)
        lab.wait(lambda: fabric_converged(lab), timeout=30, what="re-converge")
        time.sleep(1.0)
    return {k: {"raw_s": v, **summarize(v)} for k, v in res.items()}


def withdrawal(lab):
    out = {}
    cases = [
        ("nano leaf1 -> observers", "leaf1", "192.168.1.0/24",
         {"spine1 (FRR, 1 hop)": "spine1", "spine2 (nano, 1 hop)": "spine2",
          "leaf3 (nano, 2 hops)": "leaf3", "leaf2 (FRR, 2 hops)": "leaf2"}),
        ("FRR leaf2 -> observers", "leaf2", "192.168.2.0/24",
         {"spine1 (FRR, 1 hop)": "spine1", "spine2 (nano, 1 hop)": "spine2",
          "leaf1 (nano, 2 hops)": "leaf1", "leaf4 (FRR, 2 hops)": "leaf4"}),
    ]
    for label, origin, pfx, obs in cases:
        res = {k: [] for k in obs}
        for rep in range(REPS):
            mons = {k: Monitor(ns) for k, ns in obs.items()}
            t0 = time.time()
            if lab.nodes[origin].kind == "nano":
                lab.nano(origin, f"withdraw {pfx}")
            else:
                lab.vtysh(origin, f"configure terminal\nrouter bgp {lab.nodes[origin].asn}\n"
                                  f"address-family ipv4 unicast\nno network {pfx}")
            for k, m in mons.items():
                res[k].append(m.first_after(t0, rf"^Deleted {re.escape(pfx)}"))
                m.close()
            if lab.nodes[origin].kind == "nano":
                lab.nano(origin, f"announce {pfx}")
            else:
                lab.vtysh(origin, f"configure terminal\nrouter bgp {lab.nodes[origin].asn}\n"
                                  f"address-family ipv4 unicast\nnetwork {pfx}")
            lab.wait(lambda: fabric_converged(lab), timeout=30, what="re-converge")
            time.sleep(0.5)
        out[label] = {k: {"raw_s": v, **summarize(v)} for k, v in res.items()}
    return out


def scale(direction, fib):
    """direction 'frr->nano' or 'nano->frr'. One FRR node, one nano node, one link."""
    sender_kind, receiver_kind = direction.split("->")
    nets = [f"{10 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24" for i in range(SCALE_N)]
    a = Node("src", sender_kind, 65101, "10.255.5.1", networks=[], neighbors=[("10.5.0.1", 65102)])
    b = Node("dst", receiver_kind, 65102, "10.255.5.2", neighbors=[("10.5.0.0", 65101)])
    lab = Lab({"src": a, "dst": b}, NBGPD, hold=9, keepalive=3)
    lab.build()
    sh("ip", "link", "add", "x", "netns", "src", "type", "veth", "peer", "name", "x", "netns", "dst")
    sh("ip", "-n", "src", "addr", "add", "10.5.0.0/31", "dev", "x")
    sh("ip", "-n", "dst", "addr", "add", "10.5.0.1/31", "dev", "x")
    sh("ip", "-n", "src", "link", "set", "x", "up")
    sh("ip", "-n", "dst", "link", "set", "x", "up")
    a.networks = nets
    if b.kind == "nano":
        orig = lab.nano_conf
        lab.nano_conf = lambda n: orig(n).replace("fib on", "fib on" if fib else "fib off")
    try:
        # Start the receiver first, then the sender, so the clock starts at Established.
        lab.start_node(b)
        time.sleep(0.5)
        lab.start_node(a)
        if b.kind == "nano":
            def done():
                s = lab.nano("dst", "summary")
                p = s["peers"][0]
                return (p["up_ms"], s["fib_ops"]) if s["loc_rib"] >= SCALE_N and p["state"] == "Established" else None
            up_ms, fib_ops = lab.wait(done, timeout=300, interval=0.02, what="all routes at nano")
            secs = up_ms / 1000
            n_kernel = len(sh("ip", "-n", "dst", "route", "show", "proto", "bgp").splitlines())
            extra = {"fib_ops": fib_ops, "kernel_routes": n_kernel}
        else:
            # FRR's peerUptimeMsec only has 1 s resolution, so time it ourselves:
            # first poll that sees Established -> first poll that sees all N.
            # Resolution is one vtysh round trip (reported as poll_ms).
            t_est = None
            polls = []

            def done():
                nonlocal t_est
                t = time.monotonic()
                j = lab.frr_json("dst", "show bgp ipv4 unicast summary")
                polls.append(time.monotonic() - t)
                p = next(iter(j["peers"].values()))
                if p.get("state") == "Established" and t_est is None:
                    t_est = t
                return t if t_est is not None and p.get("pfxRcd", 0) >= SCALE_N else None
            t_done = lab.wait(done, timeout=300, interval=0.0, what="all routes at FRR")
            secs = t_done - t_est
            extra = {"poll_ms": round(1000 * statistics.median(polls), 1)}
        return {"routes": SCALE_N, "seconds": round(secs, 3), "routes_per_s": round(SCALE_N / secs), **extra}
    finally:
        lab.stop()


def main():
    if os.environ.get("ONLY") == "scale":
        r = {k: scale(*a) for k, a in (("frr->nano (fib on)", ("frr->nano", True)),
                                         ("frr->nano (fib off)", ("frr->nano", False)),
                                         ("nano->frr", ("nano->frr", True)),
                                         ("nano->nano (fib on)", ("nano->nano", True)))}
        print(json.dumps(r, indent=1))
        with open(os.path.join(OUT, "scale.json"), "w") as f:
            json.dump(r, f, indent=1)
        return
    results = {"reps": REPS}
    lab = Lab(spine_leaf(), NBGPD)
    try:
        lab.build()
        lab.start()
        lab.wait(lab.all_established, timeout=30)
        lab.wait(lambda: fabric_converged(lab), timeout=15)
        time.sleep(1)
        for spine in ("spine1", "spine2"):
            for mode in ("down", "silent"):
                results[f"link_{mode}_{spine}"] = link_failure(lab, spine, mode)
        results["withdrawal"] = withdrawal(lab)
    finally:
        lab.stop()
    results["scale"] = {
        "frr->nano (fib on)": scale("frr->nano", True),
        "frr->nano (fib off)": scale("frr->nano", False),
        "nano->frr": scale("nano->frr", True),
        "nano->nano (fib on)": scale("nano->nano", True),
    }
    with open(os.path.join(OUT, "bench.json"), "w") as f:
        json.dump(results, f, indent=1)

    lines = [f"reps per case: {REPS}; hold 3 s / keepalive 1 s; times are kernel FIB events (ip -ts monitor route)",
             "FRR-side withdrawals start when vtysh is launched, so they include vtysh's own run time", ""]
    titles = {"down": "carrier down", "silent": "silent drop, carrier up (hold timer)"}
    for spine, who in (("spine1", "FRR"), ("spine2", "nano")):
        for mode in ("down", "silent"):
            lines.append(f"Link {spine} ({who})<->leaf3: {titles[mode]}  (until 192.168.3.0/24 is single-path)")
            for obs, r in results[f"link_{mode}_{spine}"].items():
                lines.append(f"  {obs:<22} median {r.get('median_ms')} ms  "
                             f"[min {r.get('min_ms')}, max {r.get('max_ms')}]  n={r['n']}")
            lines.append("")
    for label, obs in results["withdrawal"].items():
        lines.append(f"Withdrawal {label}  (until the route is deleted from the kernel)")
        for o, r in obs.items():
            lines.append(f"  {o:<22} median {r.get('median_ms')} ms  [min {r.get('min_ms')}, max {r.get('max_ms')}]  n={r['n']}")
        lines.append("")
    lines.append(f"Route scale ({SCALE_N} prefixes, one session, from Established)")
    for k, r in results["scale"].items():
        note = f"kernel routes {r['kernel_routes']}" if "kernel_routes" in r else f"(poll resolution {r.get('poll_ms')} ms)"
        lines.append(f"  {k:<20} {r['seconds']} s  = {r['routes_per_s']} routes/s  {note}")
    txt = "\n".join(lines) + "\n"
    with open(os.path.join(OUT, "bench.txt"), "w") as f:
        f.write(txt)
    print(txt)


main()
