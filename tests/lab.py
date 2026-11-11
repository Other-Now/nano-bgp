r"""A leaf-spine lab in network namespaces, mixing nano-bgp and FRR.

Must run inside scripts/run.sh (private /run, private network namespace).

    spine1 (FRR)    spine2 (nano)          AS 65000 (both spines)
       |  \  /  \  /  |
     leaf1 leaf2 leaf3 leaf4               AS 4200000001..4 (4-octet ASNs)
     nano  FRR   nano  FRR

Link spine s <-> leaf l is 10.s.l.0/31 (spine .0, leaf .1). Each leaf owns a
"server subnet" 192.168.l.0/24 (on lo) and advertises it. This is the
RFC 7938 design: eBGP everywhere, one AS for the spine layer.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
from dataclasses import dataclass, field

RUN = "/run/nbgp"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def sh(*cmd: str, check: bool = True, ns: str | None = None, capture: bool = True) -> str:
    if ns:
        cmd = ("ip", "netns", "exec", ns) + cmd
    r = subprocess.run(cmd, capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> {r.returncode}: {r.stderr.strip()}")
    return r.stdout if capture else ""


@dataclass
class Node:
    name: str
    kind: str  # "nano" | "frr"
    asn: int
    rid: str
    networks: list[str] = field(default_factory=list)
    neighbors: list[tuple[str, int]] = field(default_factory=list)  # (ip, asn)
    procs: list[subprocess.Popen] = field(default_factory=list)

    @property
    def dir(self) -> str:
        return f"{RUN}/{self.name}"


def spine_leaf(spines: int = 2, leaves: int = 4, nano: set[str] | None = None) -> dict[str, Node]:
    """The default topology. `nano` = names of nodes that run nano-bgp; the rest run FRR."""
    if nano is None:
        nano = {"spine2", "leaf1", "leaf3"}
    nodes: dict[str, Node] = {}
    for s in range(1, spines + 1):
        n = f"spine{s}"
        nodes[n] = Node(n, "nano" if n in nano else "frr", 65000, f"10.255.0.{s}")
    for l in range(1, leaves + 1):
        n = f"leaf{l}"
        nodes[n] = Node(n, "nano" if n in nano else "frr", 4200000000 + l, f"10.255.1.{l}",
                        networks=[f"192.168.{l}.0/24"])
    for s in range(1, spines + 1):
        for l in range(1, leaves + 1):
            nodes[f"spine{s}"].neighbors.append((f"10.{s}.{l}.1", nodes[f"leaf{l}"].asn))
            nodes[f"leaf{l}"].neighbors.append((f"10.{s}.{l}.0", 65000))
    return nodes


class Lab:
    def __init__(self, nodes: dict[str, Node], nbgpd: str, hold: int = 3, keepalive: int = 1,
                 zebra: bool = True, extra_frr: dict[str, str] | None = None):
        self.nodes = nodes
        self.nbgpd = nbgpd
        self.hold = hold
        self.keepalive = keepalive
        self.zebra = zebra
        self.extra_frr = extra_frr or {}
        self.links: list[tuple[str, str, str, str]] = []  # (a, a_ip, b, b_ip)

    # ------------------------------------------------------------ build
    def build(self) -> None:
        os.makedirs(RUN, exist_ok=True)
        for n in self.nodes.values():
            shutil.rmtree(n.dir, ignore_errors=True)
            os.makedirs(n.dir)
            sh("ip", "netns", "add", n.name)
            sh("ip", "link", "set", "lo", "up", ns=n.name)
            for net in n.networks:  # the server subnet, on lo
                ip = net.split("/")[0].rsplit(".", 1)[0] + ".1/24"
                sh("ip", "addr", "add", ip, "dev", "lo", ns=n.name)
        for name, n in self.nodes.items():
            if not name.startswith("spine"):
                continue
            s = name[5:]
            for ip, _ in n.neighbors:
                l = ip.split(".")[2]
                leaf = f"leaf{l}"
                a_if, b_if = f"l{l}", f"s{s}"
                sh("ip", "link", "add", a_if, "netns", name, "type", "veth", "peer", "name", b_if, "netns", leaf)
                sh("ip", "addr", "add", f"10.{s}.{l}.0/31", "dev", a_if, ns=name)
                sh("ip", "addr", "add", f"10.{s}.{l}.1/31", "dev", b_if, ns=leaf)
                sh("ip", "link", "set", a_if, "up", ns=name)
                sh("ip", "link", "set", b_if, "up", ns=leaf)
                self.links.append((name, a_if, leaf, b_if))
        for n in self.nodes.values():
            # ECMP: hash on L4 ports too, so different flows can take different spines.
            sh("sysctl", "-qw", "net.ipv4.fib_multipath_hash_policy=1", ns=n.name, check=False)
            sh("sysctl", "-qw", "net.ipv4.ip_forward=1", ns=n.name)

    def start(self) -> None:
        for n in self.nodes.values():
            self.start_node(n)

    def start_node(self, n: Node) -> None:
        if n.kind == "nano":
            conf = f"{n.dir}/nbgpd.conf"
            with open(conf, "w") as f:
                f.write(self.nano_conf(n))
            log = open(f"{n.dir}/nbgpd.log", "a")
            n.procs = [subprocess.Popen(["ip", "netns", "exec", n.name, self.nbgpd, conf],
                                        stdout=log, stderr=subprocess.STDOUT)]
        else:
            conf = f"{n.dir}/bgpd.conf"
            with open(conf, "w") as f:
                f.write(self.frr_conf(n))
            log = open(f"{n.dir}/frr.out", "a")
            procs = []
            zs = f"{n.dir}/zserv.api"
            if self.zebra:
                zc = f"{n.dir}/zebra.conf"
                with open(zc, "w") as f:
                    f.write(f"hostname {n.name}\n")
                procs.append(subprocess.Popen(
                    ["ip", "netns", "exec", n.name, "zebra", "-u", "root", "-g", "root", "-f", zc,
                     "-i", f"{n.dir}/zebra.pid", "-z", zs, "--vty_socket", n.dir],
                    stdout=log, stderr=subprocess.STDOUT))
                for _ in range(100):
                    if os.path.exists(zs):
                        break
                    time.sleep(0.02)
            args = ["ip", "netns", "exec", n.name, "bgpd", "-u", "root", "-g", "root", "-f", conf,
                    "-i", f"{n.dir}/bgpd.pid", "--vty_socket", n.dir]
            args += ["-z", zs] if self.zebra else ["-Z"]
            procs.append(subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT))
            n.procs = procs

    def stop_node(self, n: Node, sig: int = signal.SIGTERM) -> None:
        for p in reversed(n.procs):
            if p.poll() is None:
                p.send_signal(sig)
        for p in n.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        n.procs = []

    def stop(self) -> None:
        for n in self.nodes.values():
            self.stop_node(n)
        for n in self.nodes.values():
            sh("ip", "netns", "del", n.name, check=False)

    # ------------------------------------------------------------ configs
    def nano_conf(self, n: Node) -> str:
        lines = [f"name {n.name}", f"asn {n.asn}", f"router-id {n.rid}", f"hold-time {self.hold}",
                 "connect-retry 1", "maximum-paths 8", "fib on", f"control {n.dir}/ctl.sock"]
        lines += [f"network {p}" for p in n.networks]
        lines += [f"neighbor {ip} remote-as {asn}" for ip, asn in n.neighbors]
        return "\n".join(lines) + "\n"

    def frr_conf(self, n: Node) -> str:
        out = [f"hostname {n.name}", f"log file {n.dir}/bgpd.log", "log timestamp precision 3",
               f"router bgp {n.asn}", f" bgp router-id {n.rid}", " no bgp ebgp-requires-policy",
               " no bgp network import-check", f" timers bgp {self.keepalive} {self.hold}"]
        for ip, asn in n.neighbors:
            out += [f" neighbor {ip} remote-as {asn}", f" neighbor {ip} timers connect 1"]
        out += [" address-family ipv4 unicast", "  maximum-paths 8"]
        out += [f"  network {p}" for p in n.networks]
        out += [" exit-address-family"]
        extra = self.extra_frr.get(n.name)
        if extra:
            out.append(extra)
        return "\n".join(out) + "\n"

    # ------------------------------------------------------------ queries
    def nano(self, node: str, cmd: str, timeout: float = 5.0) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(f"{self.nodes[node].dir}/ctl.sock")
        s.sendall((cmd + "\n").encode())
        buf = b""
        while True:
            chunk = s.recv(1 << 20)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf)

    def vtysh(self, node: str, cmd: str) -> str:
        return sh("vtysh", "--vty_socket", self.nodes[node].dir, "-c", cmd)

    def frr_json(self, node: str, cmd: str) -> dict:
        return json.loads(self.vtysh(node, cmd + " json"))

    def sessions(self, node: str) -> dict[str, str]:
        """peer ip -> state"""
        n = self.nodes[node]
        if n.kind == "nano":
            return {p["addr"]: p["state"] for p in self.nano(node, "summary")["peers"]}
        j = self.frr_json(node, "show bgp ipv4 unicast summary")
        return {ip: p["state"] for ip, p in j.get("peers", {}).items()}

    def rib(self, node: str) -> dict[str, list[str]]:
        """prefix -> sorted forwarding next hops (best + multipath), or ["local"]."""
        n = self.nodes[node]
        out: dict[str, list[str]] = {}
        if n.kind == "nano":
            for pfx, e in self.nano(node, "rib").items():
                out[pfx] = e["nexthops"] if e["from"] != "local" else ["local"]
            return out
        j = self.frr_json(node, "show bgp ipv4 unicast")
        for pfx, paths in j.get("routes", {}).items():
            nhs = set()
            for p in paths:
                if not p.get("valid"):
                    continue
                if not (p.get("bestpath") or p.get("multipath")):
                    continue
                for nh in p.get("nexthops", []):
                    nhs.add("local" if nh.get("ip") == "0.0.0.0" else nh["ip"])
            if nhs:
                out[pfx] = sorted(nhs)
        return out

    def fib(self, node: str) -> dict[str, list[str]]:
        """Kernel routes installed by BGP (proto bgp/186), prefix -> sorted gateways."""
        j = json.loads(sh("ip", "-j", "route", "show", "proto", "bgp", ns=node) or "[]")
        out = {}
        for r in j:
            dst = r["dst"] if "/" in r["dst"] else r["dst"] + "/32"
            if "nexthops" in r:
                out[dst] = sorted(h["gateway"] for h in r["nexthops"])
            else:
                out[dst] = [r["gateway"]]
        return out

    def wait(self, cond, timeout: float = 30.0, interval: float = 0.1, what: str = "condition"):
        t0 = time.monotonic()
        last = None
        while time.monotonic() - t0 < timeout:
            try:
                last = cond()
                if last:
                    return last
            except (OSError, RuntimeError, json.JSONDecodeError, KeyError) as e:
                last = e
            time.sleep(interval)
        raise TimeoutError(f"timed out after {timeout}s waiting for {what}; last={last!r}")

    def all_established(self) -> bool:
        for name in self.nodes:
            st = self.sessions(name)
            if len(st) != len(self.nodes[name].neighbors) or any(v != "Established" for v in st.values()):
                return False
        return True

    # ------------------------------------------------------------ expectations
    def expected_rib(self, node: str, down_links: set[tuple[str, str]] = frozenset()) -> dict[str, list[str]]:
        """What every node's table must look like, computed from the topology."""
        n = self.nodes[node]
        spines = sorted(x for x in self.nodes if x.startswith("spine"))
        leaves = sorted(x for x in self.nodes if x.startswith("leaf"))
        up = lambda s, l: (s, l) not in down_links
        out: dict[str, list[str]] = {}
        if node.startswith("leaf"):
            l = node[4:]
            for p in n.networks:
                out[p] = ["local"]
            for other in leaves:
                if other == node:
                    continue
                o = other[4:]
                nhs = sorted(f"10.{s[5:]}.{l}.0" for s in spines if up(s, node) and up(s, other))
                for p in self.nodes[other].networks:
                    if nhs:
                        out[p] = nhs
        else:
            s = node[5:]
            for leaf in leaves:
                if up(node, leaf):
                    for p in self.nodes[leaf].networks:
                        out[p] = [f"10.{s}.{leaf[4:]}.1"]
        return out

    def link(self, spine: str, leaf: str, up: bool) -> None:
        s, l = spine[5:], leaf[4:]
        sh("ip", "link", "set", f"l{l}", "up" if up else "down", ns=spine)
        sh("ip", "link", "set", f"s{s}", "up" if up else "down", ns=leaf)
