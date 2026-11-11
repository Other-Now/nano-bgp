# nano-bgp

A BGP-4 speaker in C++20 (about 2,200 lines, no dependencies beyond libc). It runs **side by
side with FRRouting** in a leaf-spine fabric built from Linux network namespaces, and installs
its routes, including ECMP multipath, into the Linux kernel over netlink.

```
    spine1 (FRR)          spine2 (nano-bgp)         AS 65000
       |   \   \   \      /   /   /   |
     leaf1    leaf2    leaf3    leaf4               AS 4200000001..4 (4-octet ASNs)
     nano     FRR      nano     FRR                 each owns 192.168.N.0/24
```

This is the RFC 7938 data-centre design: eBGP on every link, one AS for the spine layer, so every
leaf has two equal-cost paths to every other leaf. Every session in the fabric is nano↔FRR,
nano↔nano or FRR↔FRR. The tests check that **every node's table, and every node's kernel FIB,
matches the table computed from the topology**.

## What's implemented

| | |
|---|---|
| Session | RFC 4271 FSM over TCP. Active + passive opens with **connection-collision resolution** (§6.8). Hold/keepalive/connect-retry timers. NOTIFICATIONs with correct codes. |
| Messages | OPEN (capabilities: MP-BGP IPv4 unicast, **4-octet AS, RFC 6793**), UPDATE, NOTIFICATION, KEEPALIVE. Unknown optional transitive attributes passed on with the Partial bit. |
| Error handling | **RFC 7606**: session reset only when the NLRI can't be located. Treat-as-withdraw for bad attributes that affect route selection. Attribute discard for the rest. |
| Tables | Adj-RIB-In, Loc-RIB, per-peer Adj-RIB-Out (only real changes are sent; UPDATEs are packed up to 4 KB). |
| Best path | local-pref → AS-path length → origin → MED (same neighbour AS only) → eBGP over iBGP → router ID → peer address. |
| ECMP | Multipath across paths with an identical AS_PATH, `maximum-paths N`. |
| Policy | AS-loop rejection, enforce-first-as, next-hop-self / AS prepend / MED strip towards eBGP, iBGP split horizon. |
| FIB | rtnetlink, `RTA_MULTIPATH`, batched about 32 KB per syscall, `proto bgp`. Stale routes removed at start-up. |
| Link events | Netlink link monitor: **fast-external-failover**, plus a FIB resync after any link change (see Findings). |
| Ops | Unix-socket control: `summary`, `rib`, `route P`, `announce/withdraw P`, `peer-down/up IP`, `fast-failover on/off`. |

Not implemented: IPv6/MP_REACH, route reflection, communities, a policy language, graceful
restart, add-path, MD5/TCP-AO, BFD, and 2-octet-only peers. Details and the reasons are in
[docs/NOTES.md](docs/NOTES.md).

## Test plan

| Layer | What | Where |
|---|---|---|
| Unit | 37 tests / 68 checks: codec round trips, every RFC 7606 error class (fatal / treat-as-withdraw / discard), each decision step, multipath rules, RIB bookkeeping | `tests/unit_tests.cpp` |
| Fuzz | libFuzzer on the message decoder, with a property: any UPDATE that decodes cleanly must re-encode and decode back to the same attributes and NLRI. ASan + UBSan. | `fuzz/fuzz_update.cpp` |
| Interop (pytest) | The 6-node mixed fabric: all 16 sessions up. Tables **and kernel FIBs** match the topology. 4-octet AS paths survive FRR in both directions. ECMP traffic actually uses both spines (interface counters). Link failure + recovery. A link flap shorter than the hold time. Withdrawals nano→FRR and FRR→nano. Admin shutdown sends Cease to FRR. `kill -9` + restart. | `tests/test_fabric.py` |
| Bad peer (pytest) | A scripted Python peer: valid UPDATE installed; bad ORIGIN → treat-as-withdraw with the session kept; first-AS mismatch rejected; AS loop dropped silently; unlocatable NLRI → NOTIFICATION 3/1; wrong AS in OPEN → 2/2; silence → hold timer 4/0 after 2–4.5 s | `tests/test_bad_peer.py` |
| Sanitizers | The whole pytest suite also runs against an ASan + UBSan build; the lab fails on any sanitizer report in a daemon log | `tests/lab.py` |

The Python BGP encoder used by the bad-peer tests (`tests/bgp_raw.py`) is written independently
of the C++ codec. That way, the same misunderstanding can't pass on both sides.

## Results

Measured locally: WSL2 (kernel 6.18), FRR 8.4.4 from the Ubuntu 24.04 package, release build,
otherwise idle machine. Raw data is in [results/local](results/local). CI re-runs the same
benchmark on every push ([results/ci](results/ci) once the workflow has run).

- **Tests:** 37 unit (68 checks), 19 interop/bad-peer pass plus 1 expected FRR failure (below).
  The same suite passes with ASan + UBSan.
- **Fuzzing:** 47.9M inputs in 10 minutes, no crash and no round-trip mismatch.

**Convergence after a failure on spine↔leaf3.** Median of 10 runs, measured until the other
leaves' *kernel* route to 192.168.3.0/24 is single-path. Times come from `ip -ts monitor route`
in each observer namespace, the same clock for FRR and nano-bgp. Hold time is 3 s, keepalive
1 s.

| failure | detected by | leaf1 (nano) | leaf2 (FRR) |
|---|---|---|---|
| carrier down on spine1 link | spine1 = FRR | 66 ms | 127 ms |
| carrier down on spine2 link | spine2 = nano | **5 ms** | 66 ms |
| silent drop (carrier up) on spine1 link | FRR hold timer | 2.98 s | 3.04 s |
| silent drop (carrier up) on spine2 link | nano hold timer | 2.27 s | 2.33 s |

A silent failure is only caught by the hold timer, so detection lands between hold − keepalive
and hold (2–3 s here). With the common default hold of 180 s, it would take up to 3 minutes,
which is what BFD exists to fix.

**Withdrawal propagation.** Median of 10 runs, until the prefix is deleted from the observer's
kernel.

| origin | spine1 (FRR, 1 hop) | spine2 (nano, 1 hop) | far leaf, nano | far leaf, FRR |
|---|---|---|---|---|
| nano leaf1 withdraws | 61.6 ms | **0.8 ms** | 51.7 ms | 111.9 ms |
| FRR leaf2 withdraws (clock includes the `vtysh` call) | 153.9 ms | 93.4 ms | 143.9 ms | 205.1 ms |

The one-hop pair has the same sender and the same message, with a different receiver. nano-bgp
receives, decides and updates the kernel in under 1 ms. FRR's bgpd+zebra takes about 60 ms in
this setup. I haven't profiled where FRR's 60 ms goes, so don't read it as a general FRR number.

**Learning 100,000 /24 routes over one session**, from Established. Median of 3 runs.

| sender → receiver | time | routes/s |
|---|---|---|
| nano → nano, kernel FIB on (all 100k in `ip route`) | 0.58 s | 172k |
| FRR → nano, kernel FIB on | 1.70 s | 59k |
| FRR → nano, kernel FIB off | 1.29 s | 77k |
| nano → FRR | 0.21 s | ~470k (vtysh polling, about 35 ms resolution) |

The FRR→nano time is bounded by how fast FRR sends: the same nano-bgp receiver takes the same
100k routes from another nano-bgp 3× faster, kernel install included.

## Findings

### 1. A link flap shorter than the hold time black-holed traffic (bug in nano-bgp, fixed)

Found by `test_link_flap_shorter_than_hold_time`. The spine2↔leaf1 link went down for 0.5 s.
The BGP session survived, because TCP retransmitted inside the 3 s hold time. Spine2's BGP
table still had 192.168.1.0/24, but its kernel route was gone, and **stayed gone**.

The cause: **when a device goes down, Linux deletes every route through it and never puts them
back**. With no session change there was no RIB change, so nothing reinstalled the route.

Effect on traffic: 128 TCP flows from leaf3 to leaf1, before and after the flap
(`tools/flap_dataplane.py`).

| | flows that connect | spine2 RIB | spine2 FIB | session flaps |
|---|---|---|---|---|
| before the fix | **60 / 128** | has route | **missing** | 0 |
| after the fix | 128 / 128 | has route | has route | 1 (fast failover) |

The fix (second commit) subscribes to netlink link events. It drops an eBGP session as soon as
its interface loses carrier (**fast-external-failover**, as FRR does), and re-pushes the
Loc-RIB into the kernel after any link change. The test runs both with fast-failover on and off,
so the resync is proven on its own. A side effect: link-failure tests no longer wait for hold
timers, and the suite went from 133 s to 35 s.

### 2. FRR 8.4.4's zebra loses an ECMP member after the same kind of flap (seen in FRR, not fixed here)

After the spine2↔leaf2 link went down and up, FRR leaf2's BGP table and zebra both showed two
next hops installed. The kernel route had one. `ip nexthop show` showed why:

- zebra uses kernel nexthop groups, and group 15 was `{8, 16}`.
- On link down, the kernel deleted nexthop 8 and shrank the group to `{16}` by itself.
- On link up, zebra recreated nexthop 8 but never re-sent group 15.

This is kept as an `xfail` test (`test_frr_zebra_fib_after_link_flap`). I haven't checked
whether newer FRR releases behave differently.

It's the same lesson as finding 1, from the other side: the kernel changes its own state on
link events, and a routing daemon has to notice.

## Run it

Needs Linux, CMake, g++ ≥ 12 (or clang), Python 3 with pytest, iproute2, and FRR.

```sh
cmake -S . -B build && cmake --build build -j
build/unit_tests

# with root (CI):
sudo apt-get install frr && sudo systemctl stop frr
sudo scripts/run.sh python3 -m pytest -v --nbgpd build/nbgpd tests/

# without root: unprivileged user + network namespaces, with FRR unpacked from the .debs
scripts/deps.sh ~/bgp-deps
FRR_ROOT=~/bgp-deps/root scripts/run.sh python3 -m pytest -v --nbgpd build/nbgpd tests/

# benchmarks / the flap demonstration
FRR_ROOT=~/bgp-deps/root scripts/run.sh python3 tools/bench.py build/nbgpd results/local 10
FRR_ROOT=~/bgp-deps/root scripts/run.sh python3 tools/flap_dataplane.py build/nbgpd

# fuzz (clang)
cmake -S . -B build-fuzz -DNBGP_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ && cmake --build build-fuzz --target fuzz_update
python3 fuzz/make_seeds.py corpus && build-fuzz/fuzz_update -max_total_time=600 corpus
```

`scripts/run.sh` puts everything in a private network and mount namespace, so nothing touches
the host's network. Without root it adds a user namespace, and gives FRR the `/etc/frr` and
`frrvty` group it expects through a symlink farm over `/etc`, visible only inside that
namespace.

## Layout

```
src/wire.*      message codec, RFC 7606 error classes           (pure, fuzzed)
src/rib.*       Adj-RIB-In, Loc-RIB, decision process, multipath (pure, unit-tested)
src/fib.*       netlink route install (batched) + link monitor
src/speaker.*   FSM, timers, collision, import/export policy, epoll loop, control socket
tests/          unit tests, lab builder, pytest interop + bad-peer suites
tools/          bench.py, flap_dataplane.py
docs/NOTES.md   protocol notes tied to the code
```
