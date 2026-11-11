# nano-bgp: study sheet

Everything here is what the code does, with the file to open if asked to show it.

## 1. Session FSM (RFC 4271 §8): `src/speaker.cpp`

```
Idle --start--> Connect --TCP up, send OPEN--> OpenSent --valid OPEN, send KEEPALIVE--> OpenConfirm
                  |  (connect fails: Active, retry after connect-retry)                  |
                  +--------------------------------------------------------- KEEPALIVE --> Established
any state: NOTIFICATION received / error detected / hold timer expires --> close, back to Active
```

- Both sides connect out *and* listen, so **two TCP connections** to one peer is
  normal. Collision resolution (§6.8): once the peer's BGP ID is known (its
  OPEN), keep the connection opened by the side with the **higher BGP
  Identifier**; close the other with NOTIFICATION Cease/7. `resolve_collision()`.
- A new inbound connection while already Established is refused.
- **Hold time** = min(ours, theirs); 0 = no keepalives; 1 and 2 are illegal
  (OPEN error subcode 6). **Keepalive** = hold / 3. Every KEEPALIVE or UPDATE
  restarts the hold timer. Before the OPEN arrives, the hold timer is a "large"
  4 minutes, as the RFC suggests.
- OPEN checks: version 4; peer AS = configured; hold time; BGP ID not 0. We
  **require the 4-octet-AS capability** (65) and send NOTIFICATION 2/7 if it's
  missing. That's a simplification: a real speaker would fall back to
  AS_TRANS + AS4_PATH (RFC 6793).

## 2. Messages: `src/wire.cpp`

Every message has a 19-byte header: a 16×0xFF marker, a 2-byte length (19–4096) and a 1-byte type.

| type | body |
|---|---|
| OPEN (1) | version, My AS (2 bytes; AS_TRANS 23456 if the real ASN > 65535), hold time, BGP ID, optional params → capabilities (MP-BGP IPv4/unicast = 1, 4-octet AS = 65) |
| UPDATE (2) | withdrawn-routes length + prefixes, path-attribute length + attributes, NLRI (the rest) |
| NOTIFICATION (3) | code, subcode, data. The connection closes after it. |
| KEEPALIVE (4) | header only; length must be exactly 19 |

A prefix on the wire is a length byte followed by `ceil(len/8)` address bytes. We mask the host bits.

Path attributes are encoded as flags, type, then a length of 1 byte (2 bytes if the extended-length flag is set).

| attr | flags | notes |
|---|---|---|
| ORIGIN 1 | well-known mandatory | IGP 0 / EGP 1 / INCOMPLETE 2 |
| AS_PATH 2 | well-known mandatory | segments: AS_SET(1) / AS_SEQUENCE(2), count, 4-byte ASNs; ≤255 per segment, longer paths are split |
| NEXT_HOP 3 | well-known mandatory | 0.0.0.0, 127/8, multicast and broadcast are rejected |
| MED 4 | optional non-transitive | |
| LOCAL_PREF 5 | well-known (iBGP only) | ignored if an eBGP peer sends it |
| ATOMIC_AGGREGATE 6, AGGREGATOR 7 | | parsed and passed on |
| unknown, optional, transitive | | passed on with the **Partial** bit set |
| unknown, optional, non-transitive | | dropped |
| unknown well-known | | NOTIFICATION 3/2 |

## 3. Error handling: RFC 7606 ("revised error handling")

Under the old RFC 4271 rule, *any* malformed UPDATE resets the session, which throws away
every route on it. One bad attribute from one prefix could cost a million routes. RFC 7606 asks
a different question: **can I still find the NLRI?**

- **No** (the withdrawn length or attribute length overruns the message, or a prefix length is
  above 32 or overruns): **session reset**. NOTIFICATION 3/1 or 3/10.
- **Yes**, but an attribute that affects route selection is bad (ORIGIN value, AS_PATH structure,
  NEXT_HOP, MED/LOCAL_PREF length, wrong flags on a well-known attribute, a missing mandatory
  attribute, or an attribute that overruns the attribute field): **treat-as-withdraw**. Those
  prefixes are withdrawn and the session stays up.
- **Yes**, and the bad attribute doesn't affect selection (ATOMIC_AGGREGATE, AGGREGATOR):
  **attribute discard**.
- Duplicate attribute: keep the first.

The decoder returns either a `BgpError` (reset) or an `Update` with `treat_as_withdraw=true`.
Tested by hand-built bytes in `tests/unit_tests.cpp` and on the wire by
`tests/test_bad_peer.py`, where a Python peer sends bad UPDATEs.

## 4. Import policy (`on_update`)

- From an eBGP peer, strip LOCAL_PREF.
- **Loop detection**: our own AS in the AS_PATH means a silent drop. That's normal, not an error.
  In this fabric, every leaf re-advertises its routes back towards the spines, and the spines drop
  them this way.
- **enforce-first-as**: an eBGP path whose first AS isn't the peer's AS is rejected.

## 5. Decision process (RFC 4271 §9.1.2.2): `src/rib.cpp` `compare()`

0. A route we originate ourselves wins (FRR calls this weight 32768).
1. Highest LOCAL_PREF (default 100).
2. Shortest AS_PATH (an AS_SET counts as 1).
3. Lowest ORIGIN.
4. Lowest MED, **only between routes from the same neighbouring AS**. A missing MED counts as 0.
5. eBGP over iBGP.
6. Lowest IGP cost to the NEXT_HOP. *Skipped: there's no IGP, and every next hop is directly
   connected.*
7. Lowest BGP Identifier of the peer.
8. Lowest peer address.

`compare()` reports which step decided; the unit tests check each step.

**Difference from FRR:** for two eBGP paths, FRR prefers the *older* one before comparing router
IDs, to reduce churn. nano-bgp goes straight to the router ID. The interop tests compare the
**forwarding set** (best + multipath next hops), which is the same either way.

## 6. ECMP / multipath

A path joins the best path's forwarding set if it ties through step 5, has the **identical
AS_PATH** (FRR's default, without `as-path multipath-relax`), and has a different next hop. The
set is capped by `maximum-paths`.

Leaf-spine: both spines are AS 65000, so leaf1 sees `65000 4200000003` via spine1 and via
spine2, identical, which gives 2-way ECMP. That's why RFC 7938 puts all spines in one AS. With
a different AS per spine, you'd need multipath-relax.

The kernel route uses `RTA_MULTIPATH`: a list of `rtnexthop` entries, each with its own
`RTA_GATEWAY`, and ifindex 0 so the kernel resolves the device.
`net.ipv4.fib_multipath_hash_policy=1` hashes on L4 ports, so different flows take different
spines. `test_ecmp_dataplane_uses_both_spines` checks this with interface counters.

## 7. Export policy (`export_attrs`)

- Never send a route back to the peer it came from.
- iBGP split horizon: an iBGP-learned route is not sent to iBGP peers. There are no route
  reflectors.
- Sender-side loop check: don't send a route whose AS_PATH already contains the peer's AS (the
  peer would drop it anyway).
- To eBGP peers: **prepend our AS**, set **NEXT_HOP = self** (the local address of that TCP
  session), drop LOCAL_PREF, and **drop MED** (a MED is only meaningful between two neighbouring
  ASes).
- To iBGP peers: set LOCAL_PREF (default 100) and leave NEXT_HOP unchanged.
- **Adj-RIB-Out** (`Peer::adj_out`) remembers what each peer was last told, so only real changes
  are sent. A multipath-only change, with the same best path, sends nothing.
- Prefixes with identical exported attributes are packed into one UPDATE, as many as fit in 4096
  bytes. A /24 takes 4 bytes, so one UPDATE carries roughly 1,000 of them and 100k routes need
  about 100 messages, not 100k (`update_roundtrip_packs_and_splits` checks the split).

## 8. FIB: `src/fib.cpp`

- rtnetlink `RTM_NEWROUTE` with `NLM_F_CREATE|NLM_F_REPLACE`, protocol 186 (`proto bgp`).
  Messages are **batched** about 32 KB per `sendto`, and then the ACKs are drained. Doing one
  round trip per route would make the kernel the bottleneck.
- At start-up and shut-down, every `proto bgp` route is deleted, so a `kill -9` doesn't leave
  stale routes behind (`test_nano_kill9_and_restart`).
- **Link monitor** (`RTMGRP_LINK`). See §10: this is the bug fix.

## 9. Event loop

Single-threaded epoll. On each iteration:

1. Read all sockets and decode messages. UPDATEs mark prefixes *dirty*.
2. Run the timers.
3. `process_dirty()`: run the decision for each dirty prefix once, push FIB changes in one netlink
   batch, then export the changed prefixes to every Established peer.

Batching per iteration means a burst of 1,000 UPDATEs runs the decision process for each prefix
once, not once per message.

## 10. The bug the interop tests found (the debugging story)

**Symptom.** `test_link_flap_shorter_than_hold_time` failed. After the spine2↔leaf1 link went
down for 0.5 s and came back, spine2 (nano-bgp) still had 192.168.1.0/24 in its BGP table and
the session was still Established (0 flaps). But `ip route` on spine2 had no route.
`tools/flap_dataplane.py` showed **60/128 flows** from leaf3 to leaf1 still connecting; every
flow that ECMP hashed through spine2 was black-holed. It stayed that way permanently.

**Cause.** When a device goes down, **the Linux kernel deletes every route whose next hop is on
that device**. It doesn't restore them when the device comes back. The flap was shorter than
the 3 s hold time, so TCP retransmitted and the BGP session never noticed. With no session
change there was no RIB change, so nothing ever reinstalled the route. The RIB and the FIB had
silently diverged.

**Fix** (`on_link_change`, commit 2). Subscribe to netlink link events.
1. **fast-external-failover**: if the interface carrying an eBGP session's local address loses
   carrier, drop the session immediately. This is FRR's default too.
2. After any link event, push the whole Loc-RIB into the kernel again.

Part 2 alone fixes the bug, and the test runs both ways (`failover=off` proves the resync on its
own). Result: **128/128** flows. As a bonus, the whole test suite went from 133 s to 35 s,
because link-down tests no longer wait for hold timers.

**Lesson.** A routing daemon's job isn't done when the RIB is right. The kernel is a second
state machine that changes underneath you. FRR's zebra exists largely to track exactly this:
interface events, the kernel's own route deletions, and nexthop resolution.

## 11. Something odd seen in FRR (not my bug)

On the same link flap, **FRR 8.4.4's** zebra (Ubuntu 24.04 package) ended up with leaf2's kernel
route on one next hop, while zebra itself showed both as installed (`*`).

`ip nexthop show` explained it:
- Zebra uses kernel nexthop objects. Group 15 was `{8, 16}`.
- On link down, the kernel deleted nexthop 8 and **shrank group 15 to {16} on its own**.
- On link up, zebra recreated nexthop 8 but never re-pushed group 15, which it still believed
  was `{8, 16}`.

This is recorded as an `xfail` test. I did not check whether newer FRR fixes it, so don't claim
it's an open bug.

## 12. Failure detection numbers (see README)

- **Carrier loss**: both implementations react to link events, so detection takes milliseconds.
  The time is dominated by propagation and processing.
- **Silent failure** (carrier up, packets dropped: a hung line card, a one-way fibre fault):
  only the hold timer sees it, so it takes about 3 s with hold 3 s, and 90 s with the common
  default of hold 180 s. **This is what BFD (RFC 5880) is for**: sub-second hellos over UDP,
  with BGP told to drop the session. Not implemented here; it would be the next step.

## 13. What's deliberately not here (say so before you're asked)

- No IPv6 / MP_REACH: only IPv4 unicast, carried in the classic NLRI field.
- No route reflection, confederations, communities, route maps / policy language, graceful
  restart, add-path, route refresh, TCP-MD5/TCP-AO, or BFD.
- No 2-octet-AS-only peers (AS4_PATH reconstruction).
- No IGP, so decision step 6 is skipped.
- No `MinRouteAdvertisementInterval` (MRAI) timer: updates go out as soon as they're computed.
  That's normal for eBGP inside a data centre, where fast convergence matters more than damping
  churn.

## 14. Likely questions

- *Why BGP in a data centre rather than OSPF?* RFC 7938: it scales to large fabrics. Policy is
  per-session. There's no flooding domain, so failures stay local. It's one protocol for both
  underlay and overlay (EVPN).
- *Why are the spines in one AS?* So that paths through different spines have identical
  AS_PATHs, which gives ECMP without relaxing anything. It's also why leaf→spine→leaf→spine
  loops are impossible: the spine sees its own AS.
- *What happens if UPDATEs come faster than you can install?* They queue in the TCP socket
  buffer. The window closes and the sender slows down (TCP flow control is BGP's flow control).
  Within one iteration they are coalesced per prefix.
- *How is convergence measured?* Kernel route events (`ip -ts monitor route`) in the observer
  namespaces. That clock is the same for FRR and nano-bgp, and it measures forwarding, not just
  BGP state.
