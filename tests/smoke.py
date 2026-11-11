"""Bring the lab up, print every node's sessions and table, tear it down.

    scripts/run.sh python3 tests/smoke.py build/nbgpd
"""
import sys
import time

sys.path.insert(0, __import__("os").path.dirname(__file__))
from lab import Lab, spine_leaf  # noqa: E402

lab = Lab(spine_leaf(), sys.argv[1])
try:
    lab.build()
    lab.start()
    t0 = time.monotonic()
    try:
        lab.wait(lab.all_established, timeout=30, what="all sessions Established")
        print(f"all sessions Established after {time.monotonic() - t0:.2f}s")
    except TimeoutError as e:
        print(e)
    time.sleep(2)
    for name in lab.nodes:
        print(f"--- {name} ({lab.nodes[name].kind})")
        print("  sessions:", lab.sessions(name))
        got, want = lab.rib(name), lab.expected_rib(name)
        print("  rib:     ", got)
        print("  match:   ", got == want)
        print("  fib:     ", lab.fib(name))
finally:
    lab.stop()
