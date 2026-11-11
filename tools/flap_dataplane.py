"""What a link flap shorter than the hold time does to real traffic.

Flaps spine2<->leaf1 for 0.5 s (hold time is 3 s, so no BGP session resets),
waits, then opens 128 TCP connections from leaf3's server subnet to a listener
on leaf1's, each from a different source port so ECMP spreads them over both
spines. Prints how many connected, and whether spine2's RIB and FIB still have
leaf1's prefix.

    scripts/run.sh python3 tools/flap_dataplane.py build/nbgpd
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
from lab import Lab, spine_leaf  # noqa: E402

CLIENT = r"""
import socket, json
ok = fail = 0
for port in range(30000, 30128):
    s = socket.socket(); s.settimeout(1.0)
    s.bind(("192.168.3.1", port))
    try:
        s.connect(("192.168.1.1", 8080)); ok += 1
    except OSError:
        fail += 1
    s.close()
print(json.dumps({"ok": ok, "fail": fail}))
"""
SERVER = r"""
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("192.168.1.1", 8080)); s.listen(256)
while True:
    c, _ = s.accept(); c.close()
"""


def probe(lab, label):
    r = subprocess.run(["ip", "netns", "exec", "leaf3", "python3", "-c", CLIENT], capture_output=True, text=True)
    res = json.loads(r.stdout)
    rib = "192.168.1.0/24" in lab.rib("spine2")
    fib = "192.168.1.0/24" in lab.fib("spine2")
    print(f"{label:<22} flows ok {res['ok']:>3}/128   spine2 RIB has 192.168.1.0/24: {rib!s:<5}  FIB: {fib}")
    return res


lab = Lab(spine_leaf(), sys.argv[1])
try:
    lab.build()
    lab.start()
    lab.wait(lab.all_established, timeout=30)
    time.sleep(2)
    srv = subprocess.Popen(["ip", "netns", "exec", "leaf1", "python3", "-c", SERVER])
    time.sleep(0.5)
    probe(lab, "before flap")
    lab.link("spine2", "leaf1", up=False)
    time.sleep(0.5)
    lab.link("spine2", "leaf1", up=True)
    time.sleep(10)  # well past the hold time: anything still broken stays broken
    probe(lab, "10 s after 0.5 s flap")
    st = lab.nano("spine2", "summary")["peers"]
    print("spine2 session to leaf1:", [(p["addr"], p["state"], p["flaps"]) for p in st if p["addr"] == "10.2.1.1"])
    srv.kill()
finally:
    lab.stop()
