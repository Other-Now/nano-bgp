"""Write a seed corpus of valid messages (type byte + body) for fuzz_update."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests"))
import bgp_raw as raw

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
seeds = {
    "update_basic": raw.update(["10.1.0.0/16", "192.168.3.0/24"], as_path=[65000, 4200000003], next_hop="10.1.3.0"),
    "update_withdraw": raw.update(withdrawn=["10.1.0.0/16", "0.0.0.0/0", "1.2.3.4/32"]),
    "update_med_lp": raw.update(["10.2.0.0/16"], as_path=[65001], next_hop="10.0.0.1")[:-3],
    "update_extra": raw.msg(2, b"\x00\x00\x00\x2a" + raw.attr(0x40, 1, b"\x00") +
                            raw.attr(0x40, 2, b"\x02\x01\x00\x00\xfd\xe9") + raw.attr(0x40, 3, bytes([10, 0, 0, 1])) +
                            raw.attr(0x80, 4, b"\x00\x00\x00\x05") + raw.attr(0x40, 5, b"\x00\x00\x00\x64") +
                            raw.attr(0x40, 6, b"") + raw.attr(0xc0, 7, bytes(8)) + b"\x18\x0a\x01\x02"),
    "open": raw.open_msg(4200000001, 3, "10.255.1.1"),
    "notification": raw.msg(3, b"\x06\x02"),
}
for name, m in seeds.items():
    t, body = m[18], m[19:]
    with open(os.path.join(out, name), "wb") as f:
        f.write(bytes([t - 1]) + body)
