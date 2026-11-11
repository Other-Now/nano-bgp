"""Hand-rolled BGP messages for the misbehaving-peer tests.

Deliberately independent of the C++ codec: if both were generated from the same
misunderstanding, round-trip tests would pass and real peers would still fail.
"""
import socket
import struct

MARKER = b"\xff" * 16


def msg(type_: int, body: bytes) -> bytes:
    return MARKER + struct.pack("!HB", 19 + len(body), type_) + body


def open_msg(asn: int, hold: int, rid: str) -> bytes:
    caps = bytes([1, 4, 0, 1, 0, 1]) + bytes([65, 4]) + struct.pack("!I", asn)
    opt = bytes([2, len(caps)]) + caps
    my_as = asn if asn <= 65535 else 23456
    return msg(1, struct.pack("!BHH4sB", 4, my_as, hold, socket.inet_aton(rid), len(opt)) + opt)


def keepalive() -> bytes:
    return msg(4, b"")


def prefix(p: str) -> bytes:
    net, ln = p.split("/")
    ln = int(ln)
    return bytes([ln]) + socket.inet_aton(net)[: (ln + 7) // 8]


def attr(flags: int, type_: int, value: bytes) -> bytes:
    return bytes([flags, type_, len(value)]) + value


def update(nlri=(), withdrawn=(), origin=0, as_path=(), next_hop="0.0.0.0", raw_attrs=None) -> bytes:
    w = b"".join(prefix(p) for p in withdrawn)
    if raw_attrs is not None:
        a = raw_attrs
    elif nlri:
        seg = bytes([2, len(as_path)]) + b"".join(struct.pack("!I", x) for x in as_path)
        a = (attr(0x40, 1, bytes([origin])) + attr(0x40, 2, seg) +
             attr(0x40, 3, socket.inet_aton(next_hop)))
    else:
        a = b""
    n = b"".join(prefix(p) for p in nlri)
    return msg(2, struct.pack("!H", len(w)) + w + struct.pack("!H", len(a)) + a + n)


def read_msg(sock: socket.socket) -> tuple[int, bytes]:
    """(type, body); raises ConnectionError on EOF."""
    def exact(n):
        buf = b""
        while len(buf) < n:
            c = sock.recv(n - len(buf))
            if not c:
                raise ConnectionError("eof")
            buf += c
        return buf
    h = exact(19)
    ln, t = struct.unpack("!HB", h[16:19])
    return t, exact(ln - 19)
