#include "wire.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace nbgp {

// ================================================================ helpers
namespace {

struct Reader {
    std::span<const uint8_t> b;
    size_t pos = 0;
    size_t left() const { return b.size() - pos; }
    uint8_t u8() { return b[pos++]; }
    uint16_t u16() { uint16_t v = uint16_t(b[pos] << 8 | b[pos + 1]); pos += 2; return v; }
    uint32_t u32() {
        uint32_t v = uint32_t(b[pos]) << 24 | uint32_t(b[pos + 1]) << 16 |
                     uint32_t(b[pos + 2]) << 8 | b[pos + 3];
        pos += 4;
        return v;
    }
    std::span<const uint8_t> take(size_t n) { auto s = b.subspan(pos, n); pos += n; return s; }
};

void put8(std::vector<uint8_t>& o, uint8_t v) { o.push_back(v); }
void put16(std::vector<uint8_t>& o, uint16_t v) { o.push_back(uint8_t(v >> 8)); o.push_back(uint8_t(v)); }
void put32(std::vector<uint8_t>& o, uint32_t v) {
    o.push_back(uint8_t(v >> 24)); o.push_back(uint8_t(v >> 16));
    o.push_back(uint8_t(v >> 8)); o.push_back(uint8_t(v));
}

void put_header(std::vector<uint8_t>& o, uint8_t type) {
    o.insert(o.end(), 16, 0xFF);
    put16(o, 0);  // patched by finish_msg
    put8(o, type);
}
void finish_msg(std::vector<uint8_t>& o, size_t start) {
    size_t len = o.size() - start;
    o[start + 16] = uint8_t(len >> 8);
    o[start + 17] = uint8_t(len);
}

BgpError err(uint8_t code, uint8_t subcode, std::string what, std::vector<uint8_t> data = {}) {
    return BgpError{code, subcode, std::move(data), std::move(what)};
}

// Parse a run of <len, prefix> NLRI entries (RFC 4271 4.3). Any error here is
// fatal: once one prefix is unparseable we cannot trust the rest.
std::optional<BgpError> parse_prefixes(std::span<const uint8_t> b, std::vector<Prefix>& out) {
    Reader r{b};
    while (r.left() > 0) {
        uint8_t len = r.u8();
        if (len > 32) return err(kErrUpdate, sub::kInvalidNetwork, "prefix length > 32");
        size_t bytes = (len + 7) / 8;
        if (r.left() < bytes) return err(kErrUpdate, sub::kInvalidNetwork, "prefix overruns field");
        uint32_t a = 0;
        for (size_t i = 0; i < bytes; ++i) a |= uint32_t(r.u8()) << (24 - 8 * i);
        out.push_back(Prefix::make(a, len));
    }
    return std::nullopt;
}

void put_prefix(std::vector<uint8_t>& o, const Prefix& p) {
    put8(o, p.len);
    for (int i = 0; i < (p.len + 7) / 8; ++i) put8(o, uint8_t(p.addr >> (24 - 8 * i)));
}
size_t prefix_wire_len(const Prefix& p) { return 1 + (p.len + 7) / 8; }

}  // namespace

// ================================================================ prefixes
Prefix Prefix::make(uint32_t addr, uint8_t len) {
    uint32_t mask = len == 0 ? 0 : ~uint32_t(0) << (32 - len);
    return Prefix{addr & mask, len};
}

std::string ip_str(uint32_t a) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255);
    return buf;
}

std::optional<uint32_t> parse_ip(std::string_view s) {
    uint32_t out = 0;
    int parts = 0;
    size_t i = 0;
    while (parts < 4) {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') return std::nullopt;
        uint32_t v = 0;
        size_t digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9' && digits < 4) {
            v = v * 10 + uint32_t(s[i] - '0');
            ++i, ++digits;
        }
        if (v > 255) return std::nullopt;
        out = out << 8 | v;
        if (++parts < 4) {
            if (i >= s.size() || s[i] != '.') return std::nullopt;
            ++i;
        }
    }
    if (i != s.size()) return std::nullopt;
    return out;
}

std::string Prefix::str() const { return ip_str(addr) + "/" + std::to_string(len); }

std::optional<Prefix> Prefix::parse(std::string_view s) {
    auto slash = s.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    auto ip = parse_ip(s.substr(0, slash));
    auto ls = s.substr(slash + 1);
    if (!ip || ls.empty() || ls.size() > 2) return std::nullopt;
    int len = 0;
    for (char c : ls) {
        if (c < '0' || c > '9') return std::nullopt;
        len = len * 10 + (c - '0');
    }
    if (len > 32) return std::nullopt;
    return Prefix::make(*ip, uint8_t(len));
}

// ================================================================ attrs
size_t Attrs::as_path_len() const {
    size_t n = 0;
    for (auto& s : as_path) n += s.type == kAsSet ? 1 : s.asns.size();
    return n;
}
uint32_t Attrs::neighbor_as() const {
    if (as_path.empty() || as_path[0].type != kAsSequence || as_path[0].asns.empty()) return 0;
    return as_path[0].asns[0];
}
bool Attrs::contains_as(uint32_t asn) const {
    for (auto& s : as_path)
        if (std::find(s.asns.begin(), s.asns.end(), asn) != s.asns.end()) return true;
    return false;
}
std::string Attrs::as_path_str() const {
    std::string out;
    for (auto& s : as_path) {
        if (!out.empty()) out += ' ';
        if (s.type == kAsSet) out += '{';
        for (size_t i = 0; i < s.asns.size(); ++i) {
            if (i) out += s.type == kAsSet ? "," : " ";
            out += std::to_string(s.asns[i]);
        }
        if (s.type == kAsSet) out += '}';
    }
    return out;
}

// ================================================================ decode
std::optional<BgpError> check_header(std::span<const uint8_t> h, uint16_t& len, uint8_t& type) {
    for (int i = 0; i < 16; ++i)
        if (h[i] != 0xFF) return err(kErrHeader, sub::kNotSynced, "bad marker");
    len = uint16_t(h[16] << 8 | h[17]);
    type = h[18];
    std::vector<uint8_t> lenbytes{h[16], h[17]};
    if (len < kHeaderLen || len > kMaxMsgLen)
        return err(kErrHeader, sub::kBadLength, "length out of range", lenbytes);
    size_t min = 0;
    switch (type) {
        case kOpen: min = 29; break;
        case kUpdate: min = 23; break;
        case kNotification: min = 21; break;
        case kKeepalive: min = 19; break;
        default: return err(kErrHeader, sub::kBadType, "unknown type", {type});
    }
    if (len < min || (type == kKeepalive && len != 19))
        return err(kErrHeader, sub::kBadLength, "bad length for type", lenbytes);
    return std::nullopt;
}

std::variant<Open, BgpError> decode_open(std::span<const uint8_t> body) {
    Reader r{body};
    if (r.left() < 10) return err(kErrHeader, sub::kBadLength, "short OPEN");
    Open o;
    o.version = r.u8();
    o.my_as = r.u16();
    o.hold_time = r.u16();
    o.bgp_id = r.u32();
    uint8_t optlen = r.u8();
    if (optlen != r.left()) return err(kErrOpen, 0, "optional parameter length mismatch");
    while (r.left() > 0) {
        if (r.left() < 2) return err(kErrOpen, 0, "truncated optional parameter");
        uint8_t ptype = r.u8(), plen = r.u8();
        if (r.left() < plen) return err(kErrOpen, 0, "optional parameter overruns");
        auto pv = r.take(plen);
        if (ptype != 2) return err(kErrOpen, sub::kBadOptParam, "unsupported optional parameter");
        Reader c{pv};  // capabilities (RFC 5492)
        while (c.left() > 0) {
            if (c.left() < 2) return err(kErrOpen, 0, "truncated capability");
            uint8_t code = c.u8(), clen = c.u8();
            if (c.left() < clen) return err(kErrOpen, 0, "capability overruns");
            auto cv = c.take(clen);
            if (code == 65 && clen == 4) {
                Reader v{cv};
                o.as4 = v.u32();
            } else if (code == 1 && clen == 4) {
                if (cv[0] == 0 && cv[1] == 1 && cv[3] == 1) o.mp_ipv4_unicast = true;
            } else {
                o.other_caps.push_back(code);
            }
        }
    }
    return o;
}

std::variant<Update, BgpError> decode_update(std::span<const uint8_t> body) {
    Reader r{body};
    Update u;
    if (r.left() < 4) return err(kErrUpdate, sub::kMalformedAttrList, "short UPDATE");
    uint16_t wlen = r.u16();
    if (r.left() < size_t(wlen) + 2)
        return err(kErrUpdate, sub::kMalformedAttrList, "withdrawn length overruns");
    auto wfield = r.take(wlen);
    uint16_t alen = r.u16();
    if (r.left() < alen) return err(kErrUpdate, sub::kMalformedAttrList, "attribute length overruns");
    auto afield = r.take(alen);
    auto nfield = r.take(r.left());

    // NLRI and withdrawn routes first: if we can't locate them, nothing else
    // matters and the session has to go (RFC 7606 section 5.3).
    if (auto e = parse_prefixes(wfield, u.withdrawn)) return *e;
    if (auto e = parse_prefixes(nfield, u.nlri)) return *e;
    if (alen == 0) {
        if (!u.nlri.empty()) {  // NLRI with no attributes at all
            u.treat_as_withdraw = true;
            u.error = "NLRI without path attributes";
        }
        return u;
    }

    Attrs a;
    bool seen[256] = {};
    auto taw = [&](std::string why) {
        if (!u.treat_as_withdraw) u.error = std::move(why);
        u.treat_as_withdraw = true;
    };
    auto note = [&](std::string why) { if (u.error.empty()) u.error = std::move(why); };

    Reader ar{afield};
    while (ar.left() > 0) {
        if (ar.left() < 3) { taw("truncated attribute header"); break; }
        uint8_t flags = ar.u8(), type = ar.u8();
        size_t len;
        if (flags & kExtLen) {
            if (ar.left() < 2) { taw("truncated attribute length"); break; }
            len = ar.u16();
        } else {
            len = ar.u8();
        }
        if (ar.left() < len) { taw("attribute overruns attribute field"); break; }
        auto v = ar.take(len);
        Reader vr{v};

        if (seen[type]) {  // RFC 7606 3(g): keep the first, discard the rest
            note("duplicate attribute " + std::to_string(type) + " discarded");
            continue;
        }
        seen[type] = true;

        const uint8_t ot = flags & (kOptional | kTransitive);
        auto want = [&](uint8_t expect) { return ot == expect; };
        switch (type) {
            case kAttrOrigin:
                if (!want(kTransitive)) { taw("ORIGIN flags"); break; }
                if (len != 1) { taw("ORIGIN length"); break; }
                a.origin = vr.u8();
                if (a.origin > kIncomplete) taw("invalid ORIGIN");
                break;
            case kAttrAsPath: {
                if (!want(kTransitive)) { taw("AS_PATH flags"); break; }
                bool bad = false;
                while (vr.left() > 0) {
                    if (vr.left() < 2) { bad = true; break; }
                    AsSegment s;
                    s.type = vr.u8();
                    uint8_t n = vr.u8();
                    if ((s.type != kAsSet && s.type != kAsSequence) || n == 0 ||
                        vr.left() < size_t(n) * 4) { bad = true; break; }
                    for (int i = 0; i < n; ++i) s.asns.push_back(vr.u32());
                    a.as_path.push_back(std::move(s));
                }
                if (bad) { a.as_path.clear(); taw("malformed AS_PATH"); }
                break;
            }
            case kAttrNextHop: {
                if (!want(kTransitive)) { taw("NEXT_HOP flags"); break; }
                if (len != 4) { taw("NEXT_HOP length"); break; }
                a.next_hop = vr.u32();
                uint32_t nh = a.next_hop;
                if (nh == 0 || nh == 0xFFFFFFFF || (nh >> 28) == 0xE || (nh >> 24) == 127)
                    taw("invalid NEXT_HOP " + ip_str(nh));
                break;
            }
            case kAttrMed:
                if (!want(kOptional)) { taw("MED flags"); break; }
                if (len != 4) { taw("MED length"); break; }
                a.med = vr.u32();
                break;
            case kAttrLocalPref:
                if (!want(kTransitive)) { taw("LOCAL_PREF flags"); break; }
                if (len != 4) { taw("LOCAL_PREF length"); break; }
                a.local_pref = vr.u32();
                break;
            case kAttrAtomicAggregate:  // RFC 7606: errors here -> attribute discard
                if (!want(kTransitive) || len != 0) { note("ATOMIC_AGGREGATE discarded"); break; }
                a.atomic_aggregate = true;
                break;
            case kAttrAggregator:
                if (!want(kOptional | kTransitive) || len != 8) { note("AGGREGATOR discarded"); break; }
                a.aggregator = std::pair{vr.u32(), vr.u32()};
                break;
            case kAttrMpReach:
            case kAttrMpUnreach:
                // Only IPv4 unicast is negotiated, and that rides in the classic
                // NLRI field. Nothing else should arrive; ignore it if it does.
                note("MP_(UN)REACH ignored");
                break;
            case kAttrAs4Path:
            case kAttrAs4Aggregator:
                // RFC 6793: a NEW speaker talking to a NEW speaker discards these.
                break;
            default:
                if (!(flags & kOptional))
                    return err(kErrUpdate, sub::kUnrecognizedWellKnown,
                               "unrecognized well-known attribute " + std::to_string(type),
                               std::vector<uint8_t>{flags, type});
                if (flags & kTransitive)
                    a.unknown.push_back(RawAttr{uint8_t(flags & ~kExtLen), type, {v.begin(), v.end()}});
                break;
        }
    }

    if (!u.nlri.empty()) {
        if (!seen[kAttrOrigin]) taw("missing ORIGIN");
        if (!seen[kAttrAsPath]) taw("missing AS_PATH");
        if (!seen[kAttrNextHop]) taw("missing NEXT_HOP");
    }
    u.attrs = std::move(a);
    return u;
}

Notification decode_notification(std::span<const uint8_t> body) {
    Notification n;
    if (body.size() >= 2) {
        n.code = body[0];
        n.subcode = body[1];
        n.data.assign(body.begin() + 2, body.end());
    }
    return n;
}

AnyMsg decode_message(std::span<const uint8_t> msg) {
    if (msg.size() < kHeaderLen) return err(kErrHeader, sub::kBadLength, "short");
    uint16_t len;
    uint8_t type;
    if (auto e = check_header(msg, len, type)) return *e;
    if (len != msg.size()) return err(kErrHeader, sub::kBadLength, "length mismatch");
    auto body = msg.subspan(kHeaderLen);
    switch (type) {
        case kOpen: {
            auto r = decode_open(body);
            if (auto* e = std::get_if<BgpError>(&r)) return *e;
            return std::get<Open>(r);
        }
        case kUpdate: {
            auto r = decode_update(body);
            if (auto* e = std::get_if<BgpError>(&r)) return *e;
            return std::get<Update>(std::move(r));
        }
        case kNotification: return decode_notification(body);
        default: return std::monostate{};
    }
}

// ================================================================ encode
std::vector<uint8_t> encode_open(const Open& o) {
    std::vector<uint8_t> out;
    put_header(out, kOpen);
    put8(out, o.version);
    put16(out, o.my_as);
    put16(out, o.hold_time);
    put32(out, o.bgp_id);
    std::vector<uint8_t> caps;
    if (o.mp_ipv4_unicast) {  // multiprotocol, IPv4 unicast
        put8(caps, 1); put8(caps, 4); put16(caps, 1); put8(caps, 0); put8(caps, 1);
    }
    if (o.as4) {  // 4-octet AS
        put8(caps, 65); put8(caps, 4); put32(caps, *o.as4);
    }
    if (caps.empty()) {
        put8(out, 0);
    } else {
        put8(out, uint8_t(caps.size() + 2));
        put8(out, 2);
        put8(out, uint8_t(caps.size()));
        out.insert(out.end(), caps.begin(), caps.end());
    }
    finish_msg(out, 0);
    return out;
}

std::vector<uint8_t> encode_keepalive() {
    std::vector<uint8_t> out;
    put_header(out, kKeepalive);
    finish_msg(out, 0);
    return out;
}

std::vector<uint8_t> encode_notification(const Notification& n) {
    std::vector<uint8_t> out;
    put_header(out, kNotification);
    put8(out, n.code);
    put8(out, n.subcode);
    out.insert(out.end(), n.data.begin(), n.data.end());
    finish_msg(out, 0);
    return out;
}

static void put_attr(std::vector<uint8_t>& o, uint8_t flags, uint8_t type,
                     std::span<const uint8_t> v) {
    if (v.size() > 255) flags |= kExtLen; else flags &= uint8_t(~kExtLen);
    put8(o, flags);
    put8(o, type);
    if (flags & kExtLen) put16(o, uint16_t(v.size())); else put8(o, uint8_t(v.size()));
    o.insert(o.end(), v.begin(), v.end());
}

void encode_attrs(const Attrs& a, std::vector<uint8_t>& out) {
    std::vector<uint8_t> v;
    v = {a.origin};
    put_attr(out, kTransitive, kAttrOrigin, v);
    v.clear();
    for (auto& s : a.as_path) {
        // a segment holds at most 255 ASNs; split longer ones
        for (size_t i = 0; i < s.asns.size(); i += 255) {
            size_t n = std::min<size_t>(255, s.asns.size() - i);
            put8(v, s.type);
            put8(v, uint8_t(n));
            for (size_t j = 0; j < n; ++j) put32(v, s.asns[i + j]);
        }
    }
    put_attr(out, kTransitive, kAttrAsPath, v);
    v.clear();
    put32(v, a.next_hop);
    put_attr(out, kTransitive, kAttrNextHop, v);
    if (a.med) { v.clear(); put32(v, *a.med); put_attr(out, kOptional, kAttrMed, v); }
    if (a.local_pref) { v.clear(); put32(v, *a.local_pref); put_attr(out, kTransitive, kAttrLocalPref, v); }
    if (a.atomic_aggregate) put_attr(out, kTransitive, kAttrAtomicAggregate, {});
    if (a.aggregator) {
        v.clear(); put32(v, a.aggregator->first); put32(v, a.aggregator->second);
        put_attr(out, kOptional | kTransitive, kAttrAggregator, v);
    }
    for (auto& u : a.unknown) put_attr(out, u.flags, u.type, u.value);
}

void encode_announce(const Attrs& a, std::span<const Prefix> nlri, std::vector<uint8_t>& out) {
    std::vector<uint8_t> attrs;
    encode_attrs(a, attrs);
    size_t i = 0;
    while (i < nlri.size()) {
        size_t start = out.size();
        put_header(out, kUpdate);
        put16(out, 0);  // no withdrawn routes
        put16(out, uint16_t(attrs.size()));
        out.insert(out.end(), attrs.begin(), attrs.end());
        if (out.size() - start + 5 > kMaxMsgLen) {  // attributes alone don't leave room
            out.resize(start);
            return;
        }
        size_t room = kMaxMsgLen - (out.size() - start);
        do {
            size_t need = prefix_wire_len(nlri[i]);
            if (need > room) break;
            put_prefix(out, nlri[i]);
            room -= need;
            ++i;
        } while (i < nlri.size());
        finish_msg(out, start);
    }
}

void encode_withdraw(std::span<const Prefix> prefixes, std::vector<uint8_t>& out) {
    size_t i = 0;
    while (i < prefixes.size()) {
        size_t start = out.size();
        put_header(out, kUpdate);
        size_t wlen_at = out.size();
        put16(out, 0);
        size_t room = kMaxMsgLen - kHeaderLen - 4;
        size_t wlen = 0;
        do {
            size_t need = prefix_wire_len(prefixes[i]);
            if (need > room) break;
            put_prefix(out, prefixes[i]);
            room -= need;
            wlen += need;
            ++i;
        } while (i < prefixes.size());
        out[wlen_at] = uint8_t(wlen >> 8);
        out[wlen_at + 1] = uint8_t(wlen);
        put16(out, 0);  // no attributes
        finish_msg(out, start);
    }
}

std::string notification_str(uint8_t code, uint8_t subcode) {
    static const char* codes[] = {"?", "Header", "OPEN", "UPDATE", "HoldTimerExpired", "FSM", "Cease"};
    std::string s = code < 7 ? codes[code] : "?";
    return s + "/" + std::to_string(subcode);
}

}  // namespace nbgp
