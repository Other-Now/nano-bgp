// Unit tests for the codec and the decision process. No framework: each CHECK
// prints the failing expression; the exit code is the number of failures.
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

#include "rib.hpp"
#include "wire.hpp"

using namespace nbgp;

static int g_fail = 0, g_checks = 0;
#define CHECK(cond)                                                                  \
    do {                                                                             \
        ++g_checks;                                                                  \
        if (!(cond)) {                                                               \
            ++g_fail;                                                                \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);            \
        }                                                                            \
    } while (0)

static std::vector<std::pair<const char*, std::function<void()>>>& registry() {
    static std::vector<std::pair<const char*, std::function<void()>>> r;
    return r;
}
struct Reg {
    Reg(const char* n, std::function<void()> f) { registry().emplace_back(n, std::move(f)); }
};
#define TEST(name)                         \
    static void name();                    \
    static Reg reg_##name(#name, name);    \
    static void name()

// ---------------------------------------------------------------- helpers
static Prefix P(const char* s) { return *Prefix::parse(s); }

static std::vector<uint8_t> hdr(uint8_t type, std::vector<uint8_t> body) {
    std::vector<uint8_t> m(16, 0xFF);
    size_t len = 19 + body.size();
    m.push_back(uint8_t(len >> 8));
    m.push_back(uint8_t(len));
    m.push_back(type);
    m.insert(m.end(), body.begin(), body.end());
    return m;
}

// UPDATE body from raw attribute bytes and NLRI bytes.
static std::vector<uint8_t> update_body(std::vector<uint8_t> withdrawn, std::vector<uint8_t> attrs,
                                        std::vector<uint8_t> nlri) {
    std::vector<uint8_t> b;
    b.push_back(uint8_t(withdrawn.size() >> 8));
    b.push_back(uint8_t(withdrawn.size()));
    b.insert(b.end(), withdrawn.begin(), withdrawn.end());
    b.push_back(uint8_t(attrs.size() >> 8));
    b.push_back(uint8_t(attrs.size()));
    b.insert(b.end(), attrs.begin(), attrs.end());
    b.insert(b.end(), nlri.begin(), nlri.end());
    return b;
}

// A valid set of mandatory attributes: ORIGIN IGP, AS_PATH [65001], NEXT_HOP 10.0.0.1
static std::vector<uint8_t> good_attrs() {
    return {0x40, 1, 1, 0,
            0x40, 2, 6, 2, 1, 0, 0, 0xFD, 0xE9,
            0x40, 3, 4, 10, 0, 0, 1};
}

static Update decode_ok(const std::vector<uint8_t>& body) {
    auto r = decode_update(body);
    if (auto* e = std::get_if<BgpError>(&r)) {
        std::printf("  unexpected error: %s\n", e->what.c_str());
        ++g_fail;
        return {};
    }
    return std::get<Update>(r);
}

static Attrs attrs_with(std::vector<uint32_t> path, uint32_t nh) {
    Attrs a;
    a.as_path = {AsSegment{kAsSequence, path}};
    a.next_hop = nh;
    return a;
}

// ================================================================ prefixes
TEST(prefix_parse_and_print) {
    CHECK(P("10.1.2.0/24").str() == "10.1.2.0/24");
    CHECK(P("10.1.2.3/24").str() == "10.1.2.0/24");  // host bits masked
    CHECK(P("0.0.0.0/0").len == 0);
    CHECK(!Prefix::parse("10.1.2.0/33"));
    CHECK(!Prefix::parse("10.1.2/24"));
    CHECK(!Prefix::parse("256.1.2.0/24"));
    CHECK(!Prefix::parse("10.1.2.0"));
}

// ================================================================ OPEN
TEST(open_roundtrip_4octet_as) {
    Open o;
    o.my_as = kAsTrans;
    o.hold_time = 3;
    o.bgp_id = 0x0AFF0101;
    o.as4 = 4200000001u;
    o.mp_ipv4_unicast = true;
    auto m = encode_open(o);
    auto r = decode_message(m);
    auto* d = std::get_if<Open>(&r);
    CHECK(d != nullptr);
    if (!d) return;
    CHECK(d->my_as == kAsTrans);
    CHECK(d->asn() == 4200000001u);
    CHECK(d->hold_time == 3);
    CHECK(d->bgp_id == 0x0AFF0101);
    CHECK(d->mp_ipv4_unicast);
}

TEST(open_rejects_unknown_optional_parameter) {
    std::vector<uint8_t> body = {4, 0xFD, 0xE9, 0, 3, 1, 1, 1, 1, 3, 9, 1, 0};
    auto r = decode_open(body);
    auto* e = std::get_if<BgpError>(&r);
    CHECK(e && e->code == kErrOpen && e->subcode == sub::kBadOptParam);
}

// ================================================================ header
TEST(header_errors) {
    auto ka = encode_keepalive();
    uint16_t len;
    uint8_t type;
    CHECK(!check_header(ka, len, type));
    auto bad = ka;
    bad[3] = 0;
    CHECK(check_header(bad, len, type)->subcode == sub::kNotSynced);
    bad = ka;
    bad[18] = 9;
    CHECK(check_header(bad, len, type)->subcode == sub::kBadType);
    bad = ka;
    bad[17] = 20;  // KEEPALIVE must be exactly 19
    CHECK(check_header(bad, len, type)->subcode == sub::kBadLength);
    bad = ka;
    bad[16] = 0x10;  // 4096 + ... too long
    bad[17] = 0x01;
    CHECK(check_header(bad, len, type)->subcode == sub::kBadLength);
}

// ================================================================ UPDATE codec
TEST(update_roundtrip_packs_and_splits) {
    Attrs a = attrs_with({65000, 4200000003u}, 0x0A010100);
    a.med = 50;
    a.unknown.push_back(RawAttr{kOptional | kTransitive | kPartial, 99, {1, 2, 3}});
    std::vector<Prefix> nlri;
    for (uint32_t i = 0; i < 2000; ++i) nlri.push_back(Prefix::make(0x0B000000 + (i << 8), 24));
    std::vector<uint8_t> out;
    encode_announce(a, nlri, out);
    // walk the stream
    size_t off = 0, msgs = 0;
    std::vector<Prefix> got;
    while (off < out.size()) {
        uint16_t len = uint16_t(out[off + 16] << 8 | out[off + 17]);
        CHECK(len <= kMaxMsgLen);
        auto r = decode_message(std::span<const uint8_t>(out.data() + off, len));
        auto* u = std::get_if<Update>(&r);
        CHECK(u && !u->treat_as_withdraw && u->attrs && *u->attrs == a);
        if (u) got.insert(got.end(), u->nlri.begin(), u->nlri.end());
        off += len;
        ++msgs;
    }
    CHECK(got == nlri);
    CHECK(msgs == 2);  // 2000 * 4 bytes does not fit in one 4096-byte message
}

TEST(withdraw_roundtrip_with_odd_lengths) {
    std::vector<Prefix> w = {P("0.0.0.0/0"), P("10.0.0.0/8"), P("10.1.0.0/17"), P("192.168.1.1/32")};
    std::vector<uint8_t> out;
    encode_withdraw(w, out);
    auto r = decode_message(out);
    auto* u = std::get_if<Update>(&r);
    CHECK(u && u->withdrawn == w && u->nlri.empty() && !u->attrs);
}

TEST(as_path_longer_than_255_is_split_into_segments) {
    std::vector<uint32_t> path(300);
    for (size_t i = 0; i < path.size(); ++i) path[i] = uint32_t(100 + i);
    Attrs a = attrs_with(path, 0x0A000001);
    std::vector<uint8_t> out;
    Prefix p = P("10.9.0.0/16");
    encode_announce(a, std::span(&p, 1), out);
    auto r = decode_message(out);
    auto* u = std::get_if<Update>(&r);
    CHECK(u && u->attrs && u->attrs->as_path.size() == 2 && u->attrs->as_path_len() == 300);
}

// ================================================================ RFC 7606
TEST(withdrawn_length_overrun_is_fatal) {
    std::vector<uint8_t> body = {0, 50, 24, 10, 1, 2, 0, 0};
    auto r = decode_update(body);
    auto* e = std::get_if<BgpError>(&r);
    CHECK(e && e->code == kErrUpdate && e->subcode == sub::kMalformedAttrList);
}

TEST(nlri_prefix_len_33_is_fatal) {
    auto r = decode_update(update_body({}, good_attrs(), {33, 10, 0, 0, 0, 0}));
    auto* e = std::get_if<BgpError>(&r);
    CHECK(e && e->subcode == sub::kInvalidNetwork);
}

TEST(nlri_truncated_prefix_is_fatal) {
    auto r = decode_update(update_body({}, good_attrs(), {24, 10, 1}));
    CHECK(std::holds_alternative<BgpError>(r));
}

TEST(invalid_origin_is_treat_as_withdraw) {
    auto at = good_attrs();
    at[3] = 7;
    auto u = decode_ok(update_body({}, at, {24, 10, 1, 2}));
    CHECK(u.treat_as_withdraw);
    CHECK(u.nlri.size() == 1);  // still located, so the caller can withdraw it
}

TEST(missing_next_hop_is_treat_as_withdraw) {
    auto at = good_attrs();
    at.resize(13);
    auto u = decode_ok(update_body({}, at, {24, 10, 1, 2}));
    CHECK(u.treat_as_withdraw);
}

TEST(next_hop_zero_or_multicast_is_treat_as_withdraw) {
    auto at = good_attrs();
    at[16] = 0, at[17] = 0, at[18] = 0, at[19] = 0;
    CHECK(decode_ok(update_body({}, at, {24, 10, 1, 2})).treat_as_withdraw);
    at[16] = 224;
    CHECK(decode_ok(update_body({}, at, {24, 10, 1, 2})).treat_as_withdraw);
}

TEST(as_path_segment_with_zero_count_is_treat_as_withdraw) {
    std::vector<uint8_t> at = {0x40, 1, 1, 0, 0x40, 2, 2, 2, 0, 0x40, 3, 4, 10, 0, 0, 1};
    CHECK(decode_ok(update_body({}, at, {24, 10, 1, 2})).treat_as_withdraw);
}

TEST(as_path_count_overrunning_attribute_is_treat_as_withdraw) {
    std::vector<uint8_t> at = {0x40, 1, 1, 0, 0x40, 2, 6, 2, 2, 0, 0, 0xFD, 0xE9, 0x40, 3, 4, 10, 0, 0, 1};
    CHECK(decode_ok(update_body({}, at, {24, 10, 1, 2})).treat_as_withdraw);
}

TEST(attribute_overrunning_field_is_treat_as_withdraw) {
    auto at = good_attrs();
    at.push_back(0x80);  // MED header claiming 4 bytes, none present
    at.push_back(4);
    at.push_back(4);
    CHECK(decode_ok(update_body({}, at, {24, 10, 1, 2})).treat_as_withdraw);
}

TEST(well_known_with_optional_flag_is_treat_as_withdraw) {
    auto at = good_attrs();
    at[0] = 0xC0;  // ORIGIN marked optional
    CHECK(decode_ok(update_body({}, at, {24, 10, 1, 2})).treat_as_withdraw);
}

TEST(bad_atomic_aggregate_is_discarded_not_withdrawn) {
    auto at = good_attrs();
    std::vector<uint8_t> extra = {0x40, 6, 1, 9};
    at.insert(at.end(), extra.begin(), extra.end());
    auto u = decode_ok(update_body({}, at, {24, 10, 1, 2}));
    CHECK(!u.treat_as_withdraw);
    CHECK(u.attrs && !u.attrs->atomic_aggregate);
}

TEST(duplicate_attribute_keeps_first) {
    auto at = good_attrs();
    std::vector<uint8_t> dup = {0x40, 3, 4, 10, 0, 0, 9};
    at.insert(at.end(), dup.begin(), dup.end());
    auto u = decode_ok(update_body({}, at, {24, 10, 1, 2}));
    CHECK(!u.treat_as_withdraw && u.attrs->next_hop == 0x0A000001);
}

TEST(unrecognized_well_known_is_fatal) {
    auto at = good_attrs();
    std::vector<uint8_t> x = {0x40, 99, 0};
    at.insert(at.end(), x.begin(), x.end());
    auto r = decode_update(update_body({}, at, {24, 10, 1, 2}));
    auto* e = std::get_if<BgpError>(&r);
    CHECK(e && e->subcode == sub::kUnrecognizedWellKnown);
}

TEST(unknown_optional_transitive_kept_nontransitive_dropped) {
    auto at = good_attrs();
    std::vector<uint8_t> x = {0xC0, 99, 1, 7, 0x80, 98, 1, 8};
    at.insert(at.end(), x.begin(), x.end());
    auto u = decode_ok(update_body({}, at, {24, 10, 1, 2}));
    CHECK(u.attrs->unknown.size() == 1 && u.attrs->unknown[0].type == 99);
}

TEST(extended_length_attribute_parses) {
    std::vector<uint8_t> at = {0x40, 1, 1, 0, 0x50, 2, 0, 6, 2, 1, 0, 0, 0xFD, 0xE9, 0x40, 3, 4, 10, 0, 0, 1};
    auto u = decode_ok(update_body({}, at, {24, 10, 1, 2}));
    CHECK(!u.treat_as_withdraw && u.attrs->neighbor_as() == 65001);
}

TEST(as4_path_from_new_speaker_is_ignored) {
    auto at = good_attrs();
    std::vector<uint8_t> x = {0xC0, 17, 6, 2, 1, 0, 0, 0, 7};
    at.insert(at.end(), x.begin(), x.end());
    auto u = decode_ok(update_body({}, at, {24, 10, 1, 2}));
    CHECK(!u.treat_as_withdraw && u.attrs->as_path_len() == 1 && u.attrs->neighbor_as() == 65001);
}

// ================================================================ decision process
struct Fixture {
    PeerInfo a{0x0A000001, 0x01010101, 65001, true};
    PeerInfo b{0x0A000003, 0x02020202, 65002, true};
    PeerInfo c{0x0A000005, 0x03030303, 65000, false};  // iBGP
    Path path(const PeerInfo* from, Attrs at) { return Path{from, std::make_shared<Attrs>(std::move(at))}; }
};

TEST(decision_local_pref_beats_as_path) {
    Fixture f;
    Attrs x = attrs_with({65001, 1, 2, 3}, 1);
    x.local_pref = 200;
    Attrs y = attrs_with({65002}, 2);
    auto v = compare(f.path(&f.a, x), f.path(&f.b, y));
    CHECK(v.cmp < 0 && v.step == Step::LocalPref);
}

TEST(decision_shorter_as_path) {
    Fixture f;
    auto v = compare(f.path(&f.a, attrs_with({65001, 7}, 1)), f.path(&f.b, attrs_with({65002}, 2)));
    CHECK(v.cmp > 0 && v.step == Step::AsPathLen);
}

TEST(decision_as_set_counts_as_one) {
    Fixture f;
    Attrs x = attrs_with({65001}, 1);
    x.as_path.push_back(AsSegment{kAsSet, {5, 6, 7, 8}});
    auto v = compare(f.path(&f.a, x), f.path(&f.b, attrs_with({65002, 9, 9}, 2)));
    CHECK(v.cmp < 0 && v.step == Step::AsPathLen);  // 2 < 3
}

TEST(decision_origin) {
    Fixture f;
    Attrs x = attrs_with({65001}, 1), y = attrs_with({65002}, 2);
    x.origin = kIncomplete;
    auto v = compare(f.path(&f.a, x), f.path(&f.b, y));
    CHECK(v.cmp > 0 && v.step == Step::Origin);
}

TEST(decision_med_only_within_same_neighbor_as) {
    Fixture f;
    PeerInfo a2{0x0A000007, 0x04040404, 65001, true};
    Attrs x = attrs_with({65001}, 1), y = attrs_with({65001}, 2);
    x.med = 10, y.med = 5;
    auto v = compare(f.path(&f.a, x), f.path(&a2, y));
    CHECK(v.cmp > 0 && v.step == Step::Med);
    // Different neighbour AS: MED is skipped, falls through to router id.
    Attrs z = attrs_with({65002}, 3);
    z.med = 5;
    v = compare(f.path(&f.a, x), f.path(&f.b, z));
    CHECK(v.step == Step::RouterId && v.cmp < 0);
}

TEST(decision_missing_med_is_zero) {
    Fixture f;
    PeerInfo a2{0x0A000007, 0x04040404, 65001, true};
    Attrs x = attrs_with({65001}, 1), y = attrs_with({65001}, 2);
    y.med = 1;
    auto v = compare(f.path(&f.a, x), f.path(&a2, y));
    CHECK(v.cmp < 0 && v.step == Step::Med);
}

TEST(decision_ebgp_over_ibgp) {
    Fixture f;
    auto v = compare(f.path(&f.c, attrs_with({65009}, 1)), f.path(&f.b, attrs_with({65002}, 2)));
    CHECK(v.cmp > 0 && v.step == Step::EbgpOverIbgp);
}

TEST(decision_router_id_then_peer_address) {
    Fixture f;
    auto v = compare(f.path(&f.b, attrs_with({65002}, 2)), f.path(&f.a, attrs_with({65001}, 1)));
    CHECK(v.cmp > 0 && v.step == Step::RouterId);
    PeerInfo same_id{0x0A000009, f.a.router_id, 65003, true};
    v = compare(f.path(&same_id, attrs_with({65003}, 3)), f.path(&f.a, attrs_with({65001}, 1)));
    CHECK(v.cmp > 0 && v.step == Step::PeerAddr);
}

TEST(decision_local_route_wins) {
    Fixture f;
    Attrs x = attrs_with({65001}, 1);
    x.local_pref = 1000;
    auto v = compare(Path{nullptr, std::make_shared<Attrs>()}, f.path(&f.a, x));
    CHECK(v.cmp < 0 && v.step == Step::Local);
}

// ================================================================ RIB + multipath
TEST(rib_multipath_equal_as_path) {
    Fixture f;
    PeerInfo s1{0x0A010100, 0x0AFF0001, 65000, true}, s2{0x0A020100, 0x0AFF0002, 65000, true};
    Rib rib(8);
    Prefix p = P("192.168.3.0/24");
    rib.add(p, f.path(&s1, attrs_with({65000, 4200000003u}, s1.addr)));
    rib.add(p, f.path(&s2, attrs_with({65000, 4200000003u}, s2.addr)));
    CHECK(rib.decide(p) == Rib::Change::Added);
    auto* e = rib.lookup(p);
    CHECK(e && e->nexthops.size() == 2 && e->best.from == &s1);
    // Withdraw one: falls back to a single next hop.
    rib.remove(p, &s1);
    CHECK(rib.decide(p) == Rib::Change::Changed);
    CHECK(rib.lookup(p)->nexthops == std::vector<uint32_t>{s2.addr});
    rib.remove(p, &s2);
    CHECK(rib.decide(p) == Rib::Change::Removed);
    CHECK(rib.lookup(p) == nullptr);
}

TEST(rib_no_multipath_for_different_as_path) {
    Fixture f;
    Rib rib(8);
    Prefix p = P("192.168.3.0/24");
    rib.add(p, f.path(&f.a, attrs_with({65001, 7}, 1)));
    rib.add(p, f.path(&f.b, attrs_with({65002, 7}, 2)));
    rib.decide(p);
    CHECK(rib.lookup(p)->nexthops.size() == 1);
}

TEST(rib_maximum_paths_caps_nexthops) {
    Rib rib(2);
    std::vector<PeerInfo> peers;
    for (uint32_t i = 0; i < 4; ++i) peers.push_back(PeerInfo{100 + i, 200 + i, 65000, true});
    Prefix p = P("10.0.0.0/8");
    for (auto& pi : peers) rib.add(p, Path{&pi, std::make_shared<Attrs>(attrs_with({65000}, pi.addr))});
    rib.decide(p);
    CHECK(rib.lookup(p)->nexthops.size() == 2);
}

TEST(rib_unchanged_decision_reports_none) {
    Fixture f;
    Rib rib;
    Prefix p = P("10.0.0.0/8");
    rib.add(p, f.path(&f.a, attrs_with({65001}, 1)));
    rib.decide(p);
    rib.add(p, f.path(&f.a, attrs_with({65001}, 1)));  // same path again (implicit replace)
    CHECK(rib.decide(p) == Rib::Change::None);
}

TEST(rib_drop_peer_removes_only_its_paths) {
    Fixture f;
    Rib rib;
    for (int i = 0; i < 10; ++i) {
        Prefix p = Prefix::make(0x0A000000u + uint32_t(i << 8), 24);
        rib.add(p, f.path(&f.a, attrs_with({65001}, 1)));
        if (i % 2) rib.add(p, f.path(&f.b, attrs_with({65002}, 2)));
    }
    auto gone = rib.drop_peer(&f.a);
    CHECK(gone.size() == 10);
    CHECK(rib.adj_in_paths() == 5);
}

int main() {
    for (auto& [name, fn] : registry()) {
        int before = g_fail;
        fn();
        std::printf("%s %s\n", g_fail == before ? "ok  " : "FAIL", name);
    }
    std::printf("\n%d checks, %d failures, %zu tests\n", g_checks, g_fail, registry().size());
    return g_fail ? 1 : 0;
}
