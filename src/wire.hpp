// BGP-4 message codec (RFC 4271), 4-octet AS numbers (RFC 6793), and the
// "treat-as-withdraw" error handling of RFC 7606.
//
// Everything here is pure: bytes in, structs out (and back). No sockets, no
// state. That is what makes it easy to unit-test and to fuzz.
#pragma once
#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace nbgp {

// ---------------------------------------------------------------- prefixes
struct Prefix {
    uint32_t addr = 0;  // host byte order, host bits always zero
    uint8_t len = 0;
    auto operator<=>(const Prefix&) const = default;
    std::string str() const;
    static std::optional<Prefix> parse(std::string_view s);
    static Prefix make(uint32_t addr, uint8_t len);  // masks host bits
};
struct PrefixHash {
    size_t operator()(const Prefix& p) const noexcept {
        return (size_t(p.addr) * 0x9E3779B97F4A7C15ull) ^ p.len;
    }
};
std::string ip_str(uint32_t host_order);
std::optional<uint32_t> parse_ip(std::string_view s);

// ---------------------------------------------------------------- constants
constexpr size_t kHeaderLen = 19;
constexpr size_t kMaxMsgLen = 4096;
constexpr uint16_t kAsTrans = 23456;

enum MsgType : uint8_t { kOpen = 1, kUpdate = 2, kNotification = 3, kKeepalive = 4 };
enum Origin : uint8_t { kIgp = 0, kEgp = 1, kIncomplete = 2 };
enum AsSegType : uint8_t { kAsSet = 1, kAsSequence = 2 };
enum AttrType : uint8_t {
    kAttrOrigin = 1, kAttrAsPath = 2, kAttrNextHop = 3, kAttrMed = 4,
    kAttrLocalPref = 5, kAttrAtomicAggregate = 6, kAttrAggregator = 7,
    kAttrMpReach = 14, kAttrMpUnreach = 15, kAttrAs4Path = 17, kAttrAs4Aggregator = 18,
};
enum AttrFlag : uint8_t { kOptional = 0x80, kTransitive = 0x40, kPartial = 0x20, kExtLen = 0x10 };

// NOTIFICATION error codes (RFC 4271 section 4.5) and the subcodes we use.
enum ErrCode : uint8_t {
    kErrHeader = 1, kErrOpen = 2, kErrUpdate = 3, kErrHoldTimer = 4, kErrFsm = 5, kErrCease = 6,
};
namespace sub {
constexpr uint8_t kNotSynced = 1, kBadLength = 2, kBadType = 3;                         // header
constexpr uint8_t kBadVersion = 1, kBadPeerAs = 2, kBadBgpId = 3, kBadOptParam = 4,
                  kBadHoldTime = 6, kUnsupportedCap = 7;                               // open
constexpr uint8_t kMalformedAttrList = 1, kUnrecognizedWellKnown = 2, kMissingWellKnown = 3,
                  kAttrFlags = 4, kAttrLength = 5, kInvalidOrigin = 6, kInvalidNextHop = 8,
                  kOptAttrError = 9, kInvalidNetwork = 10, kMalformedAsPath = 11;      // update
constexpr uint8_t kAdminShutdown = 2, kAdminReset = 4, kCollision = 7;                // cease
}  // namespace sub

// ---------------------------------------------------------------- messages
struct AsSegment {
    uint8_t type = kAsSequence;
    std::vector<uint32_t> asns;
    bool operator==(const AsSegment&) const = default;
};

struct RawAttr {  // an optional transitive attribute we don't understand; passed on
    uint8_t flags = 0, type = 0;
    std::vector<uint8_t> value;
    bool operator==(const RawAttr&) const = default;
};

struct Attrs {
    uint8_t origin = kIgp;
    std::vector<AsSegment> as_path;
    uint32_t next_hop = 0;
    std::optional<uint32_t> med;
    std::optional<uint32_t> local_pref;
    bool atomic_aggregate = false;
    std::optional<std::pair<uint32_t, uint32_t>> aggregator;  // (asn, ip)
    std::vector<RawAttr> unknown;
    bool operator==(const Attrs&) const = default;

    size_t as_path_len() const;  // an AS_SET counts as 1 (RFC 4271 9.1.2.2 a)
    uint32_t neighbor_as() const;  // first AS of the leading AS_SEQUENCE, 0 if none
    bool contains_as(uint32_t asn) const;
    std::string as_path_str() const;
};

struct Open {
    uint8_t version = 4;
    uint16_t my_as = 0;      // the 2-octet field (AS_TRANS if the real AS doesn't fit)
    uint16_t hold_time = 0;
    uint32_t bgp_id = 0;
    std::optional<uint32_t> as4;  // capability 65, the real AS
    bool mp_ipv4_unicast = false; // capability 1, AFI 1 / SAFI 1
    std::vector<uint8_t> other_caps;  // codes only, for logging
    uint32_t asn() const { return as4 ? *as4 : my_as; }
};

struct Update {
    std::vector<Prefix> withdrawn;
    std::optional<Attrs> attrs;  // present iff the attribute section was non-empty
    std::vector<Prefix> nlri;
    // RFC 7606: an attribute was malformed but the NLRI could still be located.
    // The receiver must withdraw `nlri` instead of resetting the session.
    bool treat_as_withdraw = false;
    std::string error;  // what was wrong (also set for discarded attributes)
};

struct Notification {
    uint8_t code = 0, subcode = 0;
    std::vector<uint8_t> data;
};

// A decode error that must reset the session with this NOTIFICATION.
struct BgpError {
    uint8_t code = 0, subcode = 0;
    std::vector<uint8_t> data;
    std::string what;
};

// ---------------------------------------------------------------- decode
// `hdr` must be at least 19 bytes. On success returns nullopt and fills len/type.
std::optional<BgpError> check_header(std::span<const uint8_t> hdr, uint16_t& len, uint8_t& type);
// Bodies exclude the 19-byte header.
std::variant<Open, BgpError> decode_open(std::span<const uint8_t> body);
std::variant<Update, BgpError> decode_update(std::span<const uint8_t> body);
Notification decode_notification(std::span<const uint8_t> body);

// Whole-message convenience used by the fuzzer and tests.
using AnyMsg = std::variant<Open, Update, Notification, std::monostate /*keepalive*/, BgpError>;
AnyMsg decode_message(std::span<const uint8_t> msg);

// ---------------------------------------------------------------- encode
std::vector<uint8_t> encode_open(const Open& o);
std::vector<uint8_t> encode_keepalive();
std::vector<uint8_t> encode_notification(const Notification& n);
void encode_attrs(const Attrs& a, std::vector<uint8_t>& out);
// Append as many UPDATE messages as needed (each <= 4096 bytes) to `out`.
void encode_announce(const Attrs& a, std::span<const Prefix> nlri, std::vector<uint8_t>& out);
void encode_withdraw(std::span<const Prefix> prefixes, std::vector<uint8_t>& out);

std::string notification_str(uint8_t code, uint8_t subcode);

}  // namespace nbgp
