// Routing tables and the BGP decision process (RFC 4271 section 9.1).
//
//   Adj-RIB-In : every path every peer sent us, per prefix (`in_`)
//   Loc-RIB    : the chosen best path per prefix, plus the equal-cost
//                multipath set that goes to the kernel (`loc_`)
#pragma once
#include <memory>
#include <unordered_map>
#include <vector>

#include "wire.hpp"

namespace nbgp {

// Who a path came from. nullptr in a Path means "originated locally".
struct PeerInfo {
    uint32_t addr = 0;       // peer's IP (tie-break 2)
    uint32_t router_id = 0;  // peer's BGP Identifier (tie-break 1)
    uint32_t remote_as = 0;
    bool ebgp = true;
};

using AttrsPtr = std::shared_ptr<const Attrs>;

struct Path {
    const PeerInfo* from = nullptr;
    AttrsPtr attrs;
    bool operator==(const Path& o) const { return from == o.from && *attrs == *o.attrs; }
};

struct LocEntry {
    Path best;
    std::vector<uint32_t> nexthops;  // sorted; best's next hop + multipath siblings. Empty for local.
};

// The decision steps, in order. compare() reports which step decided.
enum class Step { Local, LocalPref, AsPathLen, Origin, Med, EbgpOverIbgp, RouterId, PeerAddr, Equal };
const char* step_name(Step s);

struct Verdict {
    int cmp;    // <0: a better, >0: b better
    Step step;  // the step that decided
};
Verdict compare(const Path& a, const Path& b);

// True if b can share the forwarding of best a: equal through step 5 and
// (like FRR's default) the identical AS_PATH. Different next hops required.
bool multipath_ok(const Path& best, const Path& other);

class Rib {
public:
    explicit Rib(size_t max_paths = 8) : max_paths_(max_paths) {}

    // Replaces the path from the same peer. True if this peer had no path before.
    bool add(const Prefix& p, Path path);
    bool remove(const Prefix& p, const PeerInfo* from);  // true if something was removed
    // All prefixes this peer contributed to, removed. Returns them.
    std::vector<Prefix> drop_peer(const PeerInfo* from);

    enum class Change { None, Added, Changed, Removed };
    // Re-run the decision process for one prefix and update the Loc-RIB.
    Change decide(const Prefix& p);

    const LocEntry* lookup(const Prefix& p) const;
    const std::unordered_map<Prefix, LocEntry, PrefixHash>& loc() const { return loc_; }
    size_t adj_in_paths() const { return in_paths_; }

private:
    size_t max_paths_;
    size_t in_paths_ = 0;
    std::unordered_map<Prefix, std::vector<Path>, PrefixHash> in_;
    std::unordered_map<Prefix, LocEntry, PrefixHash> loc_;
};

}  // namespace nbgp
