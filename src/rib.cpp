#include "rib.hpp"

#include <algorithm>

namespace nbgp {

const char* step_name(Step s) {
    switch (s) {
        case Step::Local: return "locally-originated";
        case Step::LocalPref: return "local-pref";
        case Step::AsPathLen: return "as-path-length";
        case Step::Origin: return "origin";
        case Step::Med: return "med";
        case Step::EbgpOverIbgp: return "ebgp-over-ibgp";
        case Step::RouterId: return "router-id";
        case Step::PeerAddr: return "peer-address";
        case Step::Equal: return "equal";
    }
    return "?";
}

namespace {
uint32_t lp(const Path& p) { return p.attrs->local_pref.value_or(100); }

// Steps that multipath must tie on. Returns the first step that differs.
Verdict compare_through_ebgp(const Path& a, const Path& b) {
    // 0. A route we originate ourselves beats anything learned (FRR's weight 32768).
    bool la = a.from == nullptr, lb = b.from == nullptr;
    if (la != lb) return {la ? -1 : 1, Step::Local};
    // 1. Highest LOCAL_PREF.
    if (lp(a) != lp(b)) return {lp(a) > lp(b) ? -1 : 1, Step::LocalPref};
    // 2. Shortest AS_PATH.
    size_t aa = a.attrs->as_path_len(), bb = b.attrs->as_path_len();
    if (aa != bb) return {aa < bb ? -1 : 1, Step::AsPathLen};
    // 3. Lowest ORIGIN (IGP < EGP < INCOMPLETE).
    if (a.attrs->origin != b.attrs->origin)
        return {a.attrs->origin < b.attrs->origin ? -1 : 1, Step::Origin};
    // 4. Lowest MED, but only between routes from the same neighbouring AS.
    //    A missing MED counts as 0 (RFC 4271 9.1.2.2 c).
    uint32_t na = a.attrs->neighbor_as(), nb = b.attrs->neighbor_as();
    if (na != 0 && na == nb) {
        uint32_t ma = a.attrs->med.value_or(0), mb = b.attrs->med.value_or(0);
        if (ma != mb) return {ma < mb ? -1 : 1, Step::Med};
    }
    // 5. eBGP over iBGP.
    if (!la) {
        bool ea = a.from->ebgp, eb = b.from->ebgp;
        if (ea != eb) return {ea ? -1 : 1, Step::EbgpOverIbgp};
    }
    return {0, Step::Equal};
}
}  // namespace

Verdict compare(const Path& a, const Path& b) {
    Verdict v = compare_through_ebgp(a, b);
    if (v.cmp != 0 || a.from == nullptr) return v;
    // (6. IGP cost to the next hop: there is no IGP here, every next hop is
    //  directly connected, so this step always ties and is skipped.)
    // 7. Lowest BGP Identifier of the advertising peer.
    if (a.from->router_id != b.from->router_id)
        return {a.from->router_id < b.from->router_id ? -1 : 1, Step::RouterId};
    // 8. Lowest peer address.
    if (a.from->addr != b.from->addr) return {a.from->addr < b.from->addr ? -1 : 1, Step::PeerAddr};
    return {0, Step::Equal};
}

bool multipath_ok(const Path& best, const Path& other) {
    if (best.from == nullptr || other.from == nullptr) return false;
    if (compare_through_ebgp(best, other).cmp != 0) return false;
    if (best.attrs->as_path != other.attrs->as_path) return false;
    return best.attrs->next_hop != other.attrs->next_hop;
}

bool Rib::add(const Prefix& p, Path path) {
    auto& v = in_[p];
    for (auto& e : v)
        if (e.from == path.from) {
            e = std::move(path);
            return false;
        }
    v.push_back(std::move(path));
    ++in_paths_;
    return true;
}

bool Rib::remove(const Prefix& p, const PeerInfo* from) {
    auto it = in_.find(p);
    if (it == in_.end()) return false;
    auto& v = it->second;
    auto e = std::find_if(v.begin(), v.end(), [&](const Path& x) { return x.from == from; });
    if (e == v.end()) return false;
    v.erase(e);
    --in_paths_;
    if (v.empty()) in_.erase(it);
    return true;
}

std::vector<Prefix> Rib::drop_peer(const PeerInfo* from) {
    std::vector<Prefix> out;
    for (auto it = in_.begin(); it != in_.end();) {
        auto& v = it->second;
        auto e = std::find_if(v.begin(), v.end(), [&](const Path& x) { return x.from == from; });
        if (e != v.end()) {
            out.push_back(it->first);
            v.erase(e);
            --in_paths_;
        }
        it = v.empty() ? in_.erase(it) : std::next(it);
    }
    return out;
}

Rib::Change Rib::decide(const Prefix& p) {
    auto it = in_.find(p);
    auto lit = loc_.find(p);
    if (it == in_.end()) {
        if (lit == loc_.end()) return Change::None;
        loc_.erase(lit);
        return Change::Removed;
    }
    const auto& paths = it->second;
    const Path* best = &paths[0];
    for (size_t i = 1; i < paths.size(); ++i)
        if (compare(paths[i], *best).cmp < 0) best = &paths[i];

    LocEntry e{*best, {}};
    if (best->from) {
        e.nexthops.push_back(best->attrs->next_hop);
        for (auto& q : paths) {
            if (e.nexthops.size() >= max_paths_) break;
            if (&q != best && multipath_ok(*best, q) &&
                std::find(e.nexthops.begin(), e.nexthops.end(), q.attrs->next_hop) == e.nexthops.end())
                e.nexthops.push_back(q.attrs->next_hop);
        }
        std::sort(e.nexthops.begin(), e.nexthops.end());
    }

    if (lit == loc_.end()) {
        loc_.emplace(p, std::move(e));
        return Change::Added;
    }
    if (lit->second.best == e.best && lit->second.nexthops == e.nexthops) return Change::None;
    lit->second = std::move(e);
    return Change::Changed;
}

const LocEntry* Rib::lookup(const Prefix& p) const {
    auto it = loc_.find(p);
    return it == loc_.end() ? nullptr : &it->second;
}

}  // namespace nbgp
