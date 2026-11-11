// Install Loc-RIB routes into the Linux kernel FIB over rtnetlink.
//
// Routes are queued and sent in batches: many RTM_NEWROUTE/DELROUTE messages
// per sendmsg(), then the ACKs are drained. One round trip per route would
// cap us at a few tens of thousands of routes per second.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "wire.hpp"

namespace nbgp {

class Fib {
public:
    static constexpr uint8_t kProtoBgp = 186;  // RTPROT_BGP, what `ip route` prints as "proto bgp"

    bool open(std::string& err);
    void set(const Prefix& p, const std::vector<uint32_t>& nexthops);  // replace
    void del(const Prefix& p);
    void flush();          // send everything queued, collect ACKs
    void remove_stale();   // delete every proto-bgp route (left over from a previous run)
    bool enabled() const { return fd_ >= 0; }

    uint64_t ops = 0, errors = 0;
    std::string last_error;

private:
    void queue_route(uint16_t type, uint16_t flags, const Prefix& p, const std::vector<uint32_t>& nh);
    int fd_ = -1;
    uint32_t seq_ = 1;
    std::vector<uint8_t> buf_;
    size_t pending_ = 0;
};

}  // namespace nbgp
