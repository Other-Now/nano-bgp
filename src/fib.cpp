#include "fib.hpp"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace nbgp {

namespace {
constexpr size_t kBatchBytes = 32 * 1024;

void put_rta(std::vector<uint8_t>& b, uint16_t type, const void* data, size_t len) {
    rtattr a{};
    a.rta_len = uint16_t(RTA_LENGTH(len));
    a.rta_type = type;
    size_t at = b.size();
    b.resize(at + RTA_ALIGN(a.rta_len));
    std::memcpy(&b[at], &a, sizeof a);
    std::memcpy(&b[at + RTA_LENGTH(0)], data, len);
}
}  // namespace

bool Fib::open(std::string& err) {
    fd_ = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd_ < 0) {
        err = std::string("netlink socket: ") + std::strerror(errno);
        return false;
    }
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (bind(fd_, reinterpret_cast<sockaddr*>(&sa), sizeof sa) < 0) {
        err = std::string("netlink bind: ") + std::strerror(errno);
        close(fd_);
        fd_ = -1;
        return false;
    }
    int big = 4 << 20;
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
    return true;
}

void Fib::queue_route(uint16_t type, uint16_t flags, const Prefix& p,
                      const std::vector<uint32_t>& nh) {
    size_t start = buf_.size();
    buf_.resize(start + NLMSG_LENGTH(sizeof(rtmsg)));
    auto* n = reinterpret_cast<nlmsghdr*>(&buf_[start]);
    n->nlmsg_type = type;
    n->nlmsg_flags = uint16_t(NLM_F_REQUEST | NLM_F_ACK | flags);
    n->nlmsg_seq = seq_++;
    auto* r = reinterpret_cast<rtmsg*>(NLMSG_DATA(n));
    *r = rtmsg{};
    r->rtm_family = AF_INET;
    r->rtm_dst_len = p.len;
    r->rtm_table = RT_TABLE_MAIN;
    r->rtm_protocol = kProtoBgp;
    r->rtm_scope = RT_SCOPE_UNIVERSE;
    r->rtm_type = RTN_UNICAST;

    uint32_t dst = htonl(p.addr);
    put_rta(buf_, RTA_DST, &dst, 4);
    if (type == RTM_NEWROUTE) {
        if (nh.size() == 1) {
            uint32_t gw = htonl(nh[0]);
            put_rta(buf_, RTA_GATEWAY, &gw, 4);
        } else {
            // RTA_MULTIPATH: a list of rtnexthop, each followed by its own RTA_GATEWAY.
            // ifindex 0 lets the kernel resolve the device from the gateway.
            std::vector<uint8_t> mp;
            for (uint32_t g : nh) {
                size_t at = mp.size();
                mp.resize(at + RTNH_ALIGN(sizeof(rtnexthop)));
                rtnexthop rh{};
                rh.rtnh_ifindex = 0;
                uint32_t gw = htonl(g);
                std::vector<uint8_t> sub;
                put_rta(sub, RTA_GATEWAY, &gw, 4);
                rh.rtnh_len = uint16_t(RTNH_ALIGN(sizeof(rtnexthop)) + sub.size());
                std::memcpy(&mp[at], &rh, sizeof rh);
                mp.insert(mp.end(), sub.begin(), sub.end());
            }
            put_rta(buf_, RTA_MULTIPATH, mp.data(), mp.size());
        }
    }
    reinterpret_cast<nlmsghdr*>(&buf_[start])->nlmsg_len = uint32_t(buf_.size() - start);
    ++pending_;
    ++ops;
    if (buf_.size() >= kBatchBytes) flush();
}

void Fib::set(const Prefix& p, const std::vector<uint32_t>& nh) {
    if (fd_ < 0 || nh.empty()) return;
    queue_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, p, nh);
}

void Fib::del(const Prefix& p) {
    if (fd_ < 0) return;
    queue_route(RTM_DELROUTE, 0, p, {});
}

void Fib::flush() {
    if (fd_ < 0 || buf_.empty()) return;
    sockaddr_nl to{};
    to.nl_family = AF_NETLINK;
    if (sendto(fd_, buf_.data(), buf_.size(), 0, reinterpret_cast<sockaddr*>(&to), sizeof to) < 0) {
        ++errors;
        last_error = std::string("netlink send: ") + std::strerror(errno);
        buf_.clear();
        pending_ = 0;
        return;
    }
    buf_.clear();
    // One ACK (an NLMSG_ERROR with error 0, or the real error) per message.
    alignas(nlmsghdr) static uint8_t rx[64 * 1024];
    while (pending_ > 0) {
        ssize_t n = recv(fd_, rx, sizeof rx, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            ++errors;
            last_error = std::string("netlink recv: ") + std::strerror(errno);
            break;
        }
        for (auto* h = reinterpret_cast<nlmsghdr*>(rx); NLMSG_OK(h, size_t(n)); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type != NLMSG_ERROR) continue;
            auto* e = reinterpret_cast<nlmsgerr*>(NLMSG_DATA(h));
            // ESRCH on delete = already gone (e.g. the interface went down); not an error.
            if (e->error != 0 && e->error != -ESRCH) {
                ++errors;
                last_error = std::string("netlink: ") + std::strerror(-e->error);
            }
            --pending_;
        }
    }
    pending_ = 0;
}

void Fib::remove_stale() {
    if (fd_ < 0) return;
    // Dump the main table and delete our own routes.
    struct {
        nlmsghdr n;
        rtmsg r;
    } req{};
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    req.n.nlmsg_type = RTM_GETROUTE;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.n.nlmsg_seq = seq_++;
    req.r.rtm_family = AF_INET;
    if (send(fd_, &req, req.n.nlmsg_len, 0) < 0) return;
    std::vector<Prefix> stale;
    alignas(nlmsghdr) static uint8_t rx[64 * 1024];
    bool done = false;
    while (!done) {
        ssize_t n = recv(fd_, rx, sizeof rx, 0);
        if (n <= 0) break;
        for (auto* h = reinterpret_cast<nlmsghdr*>(rx); NLMSG_OK(h, size_t(n)); h = NLMSG_NEXT(h, n)) {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) { done = true; break; }
            auto* r = reinterpret_cast<rtmsg*>(NLMSG_DATA(h));
            if (r->rtm_protocol != kProtoBgp || r->rtm_table != RT_TABLE_MAIN) continue;
            uint32_t dst = 0;
            int len = int(RTM_PAYLOAD(h));
            for (auto* a = RTM_RTA(r); RTA_OK(a, len); a = RTA_NEXT(a, len))
                if (a->rta_type == RTA_DST) std::memcpy(&dst, RTA_DATA(a), 4);
            stale.push_back(Prefix::make(ntohl(dst), r->rtm_dst_len));
        }
    }
    for (auto& p : stale) del(p);
    flush();
}

}  // namespace nbgp
