#include "speaker.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>

namespace nbgp {

// ================================================================ utilities
uint64_t now_ms() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000 + uint64_t(ts.tv_nsec) / 1000000;
}

void logf(const char* fmt, ...) {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    tm t;
    localtime_r(&ts.tv_sec, &t);
    std::fprintf(stderr, "%02d:%02d:%02d.%03ld ", t.tm_hour, t.tm_min, t.tm_sec, ts.tv_nsec / 1000000);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fputc('\n', stderr);
}

namespace {
volatile std::sig_atomic_t g_stop = 0;

uint32_t sock_addr(int fd, bool peer) {
    sockaddr_in sa{};
    socklen_t l = sizeof sa;
    int r = peer ? getpeername(fd, reinterpret_cast<sockaddr*>(&sa), &l)
                 : getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &l);
    return r == 0 ? ntohl(sa.sin_addr.s_addr) : 0;
}

std::string json_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') o += '\\';
        if (static_cast<unsigned char>(c) < 0x20) continue;
        o += c;
    }
    return o;
}
}  // namespace

void Speaker::request_stop() { g_stop = 1; }

// ================================================================ config
// One directive per line, '#' comments:
//   name leaf1 | asn 4200000001 | router-id 10.255.1.1 | hold-time 3
//   connect-retry 1 | listen 0.0.0.0 | port 179 | maximum-paths 8 | fib on|off
//   control /run/nbgp/leaf1.sock | network 192.168.1.0/24
//   neighbor 10.1.1.0 remote-as 65000 [passive]
std::optional<Config> Config::load(const std::string& path, std::string& err) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open " + path;
        return std::nullopt;
    }
    Config c;
    std::string line;
    int ln = 0;
    auto fail = [&](const std::string& why) {
        err = path + ":" + std::to_string(ln) + ": " + why;
        return std::nullopt;
    };
    while (std::getline(in, line)) {
        ++ln;
        if (auto h = line.find('#'); h != std::string::npos) line.resize(h);
        std::istringstream ss(line);
        std::string k;
        if (!(ss >> k)) continue;
        std::string v;
        ss >> v;
        auto num = [&](uint64_t max) -> std::optional<uint64_t> {
            try {
                size_t used = 0;
                uint64_t x = std::stoull(v, &used);
                if (used != v.size() || x > max) return std::nullopt;
                return x;
            } catch (...) {
                return std::nullopt;
            }
        };
        if (k == "name") c.name = v;
        else if (k == "asn") { auto x = num(0xFFFFFFFFull); if (!x || !*x) return fail("bad asn"); c.asn = uint32_t(*x); }
        else if (k == "router-id") { auto x = parse_ip(v); if (!x) return fail("bad router-id"); c.router_id = *x; }
        else if (k == "hold-time") {
            auto x = num(65535);
            if (!x || *x == 1 || *x == 2) return fail("hold-time must be 0 or >= 3");
            c.hold_time = uint16_t(*x);
        }
        else if (k == "connect-retry") { auto x = num(3600); if (!x || !*x) return fail("bad connect-retry"); c.connect_retry = uint16_t(*x); }
        else if (k == "listen") { auto x = parse_ip(v); if (!x) return fail("bad listen"); c.listen_addr = *x; }
        else if (k == "port") { auto x = num(65535); if (!x) return fail("bad port"); c.port = uint16_t(*x); }
        else if (k == "maximum-paths") { auto x = num(64); if (!x || !*x) return fail("bad maximum-paths"); c.max_paths = *x; }
        else if (k == "fib") c.fib = (v == "on");
        else if (k == "fast-failover") c.fast_failover = (v == "on");
        else if (k == "control") c.control = v;
        else if (k == "network") { auto p = Prefix::parse(v); if (!p) return fail("bad prefix"); c.networks.push_back(*p); }
        else if (k == "neighbor") {
            NeighborCfg n;
            auto a = parse_ip(v);
            std::string kw, as;
            ss >> kw >> as;
            if (!a || kw != "remote-as") return fail("neighbor <ip> remote-as <asn> [passive]");
            v = as;
            auto x = num(0xFFFFFFFFull);
            if (!x || !*x) return fail("bad remote-as");
            n.addr = *a;
            n.remote_as = uint32_t(*x);
            std::string opt;
            while (ss >> opt) {
                if (opt == "passive") n.passive = true;
                else return fail("unknown neighbor option " + opt);
            }
            c.neighbors.push_back(n);
        }
        else return fail("unknown directive " + k);
    }
    if (!c.asn || !c.router_id) {
        err = path + ": asn and router-id are required";
        return std::nullopt;
    }
    return c;
}

const char* Peer::state() const {
    if (est) return "Established";
    const char* s = admin_down ? "Idle" : "Active";
    int best = -1;
    for (auto& c : conns) {
        if (c->dead || int(c->st) <= best) continue;
        best = int(c->st);
        static const char* names[] = {"Connect", "OpenSent", "OpenConfirm", "Established"};
        s = names[best];
    }
    return s;
}

// ================================================================ setup
Speaker::Speaker(Config cfg) : cfg_(std::move(cfg)), rib_(cfg_.max_paths) {
    for (auto& n : cfg_.neighbors) {
        auto p = std::make_unique<Peer>();
        p->cfg = n;
        p->info.addr = n.addr;
        p->info.remote_as = n.remote_as;
        p->info.ebgp = n.remote_as != cfg_.asn;
        peers_.push_back(std::move(p));
    }
}

int Speaker::run() {
    std::signal(SIGPIPE, SIG_IGN);
    ep_ = epoll_create1(EPOLL_CLOEXEC);

    if (cfg_.fib) {
        std::string err;
        if (!fib_.open(err)) {
            logf("fib disabled: %s", err.c_str());
        } else {
            fib_.remove_stale();
        }
    }
    link_fd_ = fib_.open_link_monitor();
    if (link_fd_ >= 0) {
        epoll_event lev{EPOLLIN, {.ptr = &link_}};
        epoll_ctl(ep_, EPOLL_CTL_ADD, link_fd_, &lev);
    } else {
        logf("link monitor unavailable: %s", std::strerror(errno));
    }

    // Listening socket.
    listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    int one = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(cfg_.port);
    sa.sin_addr.s_addr = htonl(cfg_.listen_addr);
    if (bind(listen_fd_, reinterpret_cast<sockaddr*>(&sa), sizeof sa) < 0 || listen(listen_fd_, 64) < 0) {
        logf("listen on %s:%u: %s", ip_str(cfg_.listen_addr).c_str(), cfg_.port, std::strerror(errno));
        return 1;
    }
    epoll_event ev{EPOLLIN, {.ptr = &listen_}};
    epoll_ctl(ep_, EPOLL_CTL_ADD, listen_fd_, &ev);

    // Control socket.
    if (!cfg_.control.empty()) {
        control_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        sockaddr_un su{};
        su.sun_family = AF_UNIX;
        std::snprintf(su.sun_path, sizeof su.sun_path, "%s", cfg_.control.c_str());
        unlink(su.sun_path);
        if (bind(control_fd_, reinterpret_cast<sockaddr*>(&su), sizeof su) < 0 || listen(control_fd_, 16) < 0) {
            logf("control socket %s: %s", cfg_.control.c_str(), std::strerror(errno));
            return 1;
        }
        epoll_event cev{EPOLLIN, {.ptr = &control_}};
        epoll_ctl(ep_, EPOLL_CTL_ADD, control_fd_, &cev);
    }

    logf("%s: AS %u router-id %s, %zu neighbors, hold %us", cfg_.name.c_str(), cfg_.asn,
         ip_str(cfg_.router_id).c_str(), peers_.size(), cfg_.hold_time);
    for (auto& p : cfg_.networks) originate(p, true);

    epoll_event evs[64];
    while (!g_stop) {
        // Sleep until the next timer, at most 100 ms.
        uint64_t now = now_ms(), next = now + 100;
        for (auto& p : peers_) {
            if (p->conns.empty() && !p->admin_down && !p->cfg.passive) next = std::min(next, p->retry_at);
            for (auto& c : p->conns) {
                if (c->hold_deadline) next = std::min(next, c->hold_deadline);
                if (c->ka_deadline) next = std::min(next, c->ka_deadline);
            }
        }
        int timeout = next > now ? int(next - now) : 0;
        int n = epoll_wait(ep_, evs, 64, timeout);
        if (n < 0 && errno != EINTR) {
            logf("epoll_wait: %s", std::strerror(errno));
            break;
        }
        for (int i = 0; i < n; ++i) {
            auto* pl = static_cast<Pollable*>(evs[i].data.ptr);
            if (pl->kind == Pollable::kListen) on_accept();
            else if (pl->kind == Pollable::kControl) on_control();
            else if (pl->kind == Pollable::kLink) { if (fib_.drain_link_events(link_fd_)) on_link_change(); }
            else on_conn_event(static_cast<Conn*>(pl), evs[i].events);
        }
        timers();
        process_dirty();
        for (auto& p : peers_)
            for (auto& c : p->conns)
                if (!c->dead && c->woff < c->wbuf.size()) flush_conn(c.get());
        sweep();
    }

    logf("shutting down");
    for (auto& p : peers_)
        for (auto& c : p->conns)
            if (!c->dead)
                close_conn(c.get(), Notification{kErrCease, sub::kAdminShutdown, {}}, "shutdown");
    sweep();
    if (fib_.enabled()) fib_.remove_stale();
    if (!cfg_.control.empty()) unlink(cfg_.control.c_str());
    return 0;
}

// ================================================================ sockets
void Speaker::start_connect(Peer& p) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(cfg_.port);
    sa.sin_addr.s_addr = htonl(p.cfg.addr);
    int r = connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa);
    if (r < 0 && errno != EINPROGRESS) {
        p.retry_at = now_ms() + cfg_.connect_retry * 1000ull;
        close(fd);
        return;
    }
    auto c = std::make_unique<Conn>();
    c->fd = fd;
    c->peer = &p;
    c->st = Conn::Connecting;
    c->hold_deadline = now_ms() + cfg_.connect_retry * 1000ull;  // connect timeout
    epoll_event ev{EPOLLIN | EPOLLOUT, {.ptr = c.get()}};
    c->want_out = true;
    epoll_ctl(ep_, EPOLL_CTL_ADD, fd, &ev);
    p.conns.push_back(std::move(c));
}

static Open make_open(const Config& cfg) {
    Open o;
    o.my_as = cfg.asn > 65535 ? kAsTrans : uint16_t(cfg.asn);
    o.hold_time = cfg.hold_time;
    o.bgp_id = cfg.router_id;
    o.as4 = cfg.asn;
    o.mp_ipv4_unicast = true;
    return o;
}

void Speaker::on_accept() {
    for (;;) {
        sockaddr_in sa{};
        socklen_t l = sizeof sa;
        int fd = accept4(listen_fd_, reinterpret_cast<sockaddr*>(&sa), &l, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;
        uint32_t from = ntohl(sa.sin_addr.s_addr);
        Peer* p = nullptr;
        for (auto& x : peers_)
            if (x->cfg.addr == from) p = x.get();
        // Unknown peer, shut down, or already Established: refuse (RFC 4271 6.8:
        // a new connection while Established loses the collision).
        if (!p || p->admin_down || p->est) {
            close(fd);
            continue;
        }
        // A pending outbound connect that hasn't completed yet loses to a live TCP session.
        for (auto& c : p->conns)
            if (!c->dead && c->st == Conn::Connecting) close_conn(c.get(), std::nullopt, "replaced by inbound");
        auto c = std::make_unique<Conn>();
        c->fd = fd;
        c->peer = p;
        c->inbound = true;
        c->local_addr = sock_addr(fd, false);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        epoll_event ev{EPOLLIN, {.ptr = c.get()}};
        epoll_ctl(ep_, EPOLL_CTL_ADD, fd, &ev);
        Conn* raw = c.get();
        p->conns.push_back(std::move(c));
        send(raw, encode_open(make_open(cfg_)));
        raw->st = Conn::OpenSent;
        raw->hold_deadline = now_ms() + 240'000;  // RFC 4271: "large" hold timer until OPEN
    }
}

void Speaker::on_conn_event(Conn* c, uint32_t events) {
    if (c->dead) return;
    if (c->st == Conn::Connecting) {
        if (!(events & (EPOLLOUT | EPOLLERR | EPOLLHUP))) return;
        int e = 0;
        socklen_t l = sizeof e;
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &e, &l);
        if (e != 0) {
            c->peer->last_error = std::string("connect: ") + std::strerror(e);
            close_conn(c, std::nullopt, c->peer->last_error);
            return;
        }
        c->local_addr = sock_addr(c->fd, false);
        int one = 1;
        setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        c->st = Conn::OpenSent;
        c->hold_deadline = now_ms() + 240'000;
        send(c, encode_open(make_open(cfg_)));
        return;
    }
    if (events & EPOLLIN || events & EPOLLHUP || events & EPOLLERR) read_conn(c);
    if (!c->dead && (events & EPOLLOUT)) flush_conn(c);
}

void Speaker::read_conn(Conn* c) {
    uint8_t tmp[65536];
    bool eof = false;
    for (;;) {
        ssize_t n = ::recv(c->fd, tmp, sizeof tmp, 0);
        if (n > 0) {
            c->rbuf.insert(c->rbuf.end(), tmp, tmp + n);
            if (size_t(n) < sizeof tmp) break;
            continue;
        }
        if (n == 0) eof = true;
        else if (errno == EINTR) continue;
        else if (errno != EAGAIN) eof = true;
        break;
    }
    size_t off = 0;
    while (!c->dead && c->rbuf.size() - off >= kHeaderLen) {
        uint16_t len;
        uint8_t type;
        std::span<const uint8_t> hdr(c->rbuf.data() + off, kHeaderLen);
        if (auto e = check_header(hdr, len, type)) {
            close_conn(c, Notification{e->code, e->subcode, e->data}, "header: " + e->what);
            return;
        }
        if (c->rbuf.size() - off < len) break;
        on_message(c, type, std::span<const uint8_t>(c->rbuf.data() + off + kHeaderLen, len - kHeaderLen));
        off += len;
    }
    if (c->dead) return;
    c->rbuf.erase(c->rbuf.begin(), c->rbuf.begin() + off);
    if (eof) close_conn(c, std::nullopt, "connection closed by peer");
}

void Speaker::send(Conn* c, const std::vector<uint8_t>& bytes) {
    c->wbuf.insert(c->wbuf.end(), bytes.begin(), bytes.end());
    flush_conn(c);
}

void Speaker::flush_conn(Conn* c) {
    while (c->woff < c->wbuf.size()) {
        ssize_t n = ::send(c->fd, c->wbuf.data() + c->woff, c->wbuf.size() - c->woff, MSG_NOSIGNAL);
        if (n > 0) {
            c->woff += size_t(n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EAGAIN) break;
        close_conn(c, std::nullopt, std::string("send: ") + std::strerror(errno));
        return;
    }
    if (c->woff == c->wbuf.size()) {
        c->wbuf.clear();
        c->woff = 0;
    } else if (c->woff > (1u << 20)) {
        c->wbuf.erase(c->wbuf.begin(), c->wbuf.begin() + c->woff);
        c->woff = 0;
    }
    bool want = !c->wbuf.empty();
    if (want != c->want_out) {
        epoll_event ev{EPOLLIN | (want ? EPOLLOUT : 0u), {.ptr = c}};
        epoll_ctl(ep_, EPOLL_CTL_MOD, c->fd, &ev);
        c->want_out = want;
    }
}

void Speaker::close_conn(Conn* c, std::optional<Notification> why, const std::string& reason) {
    if (c->dead) return;
    Peer& p = *c->peer;
    if (why) {
        // Best effort: whatever is already queued, then the NOTIFICATION.
        auto bytes = encode_notification(*why);
        c->wbuf.insert(c->wbuf.end(), bytes.begin(), bytes.end());
        while (c->woff < c->wbuf.size()) {
            ssize_t n = ::send(c->fd, c->wbuf.data() + c->woff, c->wbuf.size() - c->woff, MSG_NOSIGNAL);
            if (n <= 0) break;
            c->woff += size_t(n);
        }
        p.last_error = "sent " + notification_str(why->code, why->subcode) + " (" + reason + ")";
    }
    static const char* names[] = {"Connect", "OpenSent", "OpenConfirm", "Established"};
    logf("peer %s: close %s conn in %s: %s", ip_str(p.cfg.addr).c_str(), c->inbound ? "inbound" : "outbound",
         names[c->st], reason.c_str());
    c->dead = true;
    epoll_ctl(ep_, EPOLL_CTL_DEL, c->fd, nullptr);
    close(c->fd);
    c->fd = -1;
    if (p.est == c) on_session_down(p);
    bool any_live = std::any_of(p.conns.begin(), p.conns.end(), [](auto& x) { return !x->dead; });
    if (!any_live) p.retry_at = now_ms() + cfg_.connect_retry * 1000ull;
}

void Speaker::sweep() {
    for (auto& p : peers_) {
        auto& v = p->conns;
        for (auto it = v.begin(); it != v.end();) {
            if ((*it)->dead) it = v.erase(it);
            else ++it;
        }
    }
}

// ================================================================ FSM
void Speaker::on_message(Conn* c, uint8_t type, std::span<const uint8_t> body) {
    Peer& p = *c->peer;
    // Any KEEPALIVE or UPDATE (and the OPEN) restarts the hold timer.
    if (c->hold) c->hold_deadline = now_ms() + c->hold * 1000ull;

    if (type == kNotification) {
        auto n = decode_notification(body);
        p.last_error = "received " + notification_str(n.code, n.subcode);
        close_conn(c, std::nullopt, p.last_error);
        return;
    }
    switch (c->st) {
        case Conn::OpenSent:
            if (type != kOpen) break;
            {
                auto r = decode_open(body);
                if (auto* e = std::get_if<BgpError>(&r)) {
                    close_conn(c, Notification{e->code, e->subcode, e->data}, "OPEN: " + e->what);
                    return;
                }
                on_open(c, std::get<Open>(r));
            }
            return;
        case Conn::OpenConfirm:
            if (type != kKeepalive) break;
            on_established(p, c);
            return;
        case Conn::Established:
            if (type == kKeepalive) return;
            if (type != kUpdate) break;
            {
                auto r = decode_update(body);
                if (auto* e = std::get_if<BgpError>(&r)) {
                    close_conn(c, Notification{e->code, e->subcode, e->data}, "UPDATE: " + e->what);
                    return;
                }
                on_update(p, std::get<Update>(r));
            }
            return;
        default:
            break;
    }
    close_conn(c, Notification{kErrFsm, 0, {}},
               "unexpected message type " + std::to_string(type) + " in state " + std::to_string(c->st));
}

void Speaker::on_open(Conn* c, const Open& o) {
    Peer& p = *c->peer;
    auto reject = [&](uint8_t subcode, std::vector<uint8_t> data, const std::string& why) {
        close_conn(c, Notification{kErrOpen, subcode, std::move(data)}, "OPEN: " + why);
    };
    if (o.version != 4) return reject(sub::kBadVersion, {0, 4}, "version " + std::to_string(o.version));
    // We only speak 4-octet AS paths, so the peer must too (RFC 6793 capability 65).
    if (!o.as4) return reject(sub::kUnsupportedCap, {65, 4, 0, 0, 0, 0}, "peer lacks 4-octet AS capability");
    if (o.asn() != p.cfg.remote_as)
        return reject(sub::kBadPeerAs, {}, "peer AS " + std::to_string(o.asn()) + ", expected " +
                                               std::to_string(p.cfg.remote_as));
    if (o.hold_time == 1 || o.hold_time == 2) return reject(sub::kBadHoldTime, {}, "hold time 1 or 2");
    if (o.bgp_id == 0 || o.bgp_id == 0xFFFFFFFF || (o.bgp_id == cfg_.router_id && !p.info.ebgp))
        return reject(sub::kBadBgpId, {}, "bad BGP identifier " + ip_str(o.bgp_id));

    c->remote_id = o.bgp_id;
    c->hold = std::min(cfg_.hold_time, o.hold_time);
    c->st = Conn::OpenConfirm;
    send(c, encode_keepalive());
    uint64_t now = now_ms();
    c->hold_deadline = c->hold ? now + c->hold * 1000ull : 0;
    c->ka_deadline = c->hold ? now + (c->hold * 1000ull) / 3 : 0;
    resolve_collision(p, c);
}

// RFC 4271 6.8: two TCP connections to the same peer. Keep the one opened by
// the speaker with the higher BGP Identifier; close the other with Cease/7.
void Speaker::resolve_collision(Peer& p, Conn* c) {
    for (auto& o : p.conns) {
        Conn* other = o.get();
        if (other == c || other->dead || other->st == Conn::Connecting) continue;
        bool keep_inbound = cfg_.router_id < c->remote_id;  // the peer's opener wins
        Conn* loser = (c->inbound == keep_inbound) ? other : c;
        logf("peer %s: connection collision, keeping %s (local id %s, remote id %s)",
             ip_str(p.cfg.addr).c_str(), keep_inbound ? "inbound" : "outbound",
             ip_str(cfg_.router_id).c_str(), ip_str(c->remote_id).c_str());
        close_conn(loser, Notification{kErrCease, sub::kCollision, {}}, "collision resolution");
        if (loser == c) return;
    }
}

void Speaker::on_established(Peer& p, Conn* c) {
    c->st = Conn::Established;
    p.est = c;
    p.up_since = now_ms();
    p.info.router_id = c->remote_id;
    p.last_error.clear();
    for (auto& o : p.conns)
        if (o.get() != c && !o->dead) close_conn(o.get(), Notification{kErrCease, sub::kCollision, {}}, "already established");
    logf("peer %s: Established (AS %u, hold %us, %s)", ip_str(p.cfg.addr).c_str(), p.cfg.remote_as, c->hold,
         c->inbound ? "inbound" : "outbound");
    // Send the full table.
    std::vector<Prefix> all;
    all.reserve(rib_.loc().size());
    for (auto& [pfx, e] : rib_.loc()) all.push_back(pfx);
    std::sort(all.begin(), all.end());
    export_to(p, all);
}

void Speaker::on_session_down(Peer& p) {
    logf("peer %s: session down (%s)", ip_str(p.cfg.addr).c_str(), p.last_error.c_str());
    p.est = nullptr;
    ++p.flaps;
    p.adj_out.clear();
    p.pfx_rcvd = 0;
    for (auto& pfx : rib_.drop_peer(&p.info)) mark(pfx);
}

void Speaker::timers() {
    uint64_t now = now_ms();
    for (auto& pp : peers_) {
        Peer& p = *pp;
        bool have_live = std::any_of(p.conns.begin(), p.conns.end(), [](auto& c) { return !c->dead; });
        if (!have_live && !p.admin_down && !p.cfg.passive && now >= p.retry_at) start_connect(p);
        for (size_t i = 0; i < p.conns.size(); ++i) {
            Conn* c = p.conns[i].get();
            if (c->dead) continue;
            if (c->hold_deadline && now >= c->hold_deadline) {
                if (c->st == Conn::Connecting) close_conn(c, std::nullopt, "connect timeout");
                else close_conn(c, Notification{kErrHoldTimer, 0, {}}, "hold timer expired");
                continue;
            }
            if (c->ka_deadline && now >= c->ka_deadline) {
                send(c, encode_keepalive());
                c->ka_deadline = now + (c->hold * 1000ull) / 3;
            }
        }
    }
}

// A link went up or down somewhere.
//  1. fast-external-failover: an eBGP session whose local address sits on an
//     interface without carrier is dead; don't wait for the hold timer.
//  2. The kernel has deleted every route through a device that went down, and
//     won't put them back when it comes up. A flap shorter than the hold time
//     leaves the session (and so the RIB) untouched, so nothing else would
//     ever reinstall them: push the whole Loc-RIB again.
void Speaker::on_link_change() {
    ++link_events_;
    if (cfg_.fast_failover) {
        std::unordered_map<uint32_t, bool> running;  // local IPv4 -> interface has carrier
        ifaddrs* ifs = nullptr;
        if (getifaddrs(&ifs) == 0) {
            for (auto* i = ifs; i; i = i->ifa_next) {
                if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
                uint32_t a = ntohl(reinterpret_cast<sockaddr_in*>(i->ifa_addr)->sin_addr.s_addr);
                running[a] = (i->ifa_flags & IFF_UP) && (i->ifa_flags & IFF_RUNNING);
            }
            freeifaddrs(ifs);
            for (auto& p : peers_) {
                if (!p->est || !p->info.ebgp) continue;
                auto it = running.find(p->est->local_addr);
                if (it == running.end() || !it->second)
                    close_conn(p->est, std::nullopt, "interface down (fast-external-failover)");
            }
        }
    }
    process_dirty();
    if (fib_.enabled()) {
        ++fib_resyncs_;
        for (auto& [pfx, e] : rib_.loc())
            if (!e.nexthops.empty()) fib_.set(pfx, e.nexthops);
        fib_.flush();
    }
}

// ================================================================ routes
void Speaker::mark(const Prefix& pfx) {
    if (dirty_set_.insert(pfx).second) dirty_.push_back(pfx);
}

void Speaker::originate(const Prefix& pfx, bool add) {
    if (add) {
        auto a = std::make_shared<Attrs>();
        a->origin = kIgp;
        rib_.add(pfx, Path{nullptr, a});
    } else {
        rib_.remove(pfx, nullptr);
    }
    mark(pfx);
}

void Speaker::on_update(Peer& p, Update& u) {
    ++p.updates_rx;
    for (auto& pfx : u.withdrawn)
        if (rib_.remove(pfx, &p.info)) { --p.pfx_rcvd; mark(pfx); }
    if (u.nlri.empty()) return;

    std::string why;
    if (u.treat_as_withdraw) why = u.error;
    AttrsPtr shared;
    if (why.empty()) {
        auto a = std::make_shared<Attrs>(std::move(*u.attrs));
        if (p.info.ebgp) {
            a->local_pref.reset();  // LOCAL_PREF from an external peer is ignored
            if (a->neighbor_as() != p.cfg.remote_as)
                why = "first AS " + std::to_string(a->neighbor_as()) + " is not the peer's AS";
        }
        if (a->contains_as(cfg_.asn)) why = "AS loop";  // normal, not an error: silently dropped
        shared = std::move(a);
    }
    if (!why.empty()) {
        // Treat-as-withdraw (RFC 7606) or loop: these NLRI must not be used.
        if (why != "AS loop") {
            ++p.taw;
            logf("peer %s: treat-as-withdraw %zu prefixes: %s", ip_str(p.cfg.addr).c_str(), u.nlri.size(), why.c_str());
        }
        for (auto& pfx : u.nlri)
            if (rib_.remove(pfx, &p.info)) { --p.pfx_rcvd; mark(pfx); }
        return;
    }
    for (auto& pfx : u.nlri) {
        if (rib_.add(pfx, Path{&p.info, shared})) ++p.pfx_rcvd;
        mark(pfx);
    }
}

void Speaker::process_dirty() {
    if (dirty_.empty()) return;
    std::vector<Prefix> changed;
    for (auto& pfx : dirty_) {
        const LocEntry* before = rib_.lookup(pfx);
        std::vector<uint32_t> old_nh = before ? before->nexthops : std::vector<uint32_t>{};
        if (rib_.decide(pfx) == Rib::Change::None) continue;
        const LocEntry* after = rib_.lookup(pfx);
        if (after && !after->nexthops.empty()) {
            if (after->nexthops != old_nh) fib_.set(pfx, after->nexthops);
        } else if (!old_nh.empty()) {
            fib_.del(pfx);
        }
        changed.push_back(pfx);
    }
    dirty_.clear();
    dirty_set_.clear();
    fib_.flush();
    if (changed.empty()) return;
    for (auto& p : peers_)
        if (p->est) export_to(*p, changed);
}

AttrsPtr Speaker::export_attrs(Peer& p, const LocEntry* e) {
    if (!e) return nullptr;
    const Path& best = e->best;
    if (best.from == &p.info) return nullptr;                      // never back to the sender
    if (best.from && !best.from->ebgp && !p.info.ebgp) return nullptr;  // iBGP split horizon
    if (p.info.ebgp && best.attrs->contains_as(p.cfg.remote_as)) return nullptr;  // they'd drop it as a loop

    auto a = std::make_shared<Attrs>(*best.attrs);
    for (auto& u : a->unknown) u.flags |= kPartial;  // passed through, not understood by us
    if (p.info.ebgp) {
        if (!a->as_path.empty() && a->as_path[0].type == kAsSequence && a->as_path[0].asns.size() < 255)
            a->as_path[0].asns.insert(a->as_path[0].asns.begin(), cfg_.asn);
        else
            a->as_path.insert(a->as_path.begin(), AsSegment{kAsSequence, {cfg_.asn}});
        a->next_hop = p.est->local_addr;  // next-hop-self towards eBGP
        a->local_pref.reset();
        a->med.reset();  // a MED learned from one AS is not passed to another
    } else {
        a->local_pref = a->local_pref.value_or(100);
        if (!best.from) a->next_hop = p.est->local_addr;
    }
    return a;
}

void Speaker::export_to(Peer& p, const std::vector<Prefix>& prefixes) {
    if (!p.est) return;
    // Group announcements by identical attributes so one UPDATE carries many prefixes.
    std::map<std::vector<uint8_t>, std::pair<AttrsPtr, std::vector<Prefix>>> groups;
    std::unordered_map<const Attrs*, AttrsPtr> cache;  // best attrs -> exported attrs
    std::vector<Prefix> withdraw;
    for (auto& pfx : prefixes) {
        const LocEntry* e = rib_.lookup(pfx);
        AttrsPtr want;
        if (e && !(e->best.from == &p.info)) {
            auto it = cache.find(e->best.attrs.get());
            if (it != cache.end() && e->best.from != nullptr) want = it->second;
            else {
                want = export_attrs(p, e);
                if (e->best.from != nullptr) cache[e->best.attrs.get()] = want;
            }
        }
        auto cur = p.adj_out.find(pfx);
        if (!want) {
            if (cur != p.adj_out.end()) {
                withdraw.push_back(pfx);
                p.adj_out.erase(cur);
            }
            continue;
        }
        if (cur != p.adj_out.end() && *cur->second == *want) continue;
        p.adj_out[pfx] = want;
        std::vector<uint8_t> key;
        encode_attrs(*want, key);
        auto& g = groups[key];
        g.first = want;
        g.second.push_back(pfx);
    }
    std::vector<uint8_t> out;
    encode_withdraw(withdraw, out);
    for (auto& [key, g] : groups) encode_announce(*g.first, g.second, out);
    if (!out.empty()) send(p.est, out);
}

// ================================================================ control
void Speaker::on_control() {
    for (;;) {
        int fd = accept4(control_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) return;
        // Commands are one short line; the client writes it and waits. Blocking is fine here.
        timeval tv{1, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        std::string line;
        char ch;
        while (line.size() < 256 && ::recv(fd, &ch, 1, 0) == 1 && ch != '\n') line += ch;
        std::string reply = handle_command(line) + "\n";
        size_t off = 0;
        while (off < reply.size()) {
            ssize_t n = ::send(fd, reply.data() + off, reply.size() - off, MSG_NOSIGNAL);
            if (n <= 0) break;
            off += size_t(n);
        }
        close(fd);
    }
}

std::string Speaker::handle_command(const std::string& line) {
    std::istringstream ss(line);
    std::string cmd, arg;
    ss >> cmd >> arg;
    if (cmd == "summary") return summary_json();
    if (cmd == "rib") return rib_json(nullptr);
    if (cmd == "route") {
        auto p = Prefix::parse(arg);
        if (!p) return "{\"error\":\"bad prefix\"}";
        return rib_json(&*p);
    }
    if (cmd == "announce" || cmd == "withdraw") {
        auto p = Prefix::parse(arg);
        if (!p) return "{\"error\":\"bad prefix\"}";
        originate(*p, cmd == "announce");
        logf("%s %s", cmd.c_str(), p->str().c_str());
        return "{\"ok\":true}";
    }
    if (cmd == "fast-failover") {
        cfg_.fast_failover = (arg == "on");
        return "{\"ok\":true}";
    }
    if (cmd == "peer-down" || cmd == "peer-up") {
        auto a = parse_ip(arg);
        for (auto& p : peers_) {
            if (!a || p->cfg.addr != *a) continue;
            if (cmd == "peer-down") {
                p->admin_down = true;
                for (auto& c : p->conns)
                    if (!c->dead) close_conn(c.get(), Notification{kErrCease, sub::kAdminShutdown, {}}, "admin shutdown");
            } else {
                p->admin_down = false;
                p->retry_at = 0;
            }
            return "{\"ok\":true}";
        }
        return "{\"error\":\"no such peer\"}";
    }
    return "{\"error\":\"commands: summary | rib | route P | announce P | withdraw P | peer-down IP | peer-up IP\"}";
}

std::string Speaker::summary_json() {
    std::string o = "{\"name\":\"" + json_escape(cfg_.name) + "\",\"asn\":" + std::to_string(cfg_.asn) +
                    ",\"router_id\":\"" + ip_str(cfg_.router_id) + "\",\"loc_rib\":" +
                    std::to_string(rib_.loc().size()) + ",\"adj_in\":" + std::to_string(rib_.adj_in_paths()) +
                    ",\"fib_ops\":" + std::to_string(fib_.ops) + ",\"fib_errors\":" + std::to_string(fib_.errors) +
                    ",\"fib_last_error\":\"" + json_escape(fib_.last_error) +
                    "\",\"link_events\":" + std::to_string(link_events_) + ",\"fib_resyncs\":" +
                    std::to_string(fib_resyncs_) + ",\"peers\":[";
    uint64_t now = now_ms();
    for (size_t i = 0; i < peers_.size(); ++i) {
        auto& p = *peers_[i];
        if (i) o += ',';
        o += "{\"addr\":\"" + ip_str(p.cfg.addr) + "\",\"remote_as\":" + std::to_string(p.cfg.remote_as) +
             ",\"state\":\"" + p.state() + "\",\"pfx_rcvd\":" + std::to_string(p.pfx_rcvd) +
             ",\"pfx_sent\":" + std::to_string(p.adj_out.size()) + ",\"updates_rx\":" + std::to_string(p.updates_rx) +
             ",\"treat_as_withdraw\":" + std::to_string(p.taw) + ",\"flaps\":" + std::to_string(p.flaps) +
             ",\"up_ms\":" + std::to_string(p.est ? now - p.up_since : 0) + ",\"last_error\":\"" +
             json_escape(p.last_error) + "\"}";
    }
    return o + "]}";
}

std::string Speaker::rib_json(const Prefix* only) {
    std::string o = "{";
    bool first = true;
    auto one = [&](const Prefix& pfx, const LocEntry& e) {
        if (!first) o += ',';
        first = false;
        o += "\"" + pfx.str() + "\":{\"nexthops\":[";
        for (size_t i = 0; i < e.nexthops.size(); ++i) o += (i ? ",\"" : "\"") + ip_str(e.nexthops[i]) + "\"";
        o += "],\"as_path\":\"" + e.best.attrs->as_path_str() + "\",\"from\":\"" +
             (e.best.from ? ip_str(e.best.from->addr) : std::string("local")) + "\"}";
    };
    if (only) {
        if (auto* e = rib_.lookup(*only)) one(*only, *e);
    } else {
        std::vector<Prefix> keys;
        for (auto& [p, e] : rib_.loc()) keys.push_back(p);
        std::sort(keys.begin(), keys.end());
        for (auto& k : keys) one(k, *rib_.lookup(k));
    }
    return o + "}";
}

}  // namespace nbgp
