// The BGP speaker: sessions (RFC 4271 section 8 FSM), timers, import/export
// policy, and one single-threaded epoll loop that drives all of it.
#pragma once
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "fib.hpp"
#include "rib.hpp"
#include "wire.hpp"

namespace nbgp {

struct NeighborCfg {
    uint32_t addr = 0;
    uint32_t remote_as = 0;
    bool passive = false;  // never connect out, only accept
};

struct Config {
    std::string name = "nbgp";
    uint32_t asn = 0;
    uint32_t router_id = 0;
    uint16_t hold_time = 9;      // keepalive = hold / 3
    uint16_t connect_retry = 2;  // seconds
    uint32_t listen_addr = 0;
    uint16_t port = 179;
    size_t max_paths = 8;
    bool fib = true;
    std::string control;  // unix socket path for nbgpctl
    std::vector<NeighborCfg> neighbors;
    std::vector<Prefix> networks;

    static std::optional<Config> load(const std::string& path, std::string& err);
};

struct Pollable {
    enum Kind { kListen, kControl, kConn } kind;
};

struct Conn : Pollable {
    enum State { Connecting, OpenSent, OpenConfirm, Established };
    Conn() : Pollable{kConn} {}
    int fd = -1;
    bool inbound = false;
    State st = Connecting;
    bool dead = false;
    bool want_out = false;  // EPOLLOUT registered
    std::vector<uint8_t> rbuf, wbuf;
    size_t woff = 0;
    uint64_t hold_deadline = 0, ka_deadline = 0;
    uint16_t hold = 0;  // negotiated, seconds
    uint32_t remote_id = 0;
    uint32_t local_addr = 0;
    struct Peer* peer = nullptr;
};

struct Peer {
    NeighborCfg cfg;
    PeerInfo info;
    std::vector<std::unique_ptr<Conn>> conns;
    Conn* est = nullptr;
    uint64_t retry_at = 0;
    bool admin_down = false;
    // Adj-RIB-Out: what we last told this peer, so we only send changes.
    std::unordered_map<Prefix, AttrsPtr, PrefixHash> adj_out;
    uint64_t pfx_rcvd = 0, updates_rx = 0, taw = 0;
    uint32_t flaps = 0;
    uint64_t up_since = 0;
    std::string last_error;
    const char* state() const;
};

class Speaker {
public:
    explicit Speaker(Config cfg);
    int run();  // returns exit code
    static void request_stop();

private:
    // sockets
    void on_accept();
    void on_control();
    void on_conn_event(Conn* c, uint32_t events);
    void start_connect(Peer& p);
    void read_conn(Conn* c);
    void flush_conn(Conn* c);
    void send(Conn* c, const std::vector<uint8_t>& bytes);
    void close_conn(Conn* c, std::optional<Notification> why, const std::string& reason);
    void sweep();

    // FSM
    void on_message(Conn* c, uint8_t type, std::span<const uint8_t> body);
    void on_open(Conn* c, const Open& o);
    void on_established(Peer& p, Conn* c);
    void on_session_down(Peer& p);
    void resolve_collision(Peer& p, Conn* winner_candidate);
    void timers();

    // routes
    void on_update(Peer& p, Update& u);
    void originate(const Prefix& pfx, bool add);
    void mark(const Prefix& pfx);
    void process_dirty();
    void export_to(Peer& p, const std::vector<Prefix>& prefixes);
    AttrsPtr export_attrs(Peer& p, const LocEntry* e);

    std::string handle_command(const std::string& line);
    std::string summary_json();
    std::string rib_json(const Prefix* only);

    Config cfg_;
    Rib rib_;
    Fib fib_;
    std::vector<std::unique_ptr<Peer>> peers_;
    int ep_ = -1;
    Pollable listen_{Pollable::kListen}, control_{Pollable::kControl};
    int listen_fd_ = -1, control_fd_ = -1;
    std::vector<Prefix> dirty_;
    std::unordered_set<Prefix, PrefixHash> dirty_set_;
    std::vector<std::unique_ptr<Conn>> graveyard_;
};

uint64_t now_ms();
void logf(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

}  // namespace nbgp
