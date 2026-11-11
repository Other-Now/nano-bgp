#include <csignal>
#include <cstdio>

#include "speaker.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: nbgpd <config-file>\n");
        return 2;
    }
    std::string err;
    auto cfg = nbgp::Config::load(argv[1], err);
    if (!cfg) {
        std::fprintf(stderr, "nbgpd: %s\n", err.c_str());
        return 2;
    }
    struct sigaction sa {};
    sa.sa_handler = [](int) { nbgp::Speaker::request_stop(); };
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    setvbuf(stderr, nullptr, _IOLBF, 0);
    return nbgp::Speaker(std::move(*cfg)).run();
}
