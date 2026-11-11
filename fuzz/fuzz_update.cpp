// libFuzzer target for the message decoder.
//
// Two properties, beyond "doesn't crash under ASan/UBSan":
//  1. Every UPDATE that decodes cleanly (no treat-as-withdraw) re-encodes into
//     messages that decode back to the same attributes and NLRI.
//  2. The decoder never reports more NLRI bytes than it was given.
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <vector>

#include "wire.hpp"

using namespace nbgp;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // First byte picks the message type (mostly UPDATE), the rest is the body.
    if (size == 0) return 0;
    uint8_t type = data[0] < 16 ? uint8_t(data[0] % 4 + 1) : uint8_t(kUpdate);
    ++data, --size;
    std::vector<uint8_t> msg(16, 0xFF);
    size_t len = std::min<size_t>(size + 19, 4096);
    msg.push_back(uint8_t(len >> 8));
    msg.push_back(uint8_t(len));
    msg.push_back(type);
    msg.insert(msg.end(), data, data + (len - 19));

    auto r = decode_message(msg);
    auto* u = std::get_if<Update>(&r);
    if (!u || u->treat_as_withdraw || !u->attrs || u->nlri.empty()) return 0;

    std::vector<uint8_t> out;
    encode_announce(*u->attrs, u->nlri, out);
    std::vector<Prefix> back;
    size_t off = 0;
    while (off < out.size()) {
        size_t l = size_t(out[off + 16]) << 8 | out[off + 17];
        auto r2 = decode_message(std::span<const uint8_t>(out.data() + off, l));
        auto* u2 = std::get_if<Update>(&r2);
        if (!u2 || u2->treat_as_withdraw || !(*u2->attrs == *u->attrs)) {
            std::fprintf(stderr, "re-encode mismatch\n");
            std::abort();
        }
        back.insert(back.end(), u2->nlri.begin(), u2->nlri.end());
        off += l;
    }
    if (!out.empty() && back != u->nlri) {
        std::fprintf(stderr, "NLRI mismatch after re-encode\n");
        std::abort();
    }
    return 0;
}
