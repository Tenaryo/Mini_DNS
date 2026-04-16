#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "protocol/header.hpp"

auto test_header_serialize() -> bool {
    DnsHeader hdr{};
    hdr.id = 0x1234;
    hdr.qr = true;
    hdr.opcode = 0;
    hdr.aa = false;
    hdr.tc = false;
    hdr.rd = false;
    hdr.ra = false;
    hdr.z = 0;
    hdr.rcode = 0;
    hdr.qdcount = 0;
    hdr.ancount = 0;
    hdr.nscount = 0;
    hdr.arcount = 0;

    auto bytes = hdr.serialize();

    if (bytes.size() != 12) {
        std::cerr << "serialize: expected 12 bytes, got " << bytes.size() << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[0]) != 0x12 || static_cast<uint8_t>(bytes[1]) != 0x34) {
        std::cerr << "serialize: id mismatch" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[2]) != 0x80) {
        std::cerr << "serialize: flags byte 2 expected 0x80, got " << std::hex
                  << static_cast<int>(bytes[2]) << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[3]) != 0x00) {
        std::cerr << "serialize: flags byte 3 expected 0x00, got " << std::hex
                  << static_cast<int>(bytes[3]) << std::endl;
        return false;
    }
    for (size_t i = 4; i < 12; ++i) {
        if (static_cast<uint8_t>(bytes[i]) != 0x00) {
            std::cerr << "serialize: count field non-zero at byte " << i << std::endl;
            return false;
        }
    }

    return true;
}

auto test_header_parse() -> bool {
    std::array<std::byte, 12> raw = {
        std::byte{0x12},
        std::byte{0x34},
        std::byte{0x81},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x01},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x00},
    };

    auto hdr = DnsHeader::parse(raw);

    if (hdr.id != 0x1234) {
        std::cerr << "parse: id expected 0x1234, got " << std::hex << hdr.id << std::endl;
        return false;
    }
    if (hdr.qr != true) {
        std::cerr << "parse: qr expected 1, got " << hdr.qr << std::endl;
        return false;
    }
    if (hdr.opcode != 0) {
        std::cerr << "parse: opcode expected 0, got " << static_cast<int>(hdr.opcode) << std::endl;
        return false;
    }
    if (hdr.rd != true) {
        std::cerr << "parse: rd expected 1, got " << hdr.rd << std::endl;
        return false;
    }
    if (hdr.qdcount != 1) {
        std::cerr << "parse: qdcount expected 1, got " << hdr.qdcount << std::endl;
        return false;
    }
    if (hdr.ancount != 0 || hdr.nscount != 0 || hdr.arcount != 0) {
        std::cerr << "parse: count fields mismatch" << std::endl;
        return false;
    }

    return true;
}

auto test_header_roundtrip() -> bool {
    DnsHeader original{};
    original.id = 0xABCD;
    original.qr = true;
    original.opcode = 0;
    original.aa = true;
    original.tc = false;
    original.rd = true;
    original.ra = false;
    original.z = 0;
    original.rcode = 0;
    original.qdcount = 1;
    original.ancount = 2;
    original.nscount = 3;
    original.arcount = 4;

    auto bytes = original.serialize();
    auto roundtrip = DnsHeader::parse(bytes);

    if (roundtrip.id != original.id || roundtrip.qr != original.qr ||
        roundtrip.opcode != original.opcode || roundtrip.aa != original.aa ||
        roundtrip.tc != original.tc || roundtrip.rd != original.rd || roundtrip.ra != original.ra ||
        roundtrip.z != original.z || roundtrip.rcode != original.rcode ||
        roundtrip.qdcount != original.qdcount || roundtrip.ancount != original.ancount ||
        roundtrip.nscount != original.nscount || roundtrip.arcount != original.arcount) {
        std::cerr << "roundtrip: fields mismatch" << std::endl;
        return false;
    }

    return true;
}

int main() {
    bool all_passed = true;

    if (!test_header_serialize()) {
        std::cerr << "FAIL: test_header_serialize" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_header_serialize" << std::endl;
    }

    if (!test_header_parse()) {
        std::cerr << "FAIL: test_header_parse" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_header_parse" << std::endl;
    }

    if (!test_header_roundtrip()) {
        std::cerr << "FAIL: test_header_roundtrip" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_header_roundtrip" << std::endl;
    }

    return all_passed ? 0 : 1;
}
