#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "protocol/message.hpp"

auto test_rr_serialize() -> bool {
    DnsResourceRecord rr{};
    rr.name = {"codecrafters", "io"};
    rr.type = 1;
    rr.cls = 1;
    rr.ttl = 60;
    rr.rdata = {std::byte{0x08}, std::byte{0x08}, std::byte{0x08}, std::byte{0x08}};

    auto bytes = rr.serialize();

    size_t expected_size = 1 + 12 + 1 + 2 + 1 + 2 + 2 + 4 + 2 + 4;
    if (bytes.size() != expected_size) {
        std::cerr << "rr_serialize: expected " << expected_size << " bytes, got " << bytes.size()
                  << std::endl;
        return false;
    }

    if (static_cast<uint8_t>(bytes[0]) != 12) {
        std::cerr << "rr_serialize: first label length expected 12" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[13]) != 2) {
        std::cerr << "rr_serialize: second label length expected 2" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[16]) != 0) {
        std::cerr << "rr_serialize: null terminator expected" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[17]) != 0 || static_cast<uint8_t>(bytes[18]) != 1) {
        std::cerr << "rr_serialize: type mismatch" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[19]) != 0 || static_cast<uint8_t>(bytes[20]) != 1) {
        std::cerr << "rr_serialize: class mismatch" << std::endl;
        return false;
    }
    if (static_cast<uint32_t>(bytes[21]) != 0 || static_cast<uint32_t>(bytes[22]) != 0 ||
        static_cast<uint32_t>(bytes[23]) != 0 || static_cast<uint32_t>(bytes[24]) != 60) {
        std::cerr << "rr_serialize: ttl mismatch" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[25]) != 0 || static_cast<uint8_t>(bytes[26]) != 4) {
        std::cerr << "rr_serialize: rdlength mismatch" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[27]) != 8 || static_cast<uint8_t>(bytes[28]) != 8 ||
        static_cast<uint8_t>(bytes[29]) != 8 || static_cast<uint8_t>(bytes[30]) != 8) {
        std::cerr << "rr_serialize: rdata mismatch" << std::endl;
        return false;
    }

    return true;
}

auto test_rr_parse() -> bool {
    std::vector<std::byte> raw = {
        std::byte{0x0c}, std::byte{'c'},  std::byte{'o'},  std::byte{'d'},  std::byte{'e'},
        std::byte{'c'},  std::byte{'r'},  std::byte{'a'},  std::byte{'f'},  std::byte{'t'},
        std::byte{'e'},  std::byte{'r'},  std::byte{'s'},  std::byte{0x02}, std::byte{'i'},
        std::byte{'o'},  std::byte{0x00}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x3c},
        std::byte{0x00}, std::byte{0x04}, std::byte{0x08}, std::byte{0x08}, std::byte{0x08},
        std::byte{0x08},
    };

    auto [rr, consumed] = DnsResourceRecord::parse(raw, 0);

    if (rr.name.size() != 2) {
        std::cerr << "rr_parse: expected 2 labels, got " << rr.name.size() << std::endl;
        return false;
    }
    if (rr.name[0] != "codecrafters") {
        std::cerr << "rr_parse: label[0] mismatch" << std::endl;
        return false;
    }
    if (rr.name[1] != "io") {
        std::cerr << "rr_parse: label[1] mismatch" << std::endl;
        return false;
    }
    if (rr.type != 1) {
        std::cerr << "rr_parse: type expected 1, got " << rr.type << std::endl;
        return false;
    }
    if (rr.cls != 1) {
        std::cerr << "rr_parse: class expected 1, got " << rr.cls << std::endl;
        return false;
    }
    if (rr.ttl != 60) {
        std::cerr << "rr_parse: ttl expected 60, got " << rr.ttl << std::endl;
        return false;
    }
    if (rr.rdata.size() != 4) {
        std::cerr << "rr_parse: rdata size expected 4, got " << rr.rdata.size() << std::endl;
        return false;
    }
    for (size_t i = 0; i < 4; ++i) {
        if (static_cast<uint8_t>(rr.rdata[i]) != 8) {
            std::cerr << "rr_parse: rdata[" << i << "] expected 8" << std::endl;
            return false;
        }
    }
    if (consumed != raw.size()) {
        std::cerr << "rr_parse: consumed expected " << raw.size() << ", got " << consumed
                  << std::endl;
        return false;
    }

    return true;
}

auto test_message_answer_roundtrip() -> bool {
    std::vector<std::byte> raw = {
        std::byte{0x12}, std::byte{0x34}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x0c}, std::byte{'c'},  std::byte{'o'},
        std::byte{'d'},  std::byte{'e'},  std::byte{'c'},  std::byte{'r'},  std::byte{'a'},
        std::byte{'f'},  std::byte{'t'},  std::byte{'e'},  std::byte{'r'},  std::byte{'s'},
        std::byte{0x02}, std::byte{'i'},  std::byte{'o'},  std::byte{0x00}, std::byte{0x00},
        std::byte{0x01}, std::byte{0x00}, std::byte{0x01}, std::byte{0x0c}, std::byte{'c'},
        std::byte{'o'},  std::byte{'d'},  std::byte{'e'},  std::byte{'c'},  std::byte{'r'},
        std::byte{'a'},  std::byte{'f'},  std::byte{'t'},  std::byte{'e'},  std::byte{'r'},
        std::byte{'s'},  std::byte{0x02}, std::byte{'i'},  std::byte{'o'},  std::byte{0x00},
        std::byte{0x00}, std::byte{0x01}, std::byte{0x00}, std::byte{0x01}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00}, std::byte{0x3c}, std::byte{0x00}, std::byte{0x04},
        std::byte{0x08}, std::byte{0x08}, std::byte{0x08}, std::byte{0x08},
    };

    auto msg = DnsMessage::parse(raw);

    if (msg.header.id != 0x1234) {
        std::cerr << "answer_roundtrip: header id mismatch" << std::endl;
        return false;
    }
    if (msg.header.qdcount != 1) {
        std::cerr << "answer_roundtrip: qdcount expected 1" << std::endl;
        return false;
    }
    if (msg.header.ancount != 1) {
        std::cerr << "answer_roundtrip: ancount expected 1, got " << msg.header.ancount
                  << std::endl;
        return false;
    }
    if (msg.questions.size() != 1) {
        std::cerr << "answer_roundtrip: expected 1 question" << std::endl;
        return false;
    }
    if (msg.answers.size() != 1) {
        std::cerr << "answer_roundtrip: expected 1 answer, got " << msg.answers.size() << std::endl;
        return false;
    }
    if (msg.answers[0].name[0] != "codecrafters" || msg.answers[0].name[1] != "io") {
        std::cerr << "answer_roundtrip: answer name mismatch" << std::endl;
        return false;
    }
    if (msg.answers[0].type != 1 || msg.answers[0].cls != 1) {
        std::cerr << "answer_roundtrip: answer type/class mismatch" << std::endl;
        return false;
    }
    if (msg.answers[0].ttl != 60) {
        std::cerr << "answer_roundtrip: answer ttl expected 60, got " << msg.answers[0].ttl
                  << std::endl;
        return false;
    }
    if (msg.answers[0].rdata.size() != 4 || static_cast<uint8_t>(msg.answers[0].rdata[0]) != 8) {
        std::cerr << "answer_roundtrip: answer rdata mismatch" << std::endl;
        return false;
    }

    auto serialized = msg.serialize();
    if (serialized.size() != raw.size()) {
        std::cerr << "answer_roundtrip: size mismatch, expected " << raw.size() << " got "
                  << serialized.size() << std::endl;
        return false;
    }
    for (size_t i = 0; i < raw.size(); ++i) {
        if (serialized[i] != raw[i]) {
            std::cerr << "answer_roundtrip: byte mismatch at " << i << std::endl;
            return false;
        }
    }

    return true;
}

int main() {
    bool all_passed = true;

    if (!test_rr_serialize()) {
        std::cerr << "FAIL: test_rr_serialize" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_rr_serialize" << std::endl;
    }

    if (!test_rr_parse()) {
        std::cerr << "FAIL: test_rr_parse" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_rr_parse" << std::endl;
    }

    if (!test_message_answer_roundtrip()) {
        std::cerr << "FAIL: test_message_answer_roundtrip" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_message_answer_roundtrip" << std::endl;
    }

    return all_passed ? 0 : 1;
}
