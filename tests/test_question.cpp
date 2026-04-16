#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "protocol/message.hpp"

auto test_question_parse() -> bool {
    // \x0ccodecrafters\x02io\x00 \x00\x01 \x00\x01
    std::vector<std::byte> raw = {
        std::byte{0x0c},                                                  // len=12
        std::byte{'c'},  std::byte{'o'},  std::byte{'d'}, std::byte{'e'}, //
        std::byte{'c'},  std::byte{'r'},  std::byte{'a'}, std::byte{'f'}, //
        std::byte{'t'},  std::byte{'e'},  std::byte{'r'}, std::byte{'s'}, //
        std::byte{0x02},                                                  // len=2
        std::byte{'i'},  std::byte{'o'},                                  //
        std::byte{0x00},                                                  // terminator
        std::byte{0x00}, std::byte{0x01},                                 // type=1
        std::byte{0x00}, std::byte{0x01},                                 // class=1
    };

    auto [q, consumed] = DnsQuestion::parse(raw, 0);

    if (q.labels.size() != 2) {
        std::cerr << "parse: expected 2 labels, got " << q.labels.size() << std::endl;
        return false;
    }
    if (q.labels[0] != "codecrafters") {
        std::cerr << "parse: label[0] expected 'codecrafters', got '" << q.labels[0] << "'"
                  << std::endl;
        return false;
    }
    if (q.labels[1] != "io") {
        std::cerr << "parse: label[1] expected 'io', got '" << q.labels[1] << "'" << std::endl;
        return false;
    }
    if (q.type != 1) {
        std::cerr << "parse: type expected 1, got " << q.type << std::endl;
        return false;
    }
    if (q.qclass != 1) {
        std::cerr << "parse: class expected 1, got " << q.qclass << std::endl;
        return false;
    }
    if (consumed != raw.size()) {
        std::cerr << "parse: consumed expected " << raw.size() << ", got " << consumed << std::endl;
        return false;
    }

    return true;
}

auto test_question_serialize() -> bool {
    DnsQuestion q{};
    q.labels = {"codecrafters", "io"};
    q.type = 1;
    q.qclass = 1;

    auto bytes = q.serialize();

    // expected: \x0c codecrafters \x02 io \x00 \x00\x01 \x00\x01 = 21 bytes
    if (bytes.size() != 21) {
        std::cerr << "serialize: expected 21 bytes, got " << bytes.size() << std::endl;
        return false;
    }

    // check domain encoding
    if (static_cast<uint8_t>(bytes[0]) != 12) {
        std::cerr << "serialize: first label length expected 12" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[13]) != 2) {
        std::cerr << "serialize: second label length expected 2" << std::endl;
        return false;
    }
    if (static_cast<uint8_t>(bytes[16]) != 0) {
        std::cerr << "serialize: null terminator expected" << std::endl;
        return false;
    }

    // check type=1 (big-endian)
    if (static_cast<uint8_t>(bytes[17]) != 0 || static_cast<uint8_t>(bytes[18]) != 1) {
        std::cerr << "serialize: type mismatch" << std::endl;
        return false;
    }
    // check class=1 (big-endian)
    if (static_cast<uint8_t>(bytes[19]) != 0 || static_cast<uint8_t>(bytes[20]) != 1) {
        std::cerr << "serialize: class mismatch" << std::endl;
        return false;
    }

    return true;
}

auto test_message_question_roundtrip() -> bool {
    // Header (12 bytes): id=0x1234, qr=0, opcode=0, rd=1, qdcount=1
    // Question (21 bytes): codecrafters.io, type=1, class=1
    std::vector<std::byte> raw = {
        // header
        std::byte{0x12},
        std::byte{0x34}, // id
        std::byte{0x01},
        std::byte{0x00}, // flags: rd=1
        std::byte{0x00},
        std::byte{0x01}, // qdcount=1
        std::byte{0x00},
        std::byte{0x00}, // ancount=0
        std::byte{0x00},
        std::byte{0x00}, // nscount=0
        std::byte{0x00},
        std::byte{0x00}, // arcount=0
        // question
        std::byte{0x0c}, //
        std::byte{'c'},
        std::byte{'o'},
        std::byte{'d'},
        std::byte{'e'}, //
        std::byte{'c'},
        std::byte{'r'},
        std::byte{'a'},
        std::byte{'f'}, //
        std::byte{'t'},
        std::byte{'e'},
        std::byte{'r'},
        std::byte{'s'},  //
        std::byte{0x02}, //
        std::byte{'i'},
        std::byte{'o'},  //
        std::byte{0x00}, //
        std::byte{0x00},
        std::byte{0x01}, // type=1
        std::byte{0x00},
        std::byte{0x01}, // class=1
    };

    auto msg = DnsMessage::parse(raw);

    if (msg.header.id != 0x1234) {
        std::cerr << "roundtrip: header id mismatch" << std::endl;
        return false;
    }
    if (msg.header.qdcount != 1) {
        std::cerr << "roundtrip: qdcount expected 1, got " << msg.header.qdcount << std::endl;
        return false;
    }
    if (msg.questions.size() != 1) {
        std::cerr << "roundtrip: expected 1 question, got " << msg.questions.size() << std::endl;
        return false;
    }
    if (msg.questions[0].labels[0] != "codecrafters" || msg.questions[0].labels[1] != "io") {
        std::cerr << "roundtrip: question labels mismatch" << std::endl;
        return false;
    }
    if (msg.questions[0].type != 1 || msg.questions[0].qclass != 1) {
        std::cerr << "roundtrip: question type/class mismatch" << std::endl;
        return false;
    }

    auto serialized = msg.serialize();
    if (serialized.size() != raw.size()) {
        std::cerr << "roundtrip: serialized size " << serialized.size() << " != " << raw.size()
                  << std::endl;
        return false;
    }
    for (size_t i = 0; i < raw.size(); ++i) {
        if (serialized[i] != raw[i]) {
            std::cerr << "roundtrip: byte mismatch at " << i << std::endl;
            return false;
        }
    }

    return true;
}

auto test_question_compressed_pointer() -> bool {
    // Full message with 2 questions:
    // Q1 at offset 12: codecrafters.io (uncompressed)
    // Q2 at offset 33: www + compressed pointer to offset 12 (codecrafters.io)
    // Layout:
    //   [0..11]  Header: id=0x1234, qdcount=2
    //   [12..32] Q1: \x0c codecrafters \x02 io \x00 \x00\x01 \x00\x01
    //   [33..38] Q2: \x03 www \xC0\x0C \x00\x01 \x00\x01
    std::vector<std::byte> raw = {
        std::byte{0x12},
        std::byte{0x34}, // id
        std::byte{0x01},
        std::byte{0x00}, // flags: rd=1
        std::byte{0x00},
        std::byte{0x02}, // qdcount=2
        std::byte{0x00},
        std::byte{0x00}, // ancount=0
        std::byte{0x00},
        std::byte{0x00}, // nscount=0
        std::byte{0x00},
        std::byte{0x00}, // arcount=0
        // Q1: codecrafters.io
        std::byte{0x0c},
        std::byte{'c'},
        std::byte{'o'},
        std::byte{'d'},
        std::byte{'e'},
        std::byte{'c'},
        std::byte{'r'},
        std::byte{'a'},
        std::byte{'f'},
        std::byte{'t'},
        std::byte{'e'},
        std::byte{'r'},
        std::byte{'s'},
        std::byte{0x02},
        std::byte{'i'},
        std::byte{'o'},
        std::byte{0x00},
        std::byte{0x00},
        std::byte{0x01},
        std::byte{0x00},
        std::byte{0x01},
        // Q2: www.codecrafters.io (compressed)
        std::byte{0x03},
        std::byte{'w'},
        std::byte{'w'},
        std::byte{'w'},
        std::byte{0xC0},
        std::byte{0x0C}, // pointer to offset 12
        std::byte{0x00},
        std::byte{0x01},
        std::byte{0x00},
        std::byte{0x01},
    };

    auto msg = DnsMessage::parse(raw);

    if (msg.questions.size() != 2) {
        std::cerr << "compressed: expected 2 questions, got " << msg.questions.size() << std::endl;
        return false;
    }
    if (msg.questions[1].labels.size() != 3) {
        std::cerr << "compressed: expected 3 labels, got " << msg.questions[1].labels.size()
                  << std::endl;
        return false;
    }
    if (msg.questions[1].labels[0] != "www") {
        std::cerr << "compressed: label[0] expected 'www', got '" << msg.questions[1].labels[0]
                  << "'" << std::endl;
        return false;
    }
    if (msg.questions[1].labels[1] != "codecrafters") {
        std::cerr << "compressed: label[1] expected 'codecrafters', got '"
                  << msg.questions[1].labels[1] << "'" << std::endl;
        return false;
    }
    if (msg.questions[1].labels[2] != "io") {
        std::cerr << "compressed: label[2] expected 'io', got '" << msg.questions[1].labels[2]
                  << "'" << std::endl;
        return false;
    }
    if (msg.questions[1].type != 1) {
        std::cerr << "compressed: type expected 1, got " << msg.questions[1].type << std::endl;
        return false;
    }
    if (msg.questions[1].qclass != 1) {
        std::cerr << "compressed: class expected 1, got " << msg.questions[1].qclass << std::endl;
        return false;
    }

    return true;
}

int main() {
    bool all_passed = true;

    if (!test_question_parse()) {
        std::cerr << "FAIL: test_question_parse" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_question_parse" << std::endl;
    }

    if (!test_question_serialize()) {
        std::cerr << "FAIL: test_question_serialize" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_question_serialize" << std::endl;
    }

    if (!test_message_question_roundtrip()) {
        std::cerr << "FAIL: test_message_question_roundtrip" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_message_question_roundtrip" << std::endl;
    }

    if (!test_question_compressed_pointer()) {
        std::cerr << "FAIL: test_question_compressed_pointer" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_question_compressed_pointer" << std::endl;
    }

    return all_passed ? 0 : 1;
}
