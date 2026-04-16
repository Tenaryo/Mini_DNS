#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "protocol/message.hpp"
#include "server.hpp"

auto make_query_with_domain(uint16_t id,
                            uint8_t opcode,
                            bool rd,
                            std::string_view domain) -> std::vector<std::byte> {
    std::vector<std::byte> buf(12);

    buf[0] = static_cast<std::byte>(id >> 8);
    buf[1] = static_cast<std::byte>(id & 0xFF);

    uint8_t flags2 = (static_cast<uint8_t>(opcode & 0xF) << 3) | (static_cast<uint8_t>(rd) & 0x1);
    buf[2] = static_cast<std::byte>(flags2);
    buf[3] = std::byte{0x00};

    buf[4] = std::byte{0x00};
    buf[5] = std::byte{0x01};
    buf[6] = std::byte{0x00};
    buf[7] = std::byte{0x00};
    buf[8] = std::byte{0x00};
    buf[9] = std::byte{0x00};
    buf[10] = std::byte{0x00};
    buf[11] = std::byte{0x00};

    size_t start = 0;
    while (start < domain.size()) {
        auto dot = domain.find('.', start);
        auto label = (dot == std::string_view::npos) ? domain.substr(start)
                                                     : domain.substr(start, dot - start);
        buf.push_back(static_cast<std::byte>(label.size()));
        for (auto c : label)
            buf.push_back(static_cast<std::byte>(c));
        if (dot == std::string_view::npos)
            break;
        start = dot + 1;
    }
    buf.push_back(std::byte{0x00});

    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});
    buf.push_back(std::byte{0x00});
    buf.push_back(std::byte{0x01});

    return buf;
}

auto make_query(uint16_t id, uint8_t opcode, bool rd) -> std::vector<std::byte> {
    return make_query_with_domain(id, opcode, rd, "codecrafters.io");
}

auto test_standard_query_response_header() -> bool {
    auto query = make_query(0x1234, 0, true);
    auto resp = create_response(query);
    auto hdr = DnsHeader::parse(resp);

    if (hdr.id != 0x1234) {
        std::cerr << "id mismatch" << std::endl;
        return false;
    }
    if (hdr.qr != true) {
        std::cerr << "qr expected 1" << std::endl;
        return false;
    }
    if (hdr.opcode != 0) {
        std::cerr << "opcode expected 0" << std::endl;
        return false;
    }
    if (hdr.aa != false) {
        std::cerr << "aa expected 0" << std::endl;
        return false;
    }
    if (hdr.tc != false) {
        std::cerr << "tc expected 0" << std::endl;
        return false;
    }
    if (hdr.rd != true) {
        std::cerr << "rd expected 1 (echo)" << std::endl;
        return false;
    }
    if (hdr.ra != false) {
        std::cerr << "ra expected 0" << std::endl;
        return false;
    }
    if (hdr.z != 0) {
        std::cerr << "z expected 0" << std::endl;
        return false;
    }
    if (hdr.rcode != 0) {
        std::cerr << "rcode expected 0" << std::endl;
        return false;
    }
    return true;
}

auto test_response_id_echo() -> bool {
    auto query = make_query(0xABCD, 0, false);
    auto resp = create_response(query);
    auto hdr = DnsHeader::parse(resp);

    if (hdr.id != 0xABCD) {
        std::cerr << "id echo: expected 0xABCD, got " << std::hex << hdr.id << std::endl;
        return false;
    }
    return true;
}

auto test_response_question_echo_with_random_domain() -> bool {
    auto query = make_query_with_domain(0x5678, 0, true, "example.com");
    auto resp = create_response(query);
    auto msg = DnsMessage::parse(resp);

    if (msg.questions.size() != 1) {
        std::cerr << "question echo: expected 1 question, got " << msg.questions.size()
                  << std::endl;
        return false;
    }
    if (msg.questions[0].labels.size() != 2) {
        std::cerr << "question echo: expected 2 labels, got " << msg.questions[0].labels.size()
                  << std::endl;
        return false;
    }
    if (msg.questions[0].labels[0] != "example") {
        std::cerr << "question echo: label[0] expected 'example', got '"
                  << msg.questions[0].labels[0] << "'" << std::endl;
        return false;
    }
    if (msg.questions[0].labels[1] != "com") {
        std::cerr << "question echo: label[1] expected 'com', got '" << msg.questions[0].labels[1]
                  << "'" << std::endl;
        return false;
    }
    if (msg.questions[0].type != 1) {
        std::cerr << "question echo: type expected 1, got " << msg.questions[0].type << std::endl;
        return false;
    }
    if (msg.questions[0].qclass != 1) {
        std::cerr << "question echo: class expected 1, got " << msg.questions[0].qclass
                  << std::endl;
        return false;
    }

    return true;
}

auto test_response_answer_matches_question_domain() -> bool {
    auto query = make_query_with_domain(0x5678, 0, true, "example.com");
    auto resp = create_response(query);
    auto msg = DnsMessage::parse(resp);

    if (msg.answers.size() != 1) {
        std::cerr << "answer match: expected 1 answer, got " << msg.answers.size() << std::endl;
        return false;
    }
    if (msg.answers[0].name.size() != 2) {
        std::cerr << "answer match: expected 2 name labels, got " << msg.answers[0].name.size()
                  << std::endl;
        return false;
    }
    if (msg.answers[0].name[0] != "example" || msg.answers[0].name[1] != "com") {
        std::cerr << "answer match: name labels expected {example, com}, got {"
                  << msg.answers[0].name[0] << ", " << msg.answers[0].name[1] << "}" << std::endl;
        return false;
    }
    if (msg.answers[0].type != 1) {
        std::cerr << "answer match: type expected 1, got " << msg.answers[0].type << std::endl;
        return false;
    }
    if (msg.answers[0].cls != 1) {
        std::cerr << "answer match: class expected 1, got " << msg.answers[0].cls << std::endl;
        return false;
    }
    if (msg.answers[0].ttl != 60) {
        std::cerr << "answer match: ttl expected 60, got " << msg.answers[0].ttl << std::endl;
        return false;
    }
    if (msg.answers[0].rdata.size() != 4) {
        std::cerr << "answer match: rdata size expected 4, got " << msg.answers[0].rdata.size()
                  << std::endl;
        return false;
    }
    for (size_t i = 0; i < 4; ++i) {
        if (static_cast<uint8_t>(msg.answers[0].rdata[i]) != 8) {
            std::cerr << "answer match: rdata[" << i << "] expected 8" << std::endl;
            return false;
        }
    }

    return true;
}

auto test_response_multiple_questions() -> bool {
    auto q1 = make_query_with_domain(0, 0, true, "codecrafters.io");
    auto q2 = make_query_with_domain(0, 0, true, "example.com");

    std::vector<std::byte> query;
    query.push_back(std::byte{0xAA});
    query.push_back(std::byte{0xBB});
    query.push_back(std::byte{0x01});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x02});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});
    query.push_back(std::byte{0x00});

    query.insert(query.end(), q1.begin() + 12, q1.end());
    query.insert(query.end(), q2.begin() + 12, q2.end());

    auto resp = create_response(query);
    auto msg = DnsMessage::parse(resp);

    if (msg.header.qdcount != 2) {
        std::cerr << "multi_q: qdcount expected 2, got " << msg.header.qdcount << std::endl;
        return false;
    }
    if (msg.header.ancount != 2) {
        std::cerr << "multi_q: ancount expected 2, got " << msg.header.ancount << std::endl;
        return false;
    }
    if (msg.questions.size() != 2) {
        std::cerr << "multi_q: expected 2 questions, got " << msg.questions.size() << std::endl;
        return false;
    }
    if (msg.answers.size() != 2) {
        std::cerr << "multi_q: expected 2 answers, got " << msg.answers.size() << std::endl;
        return false;
    }
    if (msg.questions[0].labels[0] != "codecrafters" || msg.questions[0].labels[1] != "io") {
        std::cerr << "multi_q: q1 labels mismatch" << std::endl;
        return false;
    }
    if (msg.questions[1].labels[0] != "example" || msg.questions[1].labels[1] != "com") {
        std::cerr << "multi_q: q2 labels mismatch" << std::endl;
        return false;
    }
    if (msg.answers[0].name[0] != "codecrafters" || msg.answers[0].name[1] != "io") {
        std::cerr << "multi_q: a1 name mismatch" << std::endl;
        return false;
    }
    if (msg.answers[1].name[0] != "example" || msg.answers[1].name[1] != "com") {
        std::cerr << "multi_q: a2 name mismatch" << std::endl;
        return false;
    }
    for (size_t i = 0; i < 2; ++i) {
        if (msg.answers[i].type != 1 || msg.answers[i].cls != 1) {
            std::cerr << "multi_q: answer " << i << " type/class mismatch" << std::endl;
            return false;
        }
        if (msg.answers[i].ttl != 60) {
            std::cerr << "multi_q: answer " << i << " ttl mismatch" << std::endl;
            return false;
        }
        if (msg.answers[i].rdata.size() != 4) {
            std::cerr << "multi_q: answer " << i << " rdata size mismatch" << std::endl;
            return false;
        }
    }

    return true;
}

auto test_compressed_message_end_to_end() -> bool {
    // Full message: header + Q1(uncompressed) + Q2(compressed pointer)
    // Q1: codecrafters.io at offset 12
    // Q2: www + pointer to offset 12
    std::vector<std::byte> query = {
        std::byte{0xAB},
        std::byte{0xCD}, // id
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
        std::byte{0x0C},
        std::byte{0x00},
        std::byte{0x01},
        std::byte{0x00},
        std::byte{0x01},
    };

    auto resp = create_response(query);
    auto msg = DnsMessage::parse(resp);

    if (msg.questions.size() != 2) {
        std::cerr << "e2e: expected 2 questions, got " << msg.questions.size() << std::endl;
        return false;
    }
    if (msg.answers.size() != 2) {
        std::cerr << "e2e: expected 2 answers, got " << msg.answers.size() << std::endl;
        return false;
    }

    if (msg.questions[1].labels != std::vector<std::string>{"www", "codecrafters", "io"}) {
        std::cerr << "e2e: Q2 labels mismatch" << std::endl;
        return false;
    }
    if (msg.answers[1].name != std::vector<std::string>{"www", "codecrafters", "io"}) {
        std::cerr << "e2e: A2 name mismatch" << std::endl;
        return false;
    }

    for (size_t i = 0; i < 2; ++i) {
        if (msg.answers[i].type != 1 || msg.answers[i].cls != 1) {
            std::cerr << "e2e: answer " << i << " type/class mismatch" << std::endl;
            return false;
        }
    }

    // Verify response is fully uncompressed: no byte should have 0xC0 pattern
    for (size_t i = 12; i < resp.size(); ++i) {
        if ((static_cast<uint8_t>(resp[i]) & 0xC0) == 0xC0) {
            std::cerr << "e2e: response contains compression pointer at byte " << i << std::endl;
            return false;
        }
    }

    return true;
}

int main() {
    bool all_passed = true;

    if (!test_standard_query_response_header()) {
        std::cerr << "FAIL: test_standard_query_response_header" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_standard_query_response_header" << std::endl;
    }

    if (!test_response_id_echo()) {
        std::cerr << "FAIL: test_response_id_echo" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_response_id_echo" << std::endl;
    }

    if (!test_response_question_echo_with_random_domain()) {
        std::cerr << "FAIL: test_response_question_echo_with_random_domain" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_response_question_echo_with_random_domain" << std::endl;
    }

    if (!test_response_answer_matches_question_domain()) {
        std::cerr << "FAIL: test_response_answer_matches_question_domain" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_response_answer_matches_question_domain" << std::endl;
    }

    if (!test_response_multiple_questions()) {
        std::cerr << "FAIL: test_response_multiple_questions" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_response_multiple_questions" << std::endl;
    }

    if (!test_compressed_message_end_to_end()) {
        std::cerr << "FAIL: test_compressed_message_end_to_end" << std::endl;
        all_passed = false;
    } else {
        std::cout << "PASS: test_compressed_message_end_to_end" << std::endl;
    }

    return all_passed ? 0 : 1;
}
