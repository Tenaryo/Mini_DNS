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

    return all_passed ? 0 : 1;
}
