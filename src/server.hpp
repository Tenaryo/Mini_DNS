#pragma once

#include "protocol/message.hpp"

#include <cstddef>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

class DnsServer {
    int sockfd_{-1};
    uint16_t port_;

    static auto create_response(std::span<const std::byte> request) -> std::vector<std::byte> {
        auto msg = DnsMessage::parse(request);
        msg.header.qr = true;
        msg.header.ancount = 1;

        DnsResourceRecord answer{};
        answer.name = {"codecrafters", "io"};
        answer.type = 1;
        answer.cls = 1;
        answer.ttl = 60;
        answer.rdata = {std::byte{0x08}, std::byte{0x08}, std::byte{0x08}, std::byte{0x08}};
        msg.answers.push_back(std::move(answer));

        return msg.serialize();
    }
  public:
    explicit DnsServer(uint16_t port) : port_{port} {}

    ~DnsServer() {
        if (sockfd_ != -1)
            close(sockfd_);
    }

    DnsServer(const DnsServer&) = delete;
    auto operator=(const DnsServer&) -> DnsServer& = delete;
    DnsServer(DnsServer&& o) noexcept : sockfd_{o.sockfd_}, port_{o.port_} { o.sockfd_ = -1; }
    auto operator=(DnsServer&& o) noexcept -> DnsServer& {
        if (this != &o) {
            if (sockfd_ != -1)
                close(sockfd_);
            sockfd_ = o.sockfd_;
            port_ = o.port_;
            o.sockfd_ = -1;
        }
        return *this;
    }

    void run() {
        sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd_ == -1) {
            throw std::runtime_error("socket creation failed");
        }

        int reuse = 1;
        setsockopt(sockfd_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(sockfd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            throw std::runtime_error("bind failed");
        }

        std::byte buffer[512];
        sockaddr_in client{};
        socklen_t client_len = sizeof(client);

        while (true) {
            auto n = recvfrom(sockfd_,
                              buffer,
                              sizeof(buffer),
                              0,
                              reinterpret_cast<sockaddr*>(&client),
                              &client_len);
            if (n <= 0)
                break;

            auto response = create_response({buffer, static_cast<size_t>(n)});
            sendto(sockfd_,
                   response.data(),
                   response.size(),
                   0,
                   reinterpret_cast<sockaddr*>(&client),
                   sizeof(client));
        }
    }
};
