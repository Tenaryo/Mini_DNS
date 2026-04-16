#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

struct DnsResourceRecord {
    std::vector<std::string> name;
    uint16_t type{};
    uint16_t cls{};
    uint32_t ttl{};
    std::vector<std::byte> rdata;

    static auto parse(std::span<const std::byte> data) -> std::pair<DnsResourceRecord, size_t> {
        DnsResourceRecord rr;
        size_t offset = 0;
        while (offset < data.size()) {
            uint8_t len = static_cast<uint8_t>(data[offset]);
            ++offset;
            if (len == 0)
                break;
            rr.name.emplace_back(reinterpret_cast<const char*>(&data[offset]), len);
            offset += len;
        }

        auto get_u16 = [&data, &offset]() -> uint16_t {
            auto val = static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8) |
                                             static_cast<uint16_t>(data[offset + 1]));
            offset += 2;
            return val;
        };

        rr.type = get_u16();
        rr.cls = get_u16();

        auto get_u32 = [&data, &offset]() -> uint32_t {
            auto val = static_cast<uint32_t>((static_cast<uint32_t>(data[offset]) << 24) |
                                             (static_cast<uint32_t>(data[offset + 1]) << 16) |
                                             (static_cast<uint32_t>(data[offset + 2]) << 8) |
                                             static_cast<uint32_t>(data[offset + 3]));
            offset += 4;
            return val;
        };
        rr.ttl = get_u32();

        uint16_t rdlength = get_u16();
        rr.rdata.assign(data.begin() + static_cast<ptrdiff_t>(offset),
                        data.begin() + static_cast<ptrdiff_t>(offset + rdlength));
        offset += rdlength;

        return {rr, offset};
    }

    auto serialize() const -> std::vector<std::byte> {
        std::vector<std::byte> buf;
        for (const auto& label : name) {
            buf.push_back(static_cast<std::byte>(label.size()));
            for (char c : label) {
                buf.push_back(static_cast<std::byte>(c));
            }
        }
        buf.push_back(std::byte{0});

        auto put_u16 = [&buf](uint16_t val) {
            buf.push_back(static_cast<std::byte>(val >> 8));
            buf.push_back(static_cast<std::byte>(val & 0xFF));
        };
        put_u16(type);
        put_u16(cls);

        auto put_u32 = [&buf](uint32_t val) {
            buf.push_back(static_cast<std::byte>((val >> 24) & 0xFF));
            buf.push_back(static_cast<std::byte>((val >> 16) & 0xFF));
            buf.push_back(static_cast<std::byte>((val >> 8) & 0xFF));
            buf.push_back(static_cast<std::byte>(val & 0xFF));
        };
        put_u32(ttl);
        put_u16(static_cast<uint16_t>(rdata.size()));
        buf.insert(buf.end(), rdata.begin(), rdata.end());

        return buf;
    }
};
