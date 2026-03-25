/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SERVICE_H_
#define _SERVICE_H_

#include <memory>
#include <unordered_map>
#include <boost/version.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/udp.hpp>
#include "authenticator.h"
#include "session/udpforwardsession.h"

class Service {
private:
    enum {
        MAX_LENGTH = 8192
    };
    const Config &config;
    boost::asio::ssl::context ssl_context;
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::acceptor socket_acceptor;
    std::unique_ptr<Authenticator> auth;
    std::string plain_http_response;
    boost::asio::ip::udp::socket udp_socket;
    struct EndpointHash {
        std::size_t operator()(const boost::asio::ip::udp::endpoint &ep) const {
            auto addr = ep.address();
            std::size_t h;
            if (addr.is_v4()) {
                auto bytes = addr.to_v4().to_bytes();
                h = (std::size_t(bytes[0]) << 24) | (std::size_t(bytes[1]) << 16) |
                    (std::size_t(bytes[2]) << 8)  |  std::size_t(bytes[3]);
            } else {
                auto bytes = addr.to_v6().to_bytes();
                h = 0;
                for (auto b : bytes) h = h * 131 + b;
            }
            h ^= std::hash<unsigned short>()(ep.port()) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
    std::unordered_map<boost::asio::ip::udp::endpoint, std::weak_ptr<UDPForwardSession>, EndpointHash> udp_sessions;
    uint8_t udp_read_buf[MAX_LENGTH]{};
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    void async_accept();
    void udp_async_read();
public:
    explicit Service(Config &config, bool test = false);
    void run();
    void stop();
    boost::asio::io_context &service();
    void reload_cert();
    ~Service();
};

#endif // _SERVICE_H_
