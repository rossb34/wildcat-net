//
// Created by ross on 3/16/22.
//

#ifndef WILDCAT_NET_ADDRESS_HPP
#define WILDCAT_NET_ADDRESS_HPP

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cstring>
#include <string>
#include <vector>

namespace wildcat::net {

    enum class AddressFamily {
        IPv4,
    };

    /// Represents an Internet Protocol version 4 internet address
    class IPv4Address {
    public:
        /// Default constructs an IPv4Address
        IPv4Address() : addr_() {
            std::memset(&addr_, 0, sizeof(addr_));
        }

        /// Constructs an IPv4Address from a raw internet address
        explicit IPv4Address(const in_addr *address) : addr_() {
            std::memcpy(&addr_, address, sizeof(addr_));
        }

        /// Gets the address family
        static AddressFamily getAddressFamily() {
            return AddressFamily::IPv4;
        }

        /// Gets the address family
        /// \note The address family as defined in <sys/socket.h> (i.e. AF_*)
        static int af() {
            return AF_INET;
        }

        /// Parses an address in dot-decimal (i.e. numbers-and-dots) notation
        static IPv4Address parse(const std::string &address) {
            struct in_addr ia{};
            if (inet_aton(address.c_str(), &ia) == 1) {
                return IPv4Address(&ia);
            }
            return IPv4Address();
        }

        /// Gets the address
        [[nodiscard]] const in_addr_t *addr() const {
            return &addr_.s_addr;
        }

        /// Gets the size, in bytes, of the internet address structure
        [[nodiscard]] static socklen_t length() {
            return sizeof(struct in_addr);
        }

    private:
        struct in_addr addr_;
    };

    /// Socket address composed of an IP v4 address and port number
    class IPv4SocketAddress {
    public:
        /// Default constructs an IPv4SocketAddress
        IPv4SocketAddress() : sockaddr_() {
            std::memset(&sockaddr_, 0, sizeof(sockaddr_));
            sockaddr_.sin_family = AF_INET;
        }

        /// Constructs an IPv4SocketAddress from an internet socket address structure
        explicit IPv4SocketAddress(const struct sockaddr_in *sockaddr) : sockaddr_() {
            std::memcpy(&sockaddr_, sockaddr, sizeof(sockaddr_));
        }

        /// Constructs an IPv4SocketAddress from an address and port
        /// \note it is assumed the port is in host byte order
        IPv4SocketAddress(const std::string &address, std::uint16_t port) : sockaddr_() {
            const auto ipv4addr = IPv4Address::parse(address);
            std::memcpy(&sockaddr_.sin_addr, ipv4addr.addr(), sizeof(sockaddr_.sin_addr));
            sockaddr_.sin_port = htons(port);
            sockaddr_.sin_family = AF_INET;
        }

        /// Gets a pointer to the internet socket address structure
        [[nodiscard]] const struct sockaddr_in *sockaddr() const {
            return &sockaddr_;
        }

        /// Gets the size, in bytes, of the socket address structure
        [[nodiscard]] static socklen_t length() {
            return sizeof(struct sockaddr_in);
        }

    private:
        struct sockaddr_in sockaddr_;
    };

    class AddressInfoError : public std::exception {
    public:
        AddressInfoError(int code, const std::string &msg) : code_(code), msg_(msg) {}

        [[nodiscard]] const char *what() const noexcept override {
            return msg_.c_str();
        }

        [[nodiscard]] int code() const noexcept {
            return code_;
        }

    private:
        int code_;
        std::string msg_;
    };

    namespace {

        /// Translates a service, defined by a host and port, to a vector of IP v4 socket addresses
        std::vector<IPv4SocketAddress> getAddressInfo(const std::string &host, std::uint16_t port) {
            // https://man7.org/linux/man-pages/man3/getaddrinfo.3.html
            // Initialize hints for TCP socket (SOCK_STREAM) and IPv4 address (AF_INET)
            struct addrinfo hints{};
            std::memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            // Allocates and initializes a linked list of addrinfo structures pointed to by ai
            struct addrinfo *ai;
            auto result = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai);
            if (result < 0) {
                if (ai) {
                    freeaddrinfo(ai);
                }
                throw AddressInfoError(result, gai_strerror(result));
            }

            std::vector<IPv4SocketAddress> addressInfo;
            for (const auto *p = ai; p != nullptr; p = p->ai_next) {
                if (p->ai_family == AF_INET) {
                    const auto *sa = (struct sockaddr_in *) p->ai_addr;
                    IPv4SocketAddress ipsa(sa);
                    addressInfo.push_back(ipsa);
                }
            }
            freeaddrinfo(ai);
            return addressInfo;
        }
    }

}

#endif //WILDCAT_NET_ADDRESS_HPP
