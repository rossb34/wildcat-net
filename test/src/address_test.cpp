//
// Created by ross on 3/16/22.
//


#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <wildcat/net/address.hpp>


namespace {

    TEST(IPv4AddressTest, Family) {
        EXPECT_EQ(wildcat::net::AddressFamily::IPv4, wildcat::net::IPv4Address::getAddressFamily());
        EXPECT_EQ(AF_INET, wildcat::net::IPv4Address::af());
    }

    TEST(IPv4AddressTest, Parse) {
        struct in_addr ia{};
        inet_aton("127.0.0.1", &ia);

        EXPECT_EQ(ia.s_addr, *wildcat::net::IPv4Address::parse("127.0.0.1").addr());
    }

    TEST(AddressInfo, GetAddressInfo) {
        const auto ai = wildcat::net::getAddressInfo("127.0.0.1", "5555");
        EXPECT_EQ(1, ai.size());
        auto e = ai[0];

        wildcat::net::IPv4SocketAddress sa("127.0.0.1", 5555);
        EXPECT_EQ(sa.sockaddr()->sin_port, e.sockaddr()->sin_port);
        EXPECT_EQ(sa.sockaddr()->sin_addr.s_addr, e.sockaddr()->sin_addr.s_addr);
    }

}
