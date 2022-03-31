//
// Created by ross on 3/16/22.
//


#include <wildcat/net/socket_stream.hpp>
#include "gtest/gtest.h"


namespace {

    TEST(SocketStream, Init) {
        // default blocking socket
        {
            wildcat::net::SocketStream ss;
            EXPECT_TRUE(ss.getBlocking());
            EXPECT_NE(-1, ss.fd());
        }

        // explicit blocking socket
        {
            wildcat::net::SocketStream ss(true);
            EXPECT_TRUE(ss.getBlocking());
            EXPECT_NE(-1, ss.fd());
        }

        // explicit non-blocking socket
        {
            wildcat::net::SocketStream ss(false);
            EXPECT_FALSE(ss.getBlocking());
            EXPECT_NE(-1, ss.fd());
        }
    }

    TEST(SocketStream, Options) {
        wildcat::net::SocketStream ss;
        ss.setNoDelay(true);
        EXPECT_TRUE(ss.getNoDelay());

        ss.setNoDelay(false);
        EXPECT_FALSE(ss.getNoDelay());

        EXPECT_TRUE(ss.setBlocking(true));
        EXPECT_TRUE(ss.getBlocking());

        EXPECT_TRUE(ss.setBlocking(false));
        EXPECT_FALSE(ss.getBlocking());
    }

    TEST(SocketStream, Connect) {
        wildcat::net::SocketStream ss;
        EXPECT_ANY_THROW(ss.connect("127.0.0.1", 5555));
    }

    // TODO: test send and recv

}
