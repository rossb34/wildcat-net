
#include "wildcat/net/ssl_context.hpp"
#include "gtest/gtest.h"


namespace {

    TEST(SslContext, Init) {
        wildcat::net::SslContext ctx;
        ctx.init();
        EXPECT_EQ(TLS1_2_VERSION, SSL_CTX_get_min_proto_version(ctx.sslContext()));
    }
}

