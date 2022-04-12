
#include <wildcat/net/secure_socket_stream.hpp>

int main() {

    auto s = std::make_unique<wildcat::net::SocketStream>(true);
    auto ctx = std::make_unique<wildcat::net::SslContext>();
    ctx->init();

    wildcat::net::SecureSocketStream ss(std::move(s), std::move(ctx));
    ss.connect("www.google.com", 443);
}

