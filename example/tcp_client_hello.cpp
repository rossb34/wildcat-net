// In order for this example to work, a TCP server must be listening on port 6789.
// $nc -l 6789


#include <iostream>
#include <wildcat/net/socket_stream.hpp>

int main() {
    // non-blocking socket
    wildcat::net::SocketStream ss;
    ss.setNoDelay(true);

    try {
        ss.connect("localhost", "6789");
    } catch (wildcat::net::IOError &e) {
        std::cerr << "Failed to connect socket with error code: " << e.code() << ", msg: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    const std::string msg = "hello";
    std::cout << "sending message \"" << msg << "\" to port 6789" << std::endl;
    auto bytesSent = ss.sendBytes(msg.c_str(), msg.length());
    if (bytesSent == msg.length()) {
        std::cout << "success!" << std::endl;
    }

    exit(EXIT_SUCCESS);
}
