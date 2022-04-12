
#ifndef WILDCAT_NET_SECURE_SOCKET_STREAM_HPP
#define WILDCAT_NET_SECURE_SOCKET_STREAM_HPP

#include <memory>
#include <openssl/ssl.h>

#include "ssl_context.hpp"
#include "socket_stream.hpp"

namespace wildcat::net {


    /// Wraps an SSL structure that holds data needed for a TLS/SSL connection
    class SslConn {
    public:
        /// Constructs an SSL Connection from a raw pointer to an SSL_CTX
        /// @note throws an exception if there is a failure creating the SSL structure
        explicit SslConn(SSL_CTX *ctx) {
            ssl_ = SSL_new(ctx);
            if (ssl_ == nullptr) {
                const auto err = ERR_get_error();
                throw std::runtime_error(ERR_error_string(err, nullptr));
            }
        }

        /// Constructs an SSL Connection from the specified context
        /// @note throws an exception if there is a failure creating the SSL structure
        explicit SslConn(const SslContext &context) {
            ssl_ = SSL_new(context.sslContext());
            if (ssl_ == nullptr) {
                const auto err = ERR_get_error();
                throw std::runtime_error(ERR_error_string(err, nullptr));
            }
        }

        /// Finalizes the SSL class
        ///
        /// @note calls SSL_free() to free the underlying pointer to the ssl structure
        virtual ~SslConn() {
            if (ssl_) {
                SSL_free(ssl_);
            }
        }

        [[nodiscard]] SSL *ssl() const {
            return ssl_;
        }

    private:
        SSL *ssl_;
    };

    class SecureSocketStream {
    public:

        /// Constructs a SecureSocketStream from the specified socket stream and ssl context
        SecureSocketStream(std::unique_ptr<SocketStream> socketStream, std::unique_ptr<SslContext> sslContext)
                : socketStream_(std::move(socketStream)), sslContext_(std::move(sslContext)) {}

        /// Connects to the specified host and port
        /// @note Attempts to connect the underlying socket and then performs the handshake for SSL/TLS
        void connect(const std::string &host, std::uint16_t port) {
            socketStream_->connect(host, port);
            connectSSL(host);
        }

        /// Disconnects the socket stream
        void disconnect() {
            // TODO: should I retry shutdown? https://www.openssl.org/docs/man3.0/man3/SSL_shutdown.html
            SSL_shutdown(ssl_->ssl());
            socketStream_->disconnect();
        }

        /// Receives len bytes of data in buffer from the socket file descriptor
        ///
        /// \param buffer buffer to receive len bytes of data.
        /// \param len maximum number of bytes to read (i.e. length of buffer).
        /// \return the number of bytes read. On error, will throw an IOError exception with code set to errno and what
        /// set to the string description of the error.
        ssize_t recvBytes(char *buffer, size_t len) const {
            const auto rv = SSL_read(ssl_->ssl(), buffer, len);
            if (rv <= 0) {
                return handleErrorCode(rv);
            }
            return rv;
        }

        /// Sends len bytes of data in buffer to the socket file descriptor
        ///
        /// \param buffer buffer of data to send.
        /// \param len number of bytes to send.
        /// \return returns the number of bytes sent. On error, will throw an IOError exception with code set to errno
        /// and what set to the string description of the error.
        ssize_t sendBytes(const char *buffer, size_t len) const {
            const auto rv = SSL_write(ssl_->ssl(), buffer, len);
            if (rv <= 0) {
                return handleErrorCode(rv);
            }
            return rv;
        }

        /// Gets the socket file descriptor
        [[nodiscard]] int fd() const {
            return socketStream_->fd();
        }

        /// Gets the socket stream
        [[nodiscard]] const SocketStream *getSocketStream() const {
            return socketStream_.get();
        }

    private:
        std::unique_ptr<SocketStream> socketStream_;
        std::unique_ptr<SslConn> ssl_;
        std::unique_ptr<SslContext> sslContext_;

        bool doRetry(const int code) {
            if (code <= 0) {
                const int sslErrorCode = SSL_get_error(ssl_->ssl(), code);
                switch (sslErrorCode) {
                    case SSL_ERROR_WANT_READ:
                        if (socketStream_->getBlocking()) {
                            struct pollfd pfd{};
                            pfd.fd = socketStream_->fd();
                            pfd.events = POLLIN;
                            // FIXME: variable for timeout
                            const auto pollTimeoutMillis = 5000;
                            if (poll(&pfd, 1, pollTimeoutMillis) < 0) {
                                throw IOError(errno, strerror(errno));
                            }
                            return true;
                        }
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        if (socketStream_->getBlocking()) {
                            struct pollfd pfd{};
                            pfd.fd = socketStream_->fd();
                            pfd.events = POLLOUT;
                            // FIXME: variable for timeout
                            const auto pollTimeoutMillis = 5000;
                            if (poll(&pfd, 1, pollTimeoutMillis) < 0) {
                                throw IOError(errno, strerror(errno));
                            }
                            return true;
                        }
                        break;
                    case SSL_ERROR_SYSCALL:
                        return errno == EAGAIN || errno == EWOULDBLOCK;
                    default:
                        return false;
                }


            }
            return false;
        }

        /// Initiate the ssl connection
        void connectSSL(const std::string &host) {
            ssl_ = std::make_unique<SslConn>(sslContext_->sslContext());
            SSL_set_fd(ssl_->ssl(), socketStream_->fd());
            SSL_set_tlsext_host_name(ssl_->ssl(), host.c_str());

            bool connected = false;
            // FIXME: add a connect timeout condition
            while (!connected) {
                const auto connect = SSL_connect(ssl_->ssl());

                if (connect == 1) {
                    connected = true;
                } else if (connect <= 0) {
                    int sslError = SSL_get_error(ssl_->ssl(), connect);
                    switch (sslError) {
                        case SSL_ERROR_NONE:
                            connected = true;
                            break;
                        case SSL_ERROR_SSL: {
                            // std::cout << "ERROR_SSL" << std::endl;
                            // fatal protocol error
                            auto err = ERR_get_error();
                            char errBuf[256];
                            ERR_error_string_n(err, errBuf, sizeof(errBuf));
                            std::string msg(errBuf);
                            throw SSLError(err, msg);
                        }
                        case SSL_ERROR_SYSCALL:
                            // fatal IO error
                            // std::cout << "ERROR SYSCALL errno " << errno << std::endl;
                            throw IOError(errno, strerror(errno));
                        case SSL_ERROR_WANT_READ: {
                            // std::cout << "ERROR_WANT_READ" << std::endl;
                            // structure to poll the socket file descriptor for readiness to read
                            struct pollfd pfd{};
                            pfd.fd = socketStream_->fd();
                            pfd.events = POLLIN;
                            const auto pollTimeoutMillis = 5000;
                            if (poll(&pfd, 1, pollTimeoutMillis) < 0) {
                                throw IOError(errno, strerror(errno));
                            }
                        }
                            break;
                        case SSL_ERROR_WANT_WRITE: {
                            // std::cout << "ERROR_WANT_WRITE" << std::endl;
                            // structure to poll the socket file descriptor for readiness to write
                            struct pollfd pfd{};
                            pfd.fd = socketStream_->fd();
                            pfd.events = POLLOUT;
                            const auto pollTimeoutMillis = 5000;
                            if (poll(&pfd, 1, pollTimeoutMillis) < 0) {
                                throw IOError(errno, strerror(errno));
                            }
                        }
                            break;
                        default:
                            // std::cout << "default: SSL error code " << sslError << std::endl;
                            break;
                    }
                }
            }
        }

        /// Handles the SSL error code
        [[nodiscard]] ssize_t handleErrorCode(int code) const {
            if (code > 0)
                return code;

            const auto sslError = SSL_get_error(ssl_->ssl(), code);
            switch (sslError) {
                case SSL_ERROR_SSL: {
                    // fatal error
                    char errBuf[256];
                    ERR_error_string_n(sslError, errBuf, sizeof(errBuf));
                    std::string msg(errBuf);
                    throw SSLError(sslError, msg);
                }
                case SSL_ERROR_WANT_READ:
                    // return 0;
                case SSL_ERROR_WANT_WRITE:
                    return 0;
                case SSL_ERROR_SYSCALL:
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        return 0;
                    } else {
                        throw IOError(errno, strerror(errno));
                    }
                default:
                    return code;
            }
        }

    };

}

#endif //WILDCAT_NET_SECURE_SOCKET_STREAM_HPP
