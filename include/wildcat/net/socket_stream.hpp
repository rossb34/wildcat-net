//
// Created by ross on 3/17/22.
//

#ifndef WILDCAT_NET_SOCKET_STREAM_HPP
#define WILDCAT_NET_SOCKET_STREAM_HPP


#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <fcntl.h>
#include <poll.h>

#include "address.hpp"
#include "error.hpp"

namespace wildcat::net {


    /// Represents a socket stream of a TCP client that connects to a remote server
    class SocketStream {
    public:
        /// Default constructs a SocketStream
        /// \note Default behavior creates a SocketStream from a blocking socket of type SOCK_STREAM and domain AF_INET.
        SocketStream()
                : fd_(socket(AF_INET, SOCK_STREAM, 0)), blocking_(true) {}

        /// Constructs a SocketStream with the specified blocking
        /// \param blocking true creates a blocking socket, false creates a non-blocking socket
        /// \note If blocking is set to false, creates a SocketStream from a socket of type SOCK_STREAM | SOCK_NONBLOCK
        /// and domain AF_INET.
        explicit SocketStream(bool blocking)
                : fd_(socket(AF_INET, blocking ? SOCK_STREAM : SOCK_STREAM | SOCK_NONBLOCK, 0)), blocking_(blocking) {}

        /// Destructor closes the socket file descriptor
        virtual ~SocketStream() {
            if (fd_ != -1) {
                close(fd_);
            }
        }

        /// Gets the socket file descriptor
        [[nodiscard]] int fd() const {
            return fd_;
        }

        /// Connects the socket to the specified socket address
        ///
        /// \param socketAddress socket address to connect to
        void connect(const wildcat::net::IPv4SocketAddress &socketAddress) const {
            if (blocking_) {
                connectBlocking(socketAddress);
            } else {
                connectNonBlocking(socketAddress);
            }
        }

        /// Connects the socket to the specified host and port
        ///
        /// \param host host to connect to
        /// \param port port to connect to
        void connect(const std::string &host, std::uint16_t port) const {
            const auto addressInfo = getAddressInfo(host, port);

            if (blocking_) {
                for (auto &&ai : addressInfo) {
                    if (connectBlocking(ai))
                        break;
                }
            } else {
                for (auto &&ai : addressInfo) {
                    if (connectNonBlocking(ai))
                        break;
                }
            }
        }

        /// Disconnects the socket
        void disconnect() {
            if (fd_ != -1) {
                close(fd_);
                fd_ = -1;
            }
        }

        /// Receives len bytes of data in buffer from the socket file descriptor
        ///
        /// \param buffer buffer to receive len bytes of data.
        /// \param len maximum number of bytes to read (i.e. length of buffer).
        /// \return the number of bytes read. On error, will throw an IOError exception with code set to errno and what
        /// set to the string description of the error.
        ssize_t recvBytes(char *buffer, size_t len) const {
            const auto rv = recv(fd_, buffer, len, 0);
            if (rv == -1) {
                // errno is set to EAGAIN if there was nothing to receive on the socket or recv would block.
                // EAGAIN means resource temporarily unavailable and can be the same value as EWOULDBLOCK.
                // Any other error number is treated as a socket connection problem or socket read failure.

                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 0;
                } else {
                    throw IOError(errno, strerror(errno));
                }
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
            const auto rv = send(fd_, buffer, len, 0);
            if (rv == -1) {
                // errno is set to EAGAIN if the send would block.
                // EAGAIN means resource temporarily unavailable and can be the same value as EWOULDBLOCK.
                // Any other error number is treated as a connection problem or send failure.

                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return 0;
                } else {
                    throw IOError(errno, strerror(errno));
                }
            }

            return rv;
        }

        /// Sets the raw option on the socket
        ///
        /// \param level the level at which the option resides
        /// \param name the name of the option
        /// \param val the value of the option
        /// \param len the size of the buffer pointed to by val.
        /// \return returns true if the operation completed successfully. On error, false is returned. In the case
        /// of an error, errno is set.
        /// \note this function is a wrapper around the C function setsockopt. See setsockopt(2) for additional details.
        bool setOption(int level, int name, const void *val, socklen_t len) const {
            return setsockopt(fd_, level, name, val, len) == 0;
        }

        /// Gets the raw option on the socket
        ///
        /// \param level the level at which the option resides
        /// \param name the name of the option
        /// \param val the value of the option
        /// \param len the size of the buffer pointed to by val.
        /// \return returns true if the operation completed successfully. On error, false is returned. In the case
        /// of an error, errno is set.
        /// \note this function is a wrapper around the C function getsockopt. See getsockopt(2) for additional details.
        bool getOption(int level, int name, void *val, socklen_t *len) const {
            return getsockopt(fd_, level, name, val, len) == 0;
        }

        /// Sets the tcp no delay flag
        ///
        /// \param flag true to set TCP_NODELAY.
        /// \return returns true if the operation completed successfully. On error, false is returned. In the case
        /// of an error, errno is set.
        void setNoDelay(bool flag) const {
            int value = flag ? 1 : 0;
            setOption(IPPROTO_TCP, TCP_NODELAY, &value, sizeof(int));
        }

        /// Gets the tcp no delay flag
        ///
        /// \return true if tcp no delay flag is set to true (i.e. Nagle's algorithm is disabled), otherwise false.
        [[nodiscard]] bool getNoDelay() const {
            int value(0);
            socklen_t len = sizeof(int);
            getsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, &value, &len);
            return value != 0;
        }

        /// Sets the blocking flag
        ///
        /// \param flag true to set the socket to blocking mode, `false` to set the socket to non-blocking model.
        /// \return returns true if the operation completed successfully. On error, false is returned. In the case
        /// of an error, errno is set.
        [[nodiscard]] bool setBlocking(bool flag) {
            int opts = fcntl(fd_, F_GETFL, 0);
            if (opts == -1)
                return false;
            // clear non block bit
            int flags = opts & ~O_NONBLOCK;
            if (!flag)
                flags |= O_NONBLOCK;
            blocking_ = flag;
            return fcntl(fd_, F_SETFL, flags) == 0;
        }

        /// Gets the blocking flag
        ///
        /// \return returns true if the socket is blocking, false if the socket is non-blocking.
        [[nodiscard]] bool getBlocking() const {
            return blocking_;
        }

    private:
        int fd_;
        bool blocking_;

        /// Simple connect logic for a blocking socket
        bool connectBlocking(const IPv4SocketAddress &socketAddress) const {
            bool connected = false;
            const auto *sa = (struct sockaddr *) socketAddress.sockaddr();
            if (::connect(fd_, sa, sizeof(struct sockaddr)) == 0) {
                connected = true;
            }

            // The connection failed, throw an exception
            if (!connected) {
                throw IOError(errno, strerror(errno));
            }
            return true;
        }

        /// Connect logic for a non-blocking socket
        bool connectNonBlocking(const IPv4SocketAddress &socketAddress) const {
            const auto *sa = (struct sockaddr *) socketAddress.sockaddr();
            if (::connect(fd_, sa, sizeof(struct sockaddr)) == 0) {
                return true;
            }

            int socketErrorCode = 0;
            if (errno == EINPROGRESS) {
                // connect() returned -1 and errno indicates the connect operation is in progress

                // From connect docs... The socket is nonblocking and the connection cannot be completed
                // immediately. It is possible to select(2) or poll(2) for completion by selecting the socket
                // for writing. After select(2) indicates writability, use getsockopt(2) to read the SO_ERROR
                // option at level SOL_SOCKET to determine whether connect() completed successfully (SO_ERROR is
                // zero) or unsuccessfully (SO_ERROR is one of the usual error codes listed here, explaining the
                // reason for the failure).

                // structure to poll the socket file descriptor for readiness to write
                struct pollfd pfd{};
                pfd.fd = fd_;
                pfd.events = POLLOUT;
                const auto pollTimeoutMillis = 5000;

                const auto pollResult = poll(&pfd, 1, pollTimeoutMillis);
                if (pollResult == 1) {
                    socklen_t len = sizeof(int);
                    if (getOption(SOL_SOCKET, SO_ERROR, &socketErrorCode, &len) and socketErrorCode == 0) {
                        return true;
                    }
                } else if (pollResult == -1) {
                    throw IOError(errno, strerror(errno));
                }
            }

            // If we get to this point, then we have exhausted all addresses and have failed to connect.
            // Throw an IOError with the socket error code from getsockopt(2) to read the SO_ERROR option
            throw IOError(socketErrorCode, strerror(socketErrorCode));
        }

    };
}

#endif //WILDCAT_NET_SOCKET_STREAM_HPP
