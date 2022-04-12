
#ifndef WILDCAT_NET_SSL_CONTEXT_HPP
#define WILDCAT_NET_SSL_CONTEXT_HPP

#include <stdexcept>
#include <openssl/ssl.h>
#include <openssl/err.h>

// TODO: how to enforce openssl 1.1.0+

namespace wildcat::net {

    /// SSL Context
    ///
    /// @paragraph
    class SslContext {
    public:
        SslContext() = default;

        virtual ~SslContext() {
            if (sslCtx_) {
                SSL_CTX_free(sslCtx_);
            }
        }

        /// Initializes the context
        void init() {
            const auto *method = TLS_client_method();
            sslCtx_ = SSL_CTX_new(method);

            if (sslCtx_ == NULL) {
                const auto err = ERR_get_error();
                throw std::runtime_error(ERR_error_string(err, 0));
            }

            // TODO: options for different versions and other parameters
            // TLS v1.2
            SSL_CTX_set_min_proto_version(sslCtx_, TLS1_2_VERSION);
            const auto flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
            SSL_CTX_set_options(sslCtx_, flags);
        }

        /// Gets the SSL context
        [[nodiscard]] inline SSL_CTX* sslContext() const
        {
            return sslCtx_;
        }

    private:
        SSL_CTX *sslCtx_;
    };

}

#endif //WILDCAT_NET_SSL_CONTEXT_HPP
