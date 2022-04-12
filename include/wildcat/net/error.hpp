//
// Created by ross on 3/17/22.
//

#ifndef WILDCAT_NET_ERROR_HPP
#define WILDCAT_NET_ERROR_HPP

#include <string>
#include <exception>

namespace wildcat::net {

    class IOError : public std::exception {
    public:
        IOError(int code, const std::string &msg) : code_(code), msg_(msg) {}

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

    class SSLError : public std::exception {
    public:
        SSLError(int code, const std::string &msg) : code_(code), msg_(msg) {}

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

}

#endif //WILDCAT_NET_ERROR_HPP
