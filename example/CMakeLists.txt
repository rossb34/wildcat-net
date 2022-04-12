add_executable(tcp_client_hello tcp_client_hello.cpp)
target_link_libraries(tcp_client_hello ${LIB_NAME} ${CONAN_LIBS})

add_executable(tls_client_hello tls_client_hello.cpp)
target_link_libraries(tls_client_hello ${LIB_NAME} ${CONAN_LIBS})
