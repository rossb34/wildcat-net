add_executable(address_test src/address_test.cpp)
target_link_libraries(address_test ${LIB_NAME} ${CONAN_LIBS})
add_test(NAME run_address_test COMMAND address_test)

add_executable(socket_stream_test src/socket_stream_test.cpp)
target_link_libraries(socket_stream_test ${LIB_NAME} ${CONAN_LIBS})
add_test(NAME run_socket_stream_test COMMAND socket_stream_test)
