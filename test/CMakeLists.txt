add_executable(address_test src/address_test.cpp)
target_link_libraries(address_test ${LIB_NAME} ${CONAN_LIBS})
add_test(NAME run_address_test COMMAND address_test)
