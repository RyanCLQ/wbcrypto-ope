set(TEST_BUILD_NAME ope_test)
add_executable(${TEST_BUILD_NAME} example.cpp)
target_compile_features(${TEST_BUILD_NAME} PRIVATE cxx_std_17)
TARGET_LINK_LIBRARIES(${TEST_BUILD_NAME} ope -lntl -lgmp  -lcrypto -lpthread)

add_executable(speedtest speed_test.cpp)
target_compile_features(speedtest PRIVATE cxx_std_17)
TARGET_LINK_LIBRARIES(speedtest ope -lntl -lgmp  -lcrypto -lpthread)
