cmake_minimum_required(VERSION 3.14)
project(zhcipher CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# 库：诗句编码器（不依赖 libsodium）+ 加密层
add_library(zhc STATIC src/lexicon.cpp src/poem_codec.cpp src/zh_crypto.cpp)
target_include_directories(zhc PUBLIC src ${SODIUM_INCLUDE_DIRS})
target_link_libraries(zhc PUBLIC ${SODIUM_LIBRARIES})

# 命令行
add_executable(zhcipher src/main.cpp)
target_link_libraries(zhcipher zhc)

# 测试
add_executable(test_codec tests/test_codec.cpp src/lexicon.cpp src/poem_codec.cpp)
add_executable(test_crypto tests/test_crypto.cpp)
target_link_libraries(test_crypto zhc)
enable_testing()
add_test(NAME codec COMMAND test_codec)
add_test(NAME crypto COMMAND test_crypto)
