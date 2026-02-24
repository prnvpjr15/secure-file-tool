cmake_minimum_required(VERSION 3.15)
project(SecureFileTool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use modern CONFIG packages (vcpkg style)
find_package(wxWidgets CONFIG REQUIRED)
find_package(CryptoPP CONFIG REQUIRED)

add_executable(SecureFileTool WIN32
    src/main.cpp
    src/crypto_utils.cpp
    src/file_io.cpp
    src/audit_log.cpp
)

target_link_libraries(SecureFileTool
    wx::core
    wx::base
    cryptopp::cryptopp
)