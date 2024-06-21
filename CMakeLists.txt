cmake_minimum_required(VERSION 3.10)
project(BlockchainVotingSystem)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

include_directories(include)
add_executable(BlockchainVotingSystem src/main.cpp src/crypto_utils.cpp src/blockchain.cpp)
target_link_libraries(BlockchainVotingSystem OpenSSL::SSL OpenSSL::Crypto)
