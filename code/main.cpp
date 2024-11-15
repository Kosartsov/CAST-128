
#include "cast128.h"
#include "cast128.cpp"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>

void encryptMessage(cast128& alg, uint64_t key[2], std::string& message) {
    std::vector<uint64_t> blocks;
    size_t message_length = message.length();
    size_t num_blocks = (message_length + 7) / 8;
    
    for (size_t i = 0; i < num_blocks; ++i) {
        uint64_t block = 0;
        for (size_t j = 0; j < 8; ++j) {
            if (i * 8 + j < message_length) {
                block |= (static_cast<uint64_t>(message[i * 8 + j]) << (j * 8));
            }
        }
        blocks.push_back(alg.encrypt(block, key));
    }

    std::cout << "Encoded Message: ";
    for (const auto& encoded_block : blocks) {
        std::cout << "0x" << std::hex << encoded_block << " ";
    }
    std::cout << std::endl;

    std::cout << "Decoded Message: ";
    for (const auto& encoded_block : blocks) {
        uint64_t decoded_block = alg.decrypt(encoded_block, key);
        for (size_t j = 0; j < 8; ++j) {
            if (decoded_block & (0xFFULL << (j * 8))) {
                std::cout << static_cast<char>((decoded_block >> (j * 8)) & 0xFF);
            }
        }
    }
    std::cout << std::endl;
}

int main() {
    cast128 alg;

    uint64_t key[2];
    key[0] = 0x0123456712345678;
    key[1] = 0x234567893456789A;

    // uint64_t msg = 0x0123456789ABCDEF;

    // uint64_t encoded_msg = alg.encrypt(msg, key);
    // uint64_t decoded_msg = alg.decrypt(encoded_msg, key);

    // std::cout << "------------Test 1--------------" << std::endl;
    // std::cout << "Message: 0x" << std::hex << msg << std::endl;
    // std::cout << "Encoded: 0x" << std::hex << encoded_msg << std::endl;
    // std::cout << "Decoded: 0x" << std::hex << decoded_msg << std::endl;

    std::cout << "------------Test 2--------------" << std::endl;
    std::string message = "Hello, world";
    encryptMessage(alg, key, message);
}
