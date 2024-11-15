
#include "cast128.h"
#include "cast128.cpp"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

int main() {
    cast128 alg;

    uint64_t key[2];
    key[0] = 0x0123456712345678;
    key[1] = 0x234567893456789A;

    uint64_t msg = 0x0123456789ABCDEF;

    uint64_t encoded_msg = alg.encrypt(msg, key);
    uint64_t decoded_msg = alg.decrypt(encoded_msg, key);

    std::cout << "Message: 0x" << std::hex << msg << std::endl;
    std::cout << "Encoded: 0x" << std::hex << encoded_msg << std::endl;
    std::cout << "Decoded: 0x" << std::hex << decoded_msg << std::endl;
}