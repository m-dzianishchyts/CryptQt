#include "rc4.h"

EncryptRC4::EncryptRC4(const std::vector<uint8_t> &key) {
    initSBlock(key);
}

void EncryptRC4::initSBlock(const std::vector<uint8_t> &key) {
    if (sBlock == nullptr) {
        sBlock = new std::array<uint8_t, 256>();
    }
    for (size_t i = 0; i < sBlock->size(); i++) {
        (*sBlock)[i] = static_cast<uint8_t>(i);
    }
    uint16_t j = 0;
    for (size_t i = 0; i < sBlock->size(); i++) {
        j = (j + (*sBlock)[i] + key[i % key.size()]) % sBlock->size();
        swap((*sBlock)[i], (*sBlock)[j]);
    }
}

uint8_t EncryptRC4::keyItem() {
    x = (x + 1) % sBlock->size();
    y = (y + (*sBlock)[x]) % sBlock->size();
    swap((*sBlock)[x], (*sBlock)[y]);
    return (*sBlock)[((*sBlock)[x] + (*sBlock)[y]) % sBlock->size()];
}

void EncryptRC4::swap(uint8_t &a, uint8_t &b) {
    uint8_t &temp = a;
    a = b;
    b = temp;
}

std::vector<uint8_t> *EncryptRC4::encrypt(const std::vector<uint8_t> &message) {
    auto *cipher = new std::vector<uint8_t>(message.size());
    for (size_t i = 0; i < message.size(); i++) {
        (*cipher)[i] = (message[i] ^ keyItem());
    }
    return cipher;
}

std::vector<uint8_t> *EncryptRC4::decrypt(const std::vector<uint8_t> &cipher) {
    return encrypt(cipher);
}

void EncryptRC4::reset(const std::vector<uint8_t> &key) {
    initSBlock(key);
    x = y = 0;
}