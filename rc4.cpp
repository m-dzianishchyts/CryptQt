#include "rc4.h"
#include "iostream"

EncryptorRC4::EncryptorRC4(const std::vector<uint8_t> &key) {
    initSBlock(key);
}

EncryptorRC4::~EncryptorRC4() {
    delete(sBlock);
}

void EncryptorRC4::initSBlock(const std::vector<uint8_t> &key) {
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

uint8_t EncryptorRC4::keyItem() {
    x = (x + 1) % sBlock->size();
    y = (y + (*sBlock)[x]) % sBlock->size();
    swap((*sBlock)[x], (*sBlock)[y]);
    return (*sBlock)[((*sBlock)[x] + (*sBlock)[y]) % sBlock->size()];
}

void EncryptorRC4::swap(uint8_t &a, uint8_t &b) {
    uint8_t &temp = a;
    a = b;
    b = temp;
}

std::vector<uint8_t> *EncryptorRC4::encrypt(const std::vector<uint8_t> &message) {
    auto cipher = new std::vector<uint8_t>(message.size());
    for (size_t i = 0; i < message.size(); i++) {
        (*cipher)[i] = (message[i] ^ keyItem());
    }
    return cipher;
}

std::vector<uint8_t> *EncryptorRC4::decrypt(const std::vector<uint8_t> &cipher) {
    return encrypt(cipher);
}

void EncryptorRC4::reset(const std::vector<uint8_t> &key) {
    initSBlock(key);
    x = y = 0;
}

#ifdef DEBUG
void EncryptorRC4::print() {
    std::cout << "RC4. Key:";
    for (auto a : *sBlock) {
        std::cout << " " << (int) a;
    }
    std::cout << std::endl;
}
#endif

