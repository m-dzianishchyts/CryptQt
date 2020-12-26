#include "rc4.h"
#include "mathutils.h"

#include <random>

EncryptorRC4::EncryptorRC4() {
    algorithm = EncryptionAlgorithm::RC4;
    auto keyContainer = new std::vector<uint8_t>(64);
    std::mt19937_64 rng(currentTime());
    std::uniform_int_distribution<uint8_t> dist(0, CHAR_MAX);
    for (size_t i = 0; i < keyContainer->size(); i++) {
        keyContainer->at(i) = dist(rng);
    }
    initialKey = keyContainer;
    reset();
}
EncryptorRC4::EncryptorRC4(const std::vector<uint8_t> &key) {
    algorithm = EncryptionAlgorithm::RC4;
    initialKey = new std::vector<uint8_t>(key);
    reset();
}

EncryptorRC4::~EncryptorRC4() {
    delete(sBlock);
    delete(initialKey);
}

void EncryptorRC4::initSBlock() {
    if (sBlock == nullptr) {
        sBlock = new std::array<uint8_t, 256>();
    }
    for (size_t i = 0; i < sBlock->size(); i++) {
        sBlock->at(i) = static_cast<uint8_t>(i);
    }
    uint16_t j = 0;
    for (size_t i = 0; i < sBlock->size(); i++) {
        j = (j + sBlock->at(i) + initialKey->at(i % initialKey->size())) % sBlock->size();
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

std::vector<uint8_t> *EncryptorRC4::encrypt(const std::vector<uint8_t> &data) {
    auto cipher = new std::vector<uint8_t>(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        (*cipher)[i] = (data[i] ^ keyItem());
    }
    reset();
    return cipher;
}

std::vector<uint8_t> *EncryptorRC4::decrypt(const std::vector<uint8_t> &cipher) {
    auto result = encrypt(cipher);
    //reset();
    return result;
}

void EncryptorRC4::reset() {
    initSBlock();
    x = y = 0;
}

#ifdef QT_DEBUG
void EncryptorRC4::print() {
    QDebug deb = qDebug();
    deb << "RC4 Key:";
    for (auto a : *sBlock) {
        deb << " " << (int) a;
    }
}
#endif

