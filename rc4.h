#pragma once

#include "encryptor.h"

#include <array>
#include <cstdint>
#include <vector>
#include <QtDebug>

class EncryptorRC4 : public AbstractEncryptor {

public:
    EncryptorRC4();
    EncryptorRC4(const std::vector<uint8_t> &key);
    ~EncryptorRC4() override;

    std::vector<uint8_t> *encrypt(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> *decrypt(const std::vector<uint8_t> &cipher) override;
    void reset();

    #ifdef QT_DEBUG
        void print() override;
    #endif

    const std::vector<uint8_t> *initialKey;


private:
    std::array<uint8_t, 256> *sBlock = nullptr;
    uint16_t x = 0;
    uint16_t y = 0;

    void initSBlock();
    uint8_t keyItem();
    void swap(uint8_t &a, uint8_t &b);
};
