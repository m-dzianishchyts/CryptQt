#pragma once

#include "encryptor.h"
#include "mathutils.h"

#include <vector>
#include <QtDebug>

class EncryptorRSA : public AbstractEncryptor {

public:
    ~EncryptorRSA() override;

    std::vector<uint8_t> *encrypt(const std::vector<uint8_t> &data) override;
    std::vector<uint8_t> *decrypt(const std::vector<uint8_t> &cipher) override;

    #ifdef QT_DEBUG
        void print() override;
    #endif


    int32_t privateExp = 0;
    int32_t publicExp = 0;
    uint32_t modulus = 0;
};
