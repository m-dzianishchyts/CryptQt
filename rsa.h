#pragma once

#include "mathutils.h"

#include <vector>

class EncryptRSA {

public:
    EncryptRSA();

    std::vector<uint8_t> *encrypt(const std::vector<uint8_t> &data);
    std::vector<uint8_t> *decrypt(const std::vector<uint8_t> &cipher);

    int32_t privateExp;
    int32_t publicExp = 0;
    uint32_t modulus;
};
