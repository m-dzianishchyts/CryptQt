#pragma once

#include <array>
#include <cstdint>
#include <vector>

class EncryptRC4 {

public:
    EncryptRC4(const std::vector<uint8_t> &key);

    std::vector<uint8_t> *encrypt(const std::vector<uint8_t> &data);
    std::vector<uint8_t> *decrypt(const std::vector<uint8_t> &cipher);
    void reset(const std::vector<uint8_t> &key);

private:
    std::array<uint8_t, 256> *sBlock;
    uint16_t x;
    uint16_t y;

    void initSBlock(const std::vector<uint8_t> &key);
    uint8_t keyItem();
    void swap(uint8_t &a, uint8_t &b);
};
