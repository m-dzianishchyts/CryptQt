#include "gost.h"
#include "mathutils.h"

#include <random>

EncryptGOST::EncryptGOST() {
    std::random_device rd;
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    for (size_t i = 0; i < 8; i++) {
        key[i] = dist(rd);
    }
    seed = 0;
}

EncryptGOST::EncryptGOST(uint32_t key[8], uint32_t seed) {
    for (size_t i = 0; i < 8; i++) {
        EncryptGOST::key[i] = key[i];
    }
    EncryptGOST::seed = seed;
}

uint32_t EncryptGOST::basicOperation(uint64_t n, uint32_t keyPart) {
    uint32_t n1 = (uint32_t) n;
    uint32_t n2 = n >> 32;

    uint32_t s = (n1 + keyPart) % UINT32_MAX;

    // replace each byte of 's'
    for (uint8_t i = 0; i < 8; i++) {
        uint8_t sPart = s & 0x0000000F;
        s = s & 0xFFFFFFF0;
        sPart = replacements[i][sPart];
        s |= sPart;
        s = leftShift32(s, 4);
    }

    s = leftShift32(s, 11);
    s = s ^ n2;

    n2 = n1;
    n1 = s;
    return ((uint64_t) n2 << 32) + n1;;
}

uint32_t EncryptGOST::basicEncrypt(uint32_t n) {
    for (size_t i = 0; i < 3; i++) {
        for (size_t j = 0; j < 8; j++) {
            n = basicOperation(n, key[j]);
        }
    }
    for (int i = 7; i >= 0; i--) {
        n = basicOperation(n, key[i]);
    }
    return leftShift32(n, 16);
}

uint32_t EncryptGOST::basicDecrypt(uint32_t n) {
    for (size_t i = 0; i < 8; i++) {
        n = basicOperation(n, key[i]);
    }
    for (size_t i = 0; i < 3; i++) {
        for (int j = 7; j >= 0; j--) {
            n = basicOperation(n, key[j]);
        }
    }
    return leftShift32(n, 16);
}

uint32_t EncryptGOST::basicMesAuthcode(uint32_t n) {
    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < 8; j++) {
            n = basicOperation(n, key[j]);
        }
    }
    return n;
}

template <typename A, typename B>
std::vector<B> *resize(const std::vector<A> &data) {
    size_t inSize = sizeof(A) * 8;
    size_t outSize = sizeof(B) * 8;

    auto *result = new std::vector<B>();
    size_t filledBits = 0;
    B currentBlock = 0;
    for (A value : data) {
        for (size_t i = 0; i < inSize; i++) {
            currentBlock = (currentBlock << 1) + ((value & ((B) 1 << ((B) inSize - 1 - i))) != 0);
            filledBits++;
            if (filledBits == outSize) {
                result->push_back(currentBlock);
                filledBits = 0;
                currentBlock = 0;
            }
        }
    }

    //zero padding if last block is not full
    if (filledBits != 0) {
        result->push_back(currentBlock << (B) (outSize - filledBits));
    }
    return result;
}

std::vector<uint8_t> *EncryptGOST::encrypt(const std::vector<uint8_t> &data) {
    if (data.empty()) {
        return new std::vector<uint8_t>();
    }

    auto *dataCopy = new std::vector<uint8_t>(data.begin(), data.end());

    // push message end flag
    dataCopy->push_back(UINT8_MAX);

    auto *data32 = resize<uint8_t, uint32_t>(*dataCopy);
    delete(dataCopy);

    auto *result32 = new std::vector<uint32_t>(data32->size());
    uint32_t s = seed = mesAuthCode(*data32);
    for (size_t i = 0; i < data32->size(); i++) {
        (*result32)[i] = (*data32)[i] ^ basicEncrypt(s);
        s = (*result32)[i];
    }
    delete(data32);

    auto *result = resize<uint32_t, uint8_t>(*result32);
    delete(result32);

    return result;
}

std::vector<uint8_t> *EncryptGOST::decrypt(const std::vector<uint8_t> &cipher) {
    if (cipher.empty()) {
        return new std::vector<uint8_t>();
    }

    auto *cipher32 = resize<uint8_t, uint32_t>(cipher);

    auto *result32 = new std::vector<uint32_t>(cipher32->size());
    uint32_t s = seed;
    for (size_t i = 0; i < cipher32->size(); i++) {
        (*result32)[i] = (*cipher32)[i] ^ basicEncrypt(s);
        s = (*cipher32)[i];
    }
    delete(cipher32);

    auto *result = resize<uint32_t, uint8_t>(*result32);
    delete(result32);

    // cut trailing zeros if decrypting
    uint8_t lastPoped = 0;
    do {
        lastPoped = result->back();
        result->pop_back();
    } while (lastPoped == 0);

    return result;
}

uint32_t EncryptGOST::mesAuthCode(const std::vector<uint32_t> &data) {
    uint32_t s = 0;
    for (uint32_t piece : data) {
        s = basicMesAuthcode(s ^ piece);
    }
    return s;
}