#include "rsa.h"
#include "iostream"

EncryptorRSA::~EncryptorRSA() {}

uint8_t computeBlockSize(uint64_t modulus) {
    uint64_t pow = 0x8000000000000000; // 2^63
    uint8_t i = 0;
    while (pow > modulus) {
        i++;
        pow >>= 1;
    }
    return 64 - i;
}

std::vector<uint8_t> *processData(const std::vector<uint8_t> &data, uint64_t exp, uint64_t modulus, bool encrypt) {
    auto data64 = new std::vector<uint64_t>(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        (*data64)[i] = (uint64_t) data[i];
    }

    // push message end flag if encrypting
    if (encrypt) {
        data64->push_back(UINT64_MAX);
    }

    // 'size' - 1 for encrypting and 'size' for decrypting
    auto resizedData = resize<uint64_t>(*data64, 8, computeBlockSize(modulus) - encrypt);
    delete(data64);

    auto cryptedData = new std::vector<uint64_t>(resizedData->size());

    // actual processing
    for (size_t i = 0; i < resizedData->size(); i++) {
        (*cryptedData)[i] = modPow((*resizedData)[i], exp, modulus);
    }
    delete(resizedData);

    auto result = resize<uint8_t>(*cryptedData, computeBlockSize(modulus) - !encrypt, 8);
    delete(cryptedData);

    // cut trailing zeros if decrypting
    if (!encrypt) {
        uint8_t lastPoped = 0;
        do {
            lastPoped = result->back();
            result->pop_back();
        } while (lastPoped == 0);
    }

    return result;
}

std::vector<uint8_t> *EncryptorRSA::encrypt(const std::vector<uint8_t> &data) {
    if (data.empty()) {
        return new std::vector<uint8_t>();
    }
    return processData(data, publicExp, modulus, 1);
}

std::vector<uint8_t> *EncryptorRSA::decrypt(const std::vector<uint8_t> &cipher) {
    if (cipher.empty()) {
        return new std::vector<uint8_t>();
    }
    return processData(cipher, privateExp, modulus, 0);
}

#ifdef QT_DEBUG
void EncryptorRSA::print() {
    std::cout << "RSA. Modulus: " << modulus << ". PublicExp: " << publicExp
              << ". PrivateExp: " << privateExp << "." << std::endl;
}
#endif
