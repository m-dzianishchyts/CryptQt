#include "rsa.h"

EncryptRSA::EncryptRSA() {
    int16_t p = generatePrime();
    int16_t q = generatePrime();
    modulus = p * q;
    int32_t phi = (p - 1) * (q - 1);
    for (int32_t attempt : {17, 257, 65537}) {
        if (gcd(phi, attempt) == 1) {
            publicExp = attempt;
            break;
        }
    }
    for (int32_t attempt = 32768; publicExp == 0 && attempt > 8; attempt /= 2) {
        if (gcd(phi, (uint64_t) attempt + 1) == 1) {
            publicExp = (uint64_t) attempt + 1;
            break;
        }
    }
    privateExp = static_cast<uint32_t>(modInverse(publicExp, phi));
}

uint8_t computeBlockSize(uint64_t modulus) {
    uint64_t pow = 0x8000000000000000; // 2^63
    uint8_t i = 0;
    while (pow > modulus) {
        i++;
        pow >>= 1;
    }
    return 64 - i;
}

template <typename A>
std::vector<A> *resize(const std::vector<uint64_t> &data, size_t inSize, size_t outSize) {
    auto *result = new std::vector<A>();
    uint8_t filledBits = 0;
    A currentBlock = 0;
    for (uint64_t byte : data) {
        for (size_t i = 0; i < inSize; i++) {
            currentBlock = (currentBlock << 1) + ((byte & ((uint64_t) 1 << ((uint64_t) inSize - 1 - i))) != 0);
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
        result->push_back(currentBlock << (A) (outSize - filledBits));
    }
    return result;
}

std::vector<uint8_t> *processData(const std::vector<uint8_t> &data, uint64_t exp, uint64_t modulus, bool encrypt) {
    auto *data64 = new std::vector<uint64_t>(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        (*data64)[i] = (uint64_t) data[i];
    }

    // push message end flag if encrypting
    if (encrypt) {
        data64->push_back(UINT64_MAX);
    }

    // 'size' - 1 for encrypting and 'size' for decrypting
    auto *resizedData = resize<uint64_t>(*data64, 8, computeBlockSize(modulus) - encrypt);
    delete(data64);

    auto *cryptedData = new std::vector<uint64_t>(resizedData->size());

    // actual processing
    for (size_t i = 0; i < resizedData->size(); i++) {
        (*cryptedData)[i] = modPow((*resizedData)[i], exp, modulus);
    }
    delete(resizedData);

    auto *result = resize<uint8_t>(*cryptedData, computeBlockSize(modulus) - !encrypt, 8);
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

std::vector<uint8_t> *EncryptRSA::encrypt(const std::vector<uint8_t> &data) {
    if (data.empty()) {
        return new std::vector<uint8_t>();
    }
    return processData(data, publicExp, modulus, 1);
}

std::vector<uint8_t> *EncryptRSA::decrypt(const std::vector<uint8_t> &cipher) {
    if (cipher.empty()) {
        return new std::vector<uint8_t>();
    }
    return processData(cipher, privateExp, modulus, 0);
}