#pragma once

#include <vector>
#include <list>
#include <cstdint>
#include <string>
#include <algorithm>

class AbstractEncryptor {

public:
    virtual ~AbstractEncryptor() = 0;

    virtual std::vector<uint8_t> *encrypt(const std::vector<uint8_t> &data) = 0;
    virtual std::vector<uint8_t> *decrypt(const std::vector<uint8_t> &cipher) = 0;

    #ifdef DEBUG
        virtual void print() = 0;
    #endif
};

enum EncryptionAlgorithm {
    RC4, RSA, GOST
};

enum OperationMode {
    ENCRYPT, DECRYPT
};

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

EncryptionAlgorithm algorithmValueOf(std::string str);

OperationMode modeValueOf(std::string str);

void processFiles(AbstractEncryptor &encryptor, bool mode, const std::list<std::string> &files);

AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm);
AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm, OperationMode mode,
                                     const std::vector<uint8_t> &keyContainer);
