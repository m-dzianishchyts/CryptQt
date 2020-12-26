#pragma once

#include <vector>
#include <list>
#include <cstdint>
#include <string>
#include <algorithm>
#include <QtDebug>
#include <QLabel>

enum EncryptionAlgorithm {
    RC4, RSA, GOST28147_89
};

enum OperationMode {
    ENCRYPT, DECRYPT
};

class AbstractEncryptor {

public:
    virtual ~AbstractEncryptor() = 0;

    virtual std::vector<uint8_t> *encrypt(const std::vector<uint8_t> &data) = 0;
    virtual std::vector<uint8_t> *decrypt(const std::vector<uint8_t> &cipher) = 0;

    #ifdef QT_DEBUG
        virtual void print() = 0;
    #endif

    EncryptionAlgorithm algorithm;
};

template <typename A, typename B>
std::vector<B> *resize(const std::vector<A> &data) {
    auto *result = new std::vector<B>();
    uint8_t filledBytes = 0;
    B currentBlock = 0;
    for (A value : data) {
        for (int8_t i = sizeof(A) - 1; i >= 0; i--) {
            currentBlock = (currentBlock << 8) + ((value >> (i * 8)) & 0xFF);
            filledBytes++;
            if (filledBytes == sizeof(B)) {
                result->push_back(currentBlock);
                filledBytes = 0;
                currentBlock = 0;
            }
        }
    }

    //zero padding if last block is not full
    if (filledBytes != 0) {
        result->push_back(currentBlock << (B) ((sizeof(B) - filledBytes) * 8));
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

std::string getFileExtensionForAlgorithm(EncryptionAlgorithm algorithm);

void processFiles(AbstractEncryptor &encryptor, bool mode, bool &cancelState, std::vector<std::string> &files,
                  std::list<std::string> &processedFiles, QLabel &progressLabel);

AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm, const std::string directory,
                                     std::list<std::string> &generatedKeyPaths);
AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm, OperationMode mode,
                                     const std::vector<uint8_t> &keyContainer);
