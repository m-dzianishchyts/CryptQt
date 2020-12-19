#include "encryptor.h"
#include "mathutils.h"
#include "rc4.h"
#include "rsa.h"
#include "gost.h"

#include <fstream>
#include <random>

AbstractEncryptor::~AbstractEncryptor() {}

AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm) {
    if (algorithm == EncryptionAlgorithm::RC4) {
        auto keyContainer = new std::vector<uint8_t>(64);
        std::mt19937_64 rng(currentTimeMs());
        std::uniform_int_distribution<uint8_t> dist(0, CHAR_MAX);
        for (size_t i = 0; i < keyContainer->size(); i++) {
            keyContainer->at(i) = dist(rng);
        }
        EncryptorRC4 *encryptorRC4 = new EncryptorRC4(*keyContainer);
        delete(keyContainer);
        return encryptorRC4;
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        EncryptorRSA *encryptorRSA = new EncryptorRSA();

        int16_t p = generatePrime();
        int16_t q = generatePrime();
        encryptorRSA->modulus = p * q;
        int32_t phi = (p - 1) * (q - 1);
        for (int32_t attempt : {17, 257, 65537}) {
            if (gcd(phi, attempt) == 1) {
                encryptorRSA->publicExp = attempt;
                break;
            }
        }
        for (int32_t attempt = 32768; encryptorRSA->publicExp == 0 && attempt > 8; attempt /= 2) {
            if (gcd(phi, (uint64_t) attempt + 1) == 1) {
                encryptorRSA->publicExp = (uint64_t) attempt + 1;
                break;
            }
        }
        encryptorRSA->privateExp = static_cast<uint32_t>(modInverse(encryptorRSA->publicExp, phi));
        return encryptorRSA;
    }
    return new EncryptorGOST();
}

AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm, OperationMode mode,
                                     const std::vector<uint8_t> &keyContainer) {
    if (algorithm == EncryptionAlgorithm::RC4) {
        return new EncryptorRC4(keyContainer);
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        EncryptorRSA *encryptorRSA = new EncryptorRSA();

        for (uint8_t i = 0; i < 4; i++) {
            encryptorRSA->modulus = (encryptorRSA->modulus << 8) + keyContainer.at(i);
        }

        if (mode == OperationMode::ENCRYPT) {
            for (uint8_t i = 5; i < 8; i++) {
                encryptorRSA->publicExp = (encryptorRSA->publicExp << 8) + keyContainer.at(i);
            }
        } else {
            for (uint8_t i = 5; i < 8; i++) {
                encryptorRSA->privateExp = (encryptorRSA->privateExp << 8) + keyContainer.at(i);
            }
        }

        return encryptorRSA;
    }
    auto gostKey = resize<uint8_t, uint32_t>(keyContainer);
    EncryptorGOST *encryptorGOST = new EncryptorGOST(gostKey->data());
    delete(gostKey);
    return encryptorGOST;
}

EncryptionAlgorithm algorithmValueOf(std::string str) {
    for (auto & c: str) {
        c = (char) toupper(c);
    }
    if (str.compare("RC4") == 0) {
        return EncryptionAlgorithm::RC4;
    } else if (str.compare("RSA") == 0) {
        return EncryptionAlgorithm::RSA;
    }
    return EncryptionAlgorithm::GOST;
}

OperationMode modeValueOf(std::string str) {
    for (auto & c: str) {
        c = (char) toupper(c);
    }
    if (str.compare("ENCRYPT") == 0) {
        return OperationMode::ENCRYPT;
    }
    return OperationMode::DECRYPT;
}

void processFiles(AbstractEncryptor &encryptor, bool mode, const std::list<std::string> &files) {
    // init algorithm object

    // generate key if empty

    // foreach file (stop and erase all files if cancelled)

        // open file, read data

        // encrypt/decrypt, have data

        // create file and put data (remember new file)

    // save key into file
}

void saveDataInFile(std::vector<uint8_t> &data, std::string &filePath) {
    std::ofstream outputFileStream(filePath);
    outputFileStream.write(reinterpret_cast<char*>(data.data()), data.size());
    outputFileStream.close();
}
