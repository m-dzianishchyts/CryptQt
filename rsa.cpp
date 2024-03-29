#include "rsa.h"

#include <QThread>

EncryptorRSA::EncryptorRSA() {
    algorithm = EncryptionAlgorithm::RSA;
    int16_t p = generatePrime();
    QThread::usleep(1);
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

EncryptorRSA::EncryptorRSA(OperationMode mode, const std::vector<uint8_t> &keyContainer) {
    algorithm = EncryptionAlgorithm::RSA;
    for (uint8_t i = 0; i < 4; i++) {
        modulus = (modulus << 8) + keyContainer[i];
    }
    if (mode == OperationMode::ENCRYPT) {
        for (uint8_t i = 4; i < 8; i++) {
            publicExp = (publicExp << 8) + keyContainer[i];
        }
    } else {
        for (uint8_t i = 4; i < 8; i++) {
            privateExp = (privateExp << 8) + keyContainer[i];
        }
    }
}

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
    qDebug() << "RSA. Modulus: " << QString::number(modulus, 16) << ". PublicExp: " << QString::number(publicExp, 16) <<
                ". PrivateExp: " << QString::number(privateExp, 16) << ".";
}
#endif
