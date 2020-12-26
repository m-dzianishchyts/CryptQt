#include "gost.h"
#include "mathutils.h"

#include <random>

EncryptorGOST28147_89::EncryptorGOST28147_89() {
    algorithm = EncryptionAlgorithm::GOST28147_89;
    std::mt19937_64 rng(currentTime());
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    std::vector<uint32_t> gostKey;
    for (size_t i = 0; i < 8; i++) {
        gostKey.push_back(dist(rng));
        key[i] = gostKey.back();
    }
}

EncryptorGOST28147_89::EncryptorGOST28147_89(uint32_t key[8]) {
    algorithm = EncryptionAlgorithm::GOST28147_89;
    for (size_t i = 0; i < 8; i++) {
        EncryptorGOST28147_89::key[i] = key[i];
    }
}

EncryptorGOST28147_89::~EncryptorGOST28147_89() {}

uint32_t EncryptorGOST28147_89::basicOperation(uint64_t n, uint32_t keyPart) {
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

uint32_t EncryptorGOST28147_89::basicEncrypt(uint32_t n) {
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

uint32_t EncryptorGOST28147_89::basicDecrypt(uint32_t n) {
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

uint32_t EncryptorGOST28147_89::basicMesAuthcode(uint32_t n) {
    for (size_t i = 0; i < 2; i++) {
        for (size_t j = 0; j < 8; j++) {
            n = basicOperation(n, key[j]);
        }
    }
    return n;
}

std::vector<uint8_t> *EncryptorGOST28147_89::encrypt(const std::vector<uint8_t> &data) {
    if (data.empty()) {
        return new std::vector<uint8_t>();
    }

    auto dataCopy = new std::vector<uint8_t>(data.begin(), data.end());

    // push message end flag
    dataCopy->push_back(UINT8_MAX);

    auto data32 = resize<uint8_t, uint32_t>(*dataCopy);
    delete(dataCopy);

    auto result32 = new std::vector<uint32_t>(data32->size());
    uint32_t s = mesAuthCode(*data32);
    uint32_t seed = s;
    for (size_t i = 0; i < data32->size(); i++) {
        (*result32)[i] = (*data32)[i] ^ basicEncrypt(s);
        s = (*result32)[i];
    }
    delete(data32);

    result32->push_back(seed);

    auto result = resize<uint32_t, uint8_t>(*result32);
    delete(result32);

    return result;
}

std::vector<uint8_t> *EncryptorGOST28147_89::decrypt(const std::vector<uint8_t> &cipher) {
    if (cipher.empty()) {
        return new std::vector<uint8_t>();
    }

    auto cipher32 = resize<uint8_t, uint32_t>(cipher);
    uint32_t s = cipher32->back();
    cipher32->pop_back();

    auto result32 = new std::vector<uint32_t>(cipher32->size());
    for (size_t i = 0; i < cipher32->size(); i++) {
        (*result32)[i] = (*cipher32)[i] ^ basicEncrypt(s);
        s = (*cipher32)[i];
    }
    delete(cipher32);

    auto result = resize<uint32_t, uint8_t>(*result32);
    delete(result32);

    // cut trailing zeros if decrypting
    uint8_t lastPoped = 0;
    do {
        lastPoped = result->back();
        result->pop_back();
    } while (lastPoped == 0);

    return result;
}

uint32_t EncryptorGOST28147_89::mesAuthCode(const std::vector<uint32_t> &data) {
    uint32_t s = 0;
    for (uint32_t piece : data) {
        s = basicMesAuthcode(s ^ piece);
    }
    return s;
}

#ifdef QT_DEBUG
void EncryptorGOST28147_89::print() {
    QDebug deb = qDebug();
    deb << "GOST28147_89. Key:";
    for (auto a : key) {
        deb << QString::number(a, 16);
    }
}
#endif

