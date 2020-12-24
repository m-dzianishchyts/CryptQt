#include "encryptor.h"
#include "mathutils.h"
#include "rc4.h"
#include "rsa.h"
#include "gost.h"

#include <fstream>
#include <iostream>
#include <random>
#include <QDataStream>
#include <QFile>
#include <QDebug>

// сделать индикацию прогресса шифрования на прогресс барах

AbstractEncryptor::~AbstractEncryptor() {}

void saveKeyRC4(const std::vector<uint8_t> &keyContainer, std::string directory);
void savePublicKeyRSA(uint32_t modulus, uint32_t publicExp, std::string directory);
void savePrivateKeyRSA(uint32_t modulus, uint32_t privateExp, std::string directory);
void saveKeyGOST(const std::vector<uint32_t> gostKey, std::string directory);

AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm, const std::string directory) {
    if (algorithm == EncryptionAlgorithm::RC4) {
        auto keyContainer = new std::vector<uint8_t>(64);
        std::mt19937_64 rng(currentTime());
        std::uniform_int_distribution<uint8_t> dist(0, CHAR_MAX);
        for (size_t i = 0; i < keyContainer->size(); i++) {
            keyContainer->at(i) = dist(rng);
        }

        #ifdef QT_DEBUG
            QDebug deb = qDebug();
            deb << "RC4 init key: ";
            for (auto a : *keyContainer) {
                deb << QString::number(a, 16);
            }
        #endif

        EncryptorRC4 *encryptorRC4 = new EncryptorRC4(*keyContainer);
        encryptorRC4->algorithm = EncryptionAlgorithm::RC4;
        saveKeyRC4(*keyContainer, directory);
        delete(keyContainer);
        return encryptorRC4;
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        EncryptorRSA *encryptorRSA = new EncryptorRSA();
        encryptorRSA->algorithm = EncryptionAlgorithm::RSA;

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
        savePublicKeyRSA(encryptorRSA->modulus, encryptorRSA->publicExp, directory);
        savePrivateKeyRSA(encryptorRSA->modulus, encryptorRSA->privateExp, directory);
        return encryptorRSA;
    }
    EncryptorGOST *encryptorGOST = new EncryptorGOST();
    encryptorGOST->algorithm = EncryptionAlgorithm::GOST;
    std::mt19937_64 rng(currentTime());
    std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
    std::vector<uint32_t> gostKey;
    for (size_t i = 0; i < 8; i++) {
        gostKey.push_back(dist(rng));
        encryptorGOST->key[i] = gostKey.back();
    }
    saveKeyGOST(gostKey, directory);
    encryptorGOST->seed = dist(rng);
    return new EncryptorGOST();
}

AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm, OperationMode mode,
                                     const std::vector<uint8_t> &keyContainer) {
    #ifdef QT_DEBUG
        QDebug deb = qDebug();
        deb << "Some init key: ";
        for (auto a : keyContainer) {
            deb << QString::number(a, 16);
        }
    #endif

    AbstractEncryptor *encryptor;
    if (algorithm == EncryptionAlgorithm::RC4) {
        encryptor = new EncryptorRC4(keyContainer);
        encryptor->algorithm = EncryptionAlgorithm::RC4;
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        EncryptorRSA *encryptorRSA = new EncryptorRSA();
        encryptorRSA->algorithm = EncryptionAlgorithm::RSA;
        for (uint8_t i = 0; i < 4; i++) {
            encryptorRSA->modulus = (encryptorRSA->modulus << 8) + keyContainer[i];
        }
        if (mode == OperationMode::ENCRYPT) {
            for (uint8_t i = 4; i < 8; i++) {
                encryptorRSA->publicExp = (encryptorRSA->publicExp << 8) + keyContainer[i];
            }
        } else {
            for (uint8_t i = 4; i < 8; i++) {
                encryptorRSA->privateExp = (encryptorRSA->privateExp << 8) + keyContainer[i];
            }
        }
        encryptor = encryptorRSA;
    } else {
        auto gostKey = resize<uint8_t, uint32_t>(keyContainer);
        encryptor = new EncryptorGOST(gostKey->data());
        encryptor->algorithm = EncryptionAlgorithm::GOST;
        delete(gostKey);
    }
    return encryptor;
}

void saveKeyRC4(const std::vector<uint8_t> &keyContainer, const std::string directory) {
    std::ofstream ofs(directory + "key.rc4key", std::ios::out | std::ios::binary);
    ofs.write(reinterpret_cast<const char *>(keyContainer.data()), keyContainer.size());
    ofs.close();
}

void savePublicKeyRSA(uint32_t modulus, uint32_t publicExp, std::string directory) {
    std::ofstream ofs(directory + "publicKey.rsakey", std::ios::out | std::ios::binary);
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (modulus >> (i * 8)) & 0xFF);
    }
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (publicExp >> (i * 8)) & 0xFF);
    }
    ofs.close();
}

void savePrivateKeyRSA(uint32_t modulus, uint32_t privateExp, std::string directory) {
    std::ofstream ofs(directory + "privateKey.rsakey", std::ios::out | std::ios::binary);
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (modulus >> (i * 8)) & 0xFF);
    }
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (privateExp >> (i * 8)) & 0xFF);
    }
    ofs.close();
}

void saveKeyGOST(const std::vector<uint32_t> gostKey, std::string directory) {
    std::ofstream ofs(directory + "key.gostkey", std::ios::out | std::ios::binary);
    for (auto value : gostKey) {
        for (int8_t i = 3; i >= 0; i--) {
            ofs.put((char) (value >> (i * 8)) & 0xFF);
        }
    }
    ofs.close();
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

std::string extractFileExtensionFromData(std::vector<uint8_t> &data) {
    std::list<char> fileExtension;

    if (data.back() == 1) {
        data.pop_back();
        do {
            fileExtension.push_front(data.back());
            data.pop_back();
        } while (data.back() != '.');
        fileExtension.push_front(data.back());
        data.pop_back();
    } else {
        data.pop_back();
    }
    std::string fileExtensionStr;
    for (char c : fileExtension) {
        fileExtensionStr.append(1, c);
    }
    return fileExtensionStr;
}

std::string getFileExtensionForAlgorithm(EncryptionAlgorithm algorithm) {
    if (algorithm == EncryptionAlgorithm::RC4) {
        return ".rc4";
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        return ".rsa";
    }
    return ".gost";
}

std::string getFileExtensionFromPath(std::string filePath) {
    int dotPos = filePath.find_last_of('.');
    return dotPos >= 0 ? filePath.substr(dotPos) : "";
}

void processFiles(AbstractEncryptor &encryptor, bool mode, std::vector<std::string> &files,
                  std::list<std::string> &processedFiles) {
    std::string fileExtension;
    if (mode == OperationMode::ENCRYPT) {
        fileExtension = getFileExtensionForAlgorithm(encryptor.algorithm);
    }

    std::ifstream ifs;
    std::ofstream ofs;
    for (size_t i = 1; i < files.size() + 1;) {
        ifs.open(files[i - 1], std::ios::in | std::ios::binary);
        if (!ifs.fail()) {
            std::vector<uint8_t> contents((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            ifs.close();

            #ifdef QT_DEBUG
            qDebug() << "The file was read successfully [Size: " << contents.size() << " B]";
            #endif

            if (mode == OperationMode::ENCRYPT) {
                std::string fileExtension = getFileExtensionFromPath(files[i - 1]);
                for (uint8_t c : fileExtension) {
                    contents.push_back(c);
                }
                if (!fileExtension.empty()) {
                    contents.push_back(1);
                } else {
                    contents.push_back(0);
                }
            }

            std::vector<uint8_t> *processedData;
            if (mode == OperationMode::ENCRYPT) {
                processedData = encryptor.encrypt(contents);
            } else {
                processedData = encryptor.decrypt(contents);
                fileExtension = extractFileExtensionFromData(*processedData);
            }

            int dotPos = files[i - 1].find_last_of('.');
            std::string processedFilePath = files[i - 1].substr(0, dotPos > -1 ? dotPos : files[i - 1].length())
                    .append(fileExtension);
            ofs.open(processedFilePath, std::ios::out | std::ios::binary);
            if (!ofs.fail()) {
                ofs.write(reinterpret_cast<char *>(processedData->data()), processedData->size());
                ofs.close();
                processedFiles.push_back(processedFilePath);
                files.erase(files.begin() + i - 1);
            } else {
                i++;
            }
        } else {
            i++;
        }
    }
}
