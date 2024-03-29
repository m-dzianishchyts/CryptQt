#include "encryptor.h"
#include "mathutils.h"
#include "rc4.h"
#include "rsa.h"
#include "gost.h"

#include <fstream>
#include <iostream>
#include <random>
#include <QThread>

AbstractEncryptor::~AbstractEncryptor() {}

std::string saveKeyRC4(const std::vector<uint8_t> &keyContainer, std::string directory);
std::string savePublicKeyRSA(uint32_t modulus, uint32_t publicExp, std::string directory);
std::string savePrivateKeyRSA(uint32_t modulus, uint32_t privateExp, std::string directory);
std::string saveKeyGOST28147_89(const std::vector<uint32_t> gostKey, std::string directory);

AbstractEncryptor *generateEncryptor(EncryptionAlgorithm algorithm, const std::string directory,
                                     std::list<std::string> &generatedKeyPaths) {
    if (algorithm == EncryptionAlgorithm::RC4) {
        EncryptorRC4 *encryptorRC4 = new EncryptorRC4();
        generatedKeyPaths.push_back(saveKeyRC4(*encryptorRC4->initialKey, directory));

        #ifdef QT_DEBUG
            QDebug deb = qDebug();
            deb << "RC4 init key: ";
            for (auto a : *encryptorRC4->initialKey) {
                deb << QString::number(a, 16);
            }
        #endif

        return encryptorRC4;
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        EncryptorRSA *encryptorRSA = new EncryptorRSA();
        generatedKeyPaths.push_back(savePublicKeyRSA(encryptorRSA->modulus, encryptorRSA->publicExp, directory));
        generatedKeyPaths.push_back(savePrivateKeyRSA(encryptorRSA->modulus, encryptorRSA->privateExp, directory));
        return encryptorRSA;
    }
    EncryptorGOST28147_89 *encryptorGOST28147_89 = new EncryptorGOST28147_89();
    generatedKeyPaths.push_back(saveKeyGOST28147_89(std::vector<uint32_t>(encryptorGOST28147_89->key.begin(),
                                                                encryptorGOST28147_89->key.end()), directory));
    return encryptorGOST28147_89;
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
    } else if (algorithm == EncryptionAlgorithm::RSA) {
        encryptor = new EncryptorRSA(mode, keyContainer);
    } else {
        auto gostKey = resize<uint8_t, uint32_t>(keyContainer);
        encryptor = new EncryptorGOST28147_89(gostKey->data());
        delete(gostKey);
    }
    return encryptor;
}

std::string saveKeyRC4(const std::vector<uint8_t> &keyContainer, const std::string directory) {
    std::string keyFilePath = directory + "key.rc4key";
    std::ofstream ofs(directory + "key.rc4key", std::ios::out | std::ios::binary);
    ofs.write(reinterpret_cast<const char *>(keyContainer.data()), keyContainer.size());
    ofs.close();
    return keyFilePath;
}

std::string savePublicKeyRSA(uint32_t modulus, uint32_t publicExp, std::string directory) {
    std::string publicKeyFilePath = directory + "publicKey.rsakey";
    std::ofstream ofs(publicKeyFilePath, std::ios::out | std::ios::binary);
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (modulus >> (i * 8)) & 0xFF);
    }
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (publicExp >> (i * 8)) & 0xFF);
    }
    ofs.close();
    return publicKeyFilePath;
}

std::string savePrivateKeyRSA(uint32_t modulus, uint32_t privateExp, std::string directory) {
    std::string privateKeyFilePath = directory + "privateKey.rsakey";
    std::ofstream ofs(privateKeyFilePath, std::ios::out | std::ios::binary);
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (modulus >> (i * 8)) & 0xFF);
    }
    for (int8_t i = 3; i >= 0; i--) {
        ofs.put((char) (privateExp >> (i * 8)) & 0xFF);
    }
    ofs.close();
    return privateKeyFilePath;
}

std::string saveKeyGOST28147_89(const std::vector<uint32_t> gostKey, std::string directory) {
    std::string keyFilePath = directory + "key.gostkey";
    std::ofstream ofs(keyFilePath, std::ios::out | std::ios::binary);
    for (auto value : gostKey) {
        for (int8_t i = 3; i >= 0; i--) {
            ofs.put((char) (value >> (i * 8)) & 0xFF);
        }
    }
    ofs.close();
    return keyFilePath;
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
    return EncryptionAlgorithm::GOST28147_89;
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

std::string getFileExtensionFromPath(const std::string &filePath) {
    int dotPos = filePath.find_last_of('.');
    return dotPos >= 0 ? filePath.substr(dotPos) : "";
}

void processFiles(AbstractEncryptor &encryptor, bool mode, bool &cancelState, std::vector<std::string> &files,
                  std::list<std::string> &processedFiles, QLabel &progressLabel) {
    uint64_t fileCounter = 0;
    progressLabel.setText(QString::asprintf("Working on... [%llu / %-llu]", fileCounter, files.size() + processedFiles.size()));
    std::string resultfileExtension;
    if (mode == OperationMode::ENCRYPT) {
        resultfileExtension = getFileExtensionForAlgorithm(encryptor.algorithm);
    }

    std::ifstream ifs;
    std::ofstream ofs;
    for (size_t i = 1; i < files.size() + 1 && !cancelState;) {
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
                resultfileExtension = extractFileExtensionFromData(*processedData);
            }

            std::string processedFilePath = files[i - 1].append(resultfileExtension);
            ofs.open(processedFilePath, std::ios::out | std::ios::binary);
            if (!ofs.fail()) {
                ofs.write(reinterpret_cast<char *>(processedData->data()), processedData->size());
                ofs.close();
                delete(processedData);
                processedFiles.push_back(processedFilePath);
                files.erase(files.begin() + i - 1);
            } else {
                i++;
            }
        } else {
            i++;
        }

        if (!cancelState) {
            progressLabel.setText(QString::asprintf("Working on... [%llu / %-llu]", ++fileCounter,
                                                    files.size() + processedFiles.size()));
        }
    }
}
