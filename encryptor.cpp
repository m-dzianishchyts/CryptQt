#include "encryptor.h"

#include <fstream>

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

void processFiles(std::string algorithm, std::string key, bool mode, std::list<std::string> files) {
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
