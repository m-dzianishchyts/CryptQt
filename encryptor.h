#pragma once

#include <vector>
#include <list>
#include <cstdint>
#include <string>
#include <algorithm>

enum EncryptionAlgorithm {
    RC4, RSA, GOST
};

enum OperationMode {
    ENCRYPT, DECRYPT
};

EncryptionAlgorithm algorithmValueOf(std::string str);

OperationMode modeValueOf(std::string str);

void processFiles(EncryptionAlgorithm algorithm, std::string key, bool mode, std::list<std::string> files);
