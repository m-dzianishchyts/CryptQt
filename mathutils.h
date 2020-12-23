#pragma once

#include <cstdint>

uint64_t currentTime();

int16_t generatePrime();
bool isProvenPrime(uint64_t num);
bool isProbablePrime(uint64_t num, uint16_t rounds);
bool millerTest(uint64_t d, uint64_t n);

uint64_t modPow(uint64_t base, uint64_t exp, uint64_t modulus);
uint64_t gcd(uint64_t a, uint64_t b);
int64_t gcdExpanded(int64_t a, int64_t b, int64_t &x, int64_t &y);
int64_t modInverse(int64_t a, int64_t m);

uint8_t leftShift8(uint8_t n, size_t k);
uint8_t rightShift8(uint8_t n, size_t k);
uint16_t leftShift16(uint16_t n, size_t k);
uint16_t rightShift16(uint16_t n, size_t k);
uint32_t leftShift32(uint32_t n, size_t k);
uint32_t rightShift32(uint32_t n, size_t k);
uint64_t leftShift64(uint64_t n, size_t k);
uint64_t rightShift64(uint64_t n, size_t k);
