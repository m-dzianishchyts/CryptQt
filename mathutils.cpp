#include "mathutils.h"

#include <random>
#include <chrono>

uint64_t currentTime() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()
                                                                 .time_since_epoch()).count();
}

int16_t generatePrime() {
    uint16_t prime;
    std::mt19937_64 rng(currentTime());
    std::uniform_int_distribution<int16_t> dist(10000, SHRT_MAX);
    do {
        prime = dist(rng);
    } while (!isProbablePrime(prime, 8));
    return prime;
}

bool isProvenPrime(uint64_t num) {
    if (num == 1) {
        return false;
    }
    if (num == 2) {
        return true;
    }
    if (num % 2 == 0) {
        return false;
    }
    for (uint64_t i = 3; i < sqrt(num) + 1; i += 2) {
        if (num % i == 0) {
            return false;
        }
    }
    return true;
}

bool isProbablePrime(uint64_t num, uint16_t rounds) {

    // Corner cases 
    if (num <= 1 || num == 4)  return false;
    if (num <= 3) return true;

    // Find r such that n = 2^d * r + 1 for some r >= 1 
    uint64_t d = num - 1;
    while (d % 2 == 0) {
        d /= 2;
    }

    // Try Miller_Rabin for each round 
    for (uint16_t i = 0; i < rounds; i++)
        if (!millerTest(d, num))
            return false;

    return true;
}

bool millerTest(uint64_t d, uint64_t n) {
    // Pick a random number in [2..n-2] 
    // Corner cases make sure that n > 4
    std::mt19937_64 rng(currentTime());
    std::uniform_int_distribution<uint64_t> dist(0, n - 3);
    uint64_t a = dist(rng);

    // Compute a^d % n 
    uint64_t x = modPow(a, d, n);

    if (x == 1 || x == n - 1)
        return true;

    // Keep squaring x while one of the following doesn't 
    // happen 
    // (i)   d does not reach n-1 
    // (ii)  (x^2) % n is not 1 
    // (iii) (x^2) % n is not n-1 
    while (d != n - 1) {
        x = (x * x) % n;
        d *= 2;

        if (x == 1) {
            return false;
        }
        if (x == n - 1) {
            return true;
        }
    }

    // Return composite 
    return false;
}

uint64_t modPow(uint64_t base, uint64_t exp, uint64_t modulus) {
    base %= modulus;
    uint64_t result = 1;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % modulus;
        base = (base * base) % modulus;
        exp >>= 1;
    }
    return result;
}

// Recursive function to return gcd of a and b
uint64_t gcd(uint64_t a, uint64_t b) {
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

int64_t gcdExpanded(int64_t a, int64_t b, int64_t &x, int64_t &y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    int64_t x1, y1;
    int64_t d = gcdExpanded(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return d;
}

int64_t modInverse(int64_t a, int64_t m) {
    int64_t x, y;
    gcdExpanded(a, m, x, y);
    x = (x % m + m) % m;
    return x;
}

uint8_t leftShift8(uint8_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = n & (1 << 7);
        n <<= 1;
        n |= bit;
    }
    return n;
}

uint8_t rightShift8(uint8_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = n & 1;
        n >>= 1;
        n |= bit << 7;
    }
    return n;
}

uint16_t leftShift16(uint16_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = (n & (1 << 15)) != 0;
        n <<= 1;
        n |= bit;
    }
    return n;
}

uint16_t rightShift16(uint16_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = n & 1;
        n >>= 1;
        n |= bit << 15;
    }
    return n;
}

uint32_t leftShift32(uint32_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = (n & (1 << 31)) != 0;
        n <<= 1;
        n |= bit;
    }
    return n;
}

uint32_t rightShift32(uint32_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = n & 1;
        n >>= 1;
        n |= bit << 31;
    }
    return n;
}

uint64_t leftShift64(uint64_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = (n & (static_cast<uint64_t>(1) << 63)) != 0;
        n <<= 1;
        n |= bit;
    }
    return n;
}

uint64_t rightShift64(uint64_t n, size_t k) {
    for (size_t i = 0; i < k; i++) {
        uint8_t bit = n & 1;
        n >>= 1;
        n |= static_cast<uint64_t>(bit) << 63;
    }
    return n;
}

uint8_t adjustedSize(uint64_t number) {
    uint64_t pow = 0x8000000000000000; // 2^63
    uint8_t i = 0;
    while (!(pow & number) && pow) {
        i++;
        pow >>= 1;
    }
    return 64 - i;
}
