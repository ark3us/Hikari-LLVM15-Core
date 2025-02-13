// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "llvm/Transforms/Obfuscation/CryptoUtils.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <chrono>

using namespace llvm;
namespace llvm {
ManagedStatic<CryptoUtils> cryptoutils;
}
CryptoUtils::CryptoUtils() {}

uint32_t
CryptoUtils::scramble32(uint32_t in,
                        std::map<uint32_t /*IDX*/, uint32_t /*VAL*/> &VMap) {
  if (VMap.find(in) == VMap.end()) {
    uint32_t V = get_uint32_t();
    VMap[in] = V;
    return V;
  } else {
    return VMap[in];
  }
}
CryptoUtils::~CryptoUtils() {
  if (eng != nullptr)
    delete eng;
}
void CryptoUtils::prng_seed() {
  using namespace std::chrono;
  std::uint_fast64_t ms =
      duration_cast<microseconds>(system_clock::now().time_since_epoch())
          .count();
  errs() << format("std::mt19937_64 seeded with current timestamp: %" PRIu64 "",
                   ms)
         << "\n";
  eng = new std::mt19937_64(ms);
}
void CryptoUtils::prng_seed(std::uint_fast64_t seed) {
  errs() << format("std::mt19937_64 seeded with: %" PRIu64 "", seed) << "\n";
  eng = new std::mt19937_64(seed);
}
std::uint_fast64_t CryptoUtils::get_raw() {
  if (eng == nullptr)
    prng_seed();
  return (*eng)();
}
uint32_t CryptoUtils::get_range(uint32_t min, uint32_t max) {
  if (max == 0)
    return 0;
  std::uniform_int_distribution<uint32_t> dis(min, max - 1);
  return dis(*eng);
}

std::string CryptoUtils::rand_string(int min_length, int max_length) {
  // Define the character set for the random string
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const size_t max_index = sizeof(charset) - 1;
  int length = get_range(min_length, max_length);

  // Generate the random string
  std::string random_string(length, '\0');
  for (size_t i = 0; i < length; ++i) {
    random_string[i] = charset[get_range(0, max_index)];
  }

  return random_string;
}
