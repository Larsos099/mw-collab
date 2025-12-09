#include <iostream>
#include "OpenSSLToolkit.hpp"

#include <vector>
#include <string>
#include <cstddef>

std::vector<std::byte> stringToBytes(const std::string& str) {
  return {
      reinterpret_cast<const std::byte*>(str.data()),
      reinterpret_cast<const std::byte*>(str.data() + str.size())
  };
}

std::string bytesToString(const std::vector<std::byte>& bytes) {
  return {
      reinterpret_cast<const char*>(bytes.data()),
      bytes.size()
  };
}

std::string leckEier(const std::vector<std::byte>& data) {
  std::string out;
  out.reserve(data.size() * 2);

  for (std::byte b : data) {
    out += std::format("{:02x}", std::to_integer<unsigned int>(b));
  }

  return out;
}

int main() {
  std::string key = "yallah das eins key";
  std::string data = "yallah das eins data";
  auto uk = stringToBytes(key);
  auto d = stringToBytes(data);
  auto hr = OpenSSLToolkit::Hash(uk, OpenSSLToolkit::SHA3_256);
  if (!hr) {
    std::cerr << hr.error() << std::endl;
    return 1;
  }
  auto k = hr.value();
  auto r = OpenSSLToolkit::Encrypt(k, std::nullopt, d, OpenSSLToolkit::B256);
  if (!r) {
    std::cerr << r.error() << std::endl;
    return 1;
  }
  auto ciphertext = leckEier(r.value());
  std::cout << ciphertext << std::endl;
  auto dr = OpenSSLToolkit::Decrypt(k, r.value(), OpenSSLToolkit::B256);
  if (!dr) {
    std::cerr << dr.error() << std::endl;
    return 1;
  }
  std::cout << bytesToString(dr.value()) << std::endl;
  return 0;
}