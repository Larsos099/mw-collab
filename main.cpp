#include <iostream>
#include "OpenSSLToolkit.hpp"
int main() {
  std::cout << "Hello, World!" << std::endl;

  OpenSSLToolkit::Encrypt(std::nullopt, std::nullopt,{} , OpenSSLToolkit::B256);
  return 0;
}