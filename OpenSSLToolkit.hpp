//
// Created by Lars on 07.12.2025.
//

#ifndef OPENSSLTOOLKIT_HPP
#define OPENSSLTOOLKIT_HPP
#include <openssl/evp.h>
#include <openssl/err.h>
#include <memory>
#include <format>
#include <expected>
#include <vector>
#include <concepts>
#include <cstring>
#include <optional>
#ifndef oerr
#ifdef _MSC_VER
#define oerr openssl_error(__FUNCSIG__, __FILE__, __LINE__)
#else
#define oerr openssl_error(__PRETTY_FUNCTION__, __FILE__, __LINE__)
#endif
#endif
constexpr int ERROR_BUFFER_LEN = 512;

namespace {
  template<typename V>
  concept Vector = requires(V v) {
    typename V::value_type;
    { v.size() } -> std::convertible_to<std::size_t>;
    { v.data() } -> std::same_as<typename V::value_type*>;
};
}
class OpenSSLToolkit final {
  using byteVec = std::vector<std::byte>;
public:
  enum HashType {
    MD5,
    SHA3_256,
    SHA3_512,
    SHA_256,
    SHA_512
  };
  enum EncryptBits {
    B128,
    B256
  };
private:
  static std::string openssl_error(const char* func, const char* file, int line);
  using cipher_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
  using md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

  static cipher_ctx_ptr make_cipher_ctx_ptr(EVP_CIPHER_CTX* ptr);
  static md_ctx_ptr make_md_ctx_ptr (EVP_MD_CTX* ptr);
  template<Vector V>
  [[nodiscard]] static std::vector<std::byte> convertToByteVec( const V& vec ) {
    using T = typename V::value_type;
    std::vector<std::byte> bytes(vec.size() * sizeof(T));
    std::memcpy(bytes.data(), vec.data(), bytes.size());
    return bytes;
  }
  template<Vector V>
  [[nodiscard]] static std::pair<unsigned char*, size_t> toOpenSSL(const V& vec) {
    using T = typename V::value_type;
    return { reinterpret_cast<unsigned char*>(const_cast<T*>(vec.data())), vec.size() * sizeof(T) };
  }

  static const EVP_MD* getHashTypeFromEnum(const HashType type);
  static const EVP_CIPHER* getEncryptBitsFromEnum(const EncryptBits bits);
  OpenSSLToolkit() = delete;
  ~OpenSSLToolkit() = delete;
public:
  static std::expected<byteVec, std::string> Hash(const byteVec &data, const HashType type);
  static std::expected<byteVec, std::string> Encrypt(std::optional<byteVec&> key, std::optional<byteVec&> initVec, byteVec& data);
  // TODO: Implement Encryption (AES-CBC)
};



#endif //OPENSSLTOOLKIT_HPP
