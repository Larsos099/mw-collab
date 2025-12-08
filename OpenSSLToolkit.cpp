//
// Created by Lars on 07.12.2025.
//

#include "OpenSSLToolkit.hpp"

#include <cstring>

std::string OpenSSLToolkit::openssl_error(const char *func, const char *file, int line) {
  const unsigned long e = ERR_get_error();
  std::string err;

  if (e) {
    err.resize(ERROR_BUFFER_LEN);
    ERR_error_string_n(e, err.data(), err.size());
    err.resize(std::strlen(err.data()));
  } else {
    err = "No OpenSSL error";
  }
  ERR_clear_error();
  return std::format("[C++ Unexpected]\nOpenSSL Error: {}\nFunction: {}\nFile: {}\nLine: {}", err, func, file, line);
}

OpenSSLToolkit::cipher_ctx_ptr OpenSSLToolkit::make_cipher_ctx_ptr(EVP_CIPHER_CTX *ptr) {
  return {
    ptr,
    &EVP_CIPHER_CTX_free
  };
}

OpenSSLToolkit::md_ctx_ptr OpenSSLToolkit::make_md_ctx_ptr(EVP_MD_CTX *ptr) {
  return {
    ptr,
    &EVP_MD_CTX_free
  };
}

unsigned char* OpenSSLToolkit::takeBytesErase(unsigned char* data, const int start, const int count) {
  if (!data || start < 0 || count <= 0) return nullptr;

  unsigned char* d = static_cast<unsigned char *>(std::malloc(count));
  if (!d) return nullptr;

  std::memcpy(d, data + start, count);
  OPENSSL_cleanse(data + start, count);

  return d;
}

unsigned char* OpenSSLToolkit::takeBytes(const unsigned char *data, const int start, const int count) {
  if (!data || start < 0 || count <= 0) return nullptr;

  unsigned char* d = static_cast<unsigned char *>(std::malloc(count));
  if (!d) return nullptr;

  std::memcpy(d, data + start, count);

  return d;
}


const EVP_MD *OpenSSLToolkit::getHashTypeFromEnum(const HashType type) {
  switch (type) {
    case MD5:
      return EVP_md5();
      break;
    case SHA_256:
      return EVP_sha256();
      break;
    case SHA_512:
      return EVP_sha512();
      break;
    case SHA3_256:
      return EVP_sha3_256();
      break;
    case SHA3_512:
      return EVP_sha3_512();
      break;
    default:
      return EVP_sha3_256();

  }
}

const EVP_CIPHER * OpenSSLToolkit::getEncryptBitsFromEnum(const EncryptBits bits) {
  switch (bits) {
    default:
      return EVP_aes_128_cbc();
      break;
    case B128:
      return EVP_aes_128_cbc();
      break;
    case B256:
      return EVP_aes_256_cbc();
      break;
  }
}

std::expected<unsigned char *, std::string> OpenSSLToolkit::genBytes(const int count) {
  unsigned char* bytes = malloc(sizeof(unsigned char) * count);
  if (RAND_bytes(bytes, count) != 1) {
    return std::unexpected(oerr);
  }
  return bytes;
}

std::vector<std::byte> OpenSSLToolkit::toByteVec(const unsigned char *data, const int size) {
  return std::vector<std::byte>(
  reinterpret_cast<const std::byte*>(data),
  reinterpret_cast<const std::byte*>(data + size)
  );
}

std::expected<OpenSSLToolkit::byteVec, std::string> OpenSSLToolkit::Hash(const byteVec &data, const HashType type) {
  const md_ctx_ptr ctx = make_md_ctx_ptr(EVP_MD_CTX_new());
  const auto md = getHashTypeFromEnum(type);
  byteVec out(EVP_MD_size(md));
  if (EVP_DigestInit(ctx.get(), md) != 1) {
    return std::unexpected(oerr);
  }
  if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) {
    return std::unexpected(oerr);
  }
  if (EVP_DigestFinal_ex(ctx.get(), toOpenSSL(out), nullptr) != 1) {
    return std::unexpected(oerr);
  }
  return out;
}

std::expected<OpenSSLToolkit::byteVec, std::string> OpenSSLToolkit::Encrypt(std::optional<std::reference_wrapper<byteVec>> key,
                                                                            std::optional<std::reference_wrapper<byteVec>> initVec, byteVec &data, const EncryptBits bits) {
  int keySize = EVP_CIPHER_key_length(getEncryptBitsFromEnum(bits));
  if (!key.has_value()) {
    auto _k = genBytes(keySize);
    if (!_k) {
      return std::unexpected(_k.error());
    }
    key->get() = toByteVec(_k.value(), keySize);
  }
  if (!initVec.has_value()) {
    auto _iv = genBytes(IV_LEN);
    if (!_iv) {
      return std::unexpected(_iv.error());
    }
    initVec->get() = toByteVec(_iv.value(), IV_LEN);
  }
  const unsigned char* iv = toOpenSSL(initVec->get());
  const unsigned char* k = toOpenSSL(key->get());
  const unsigned char* in = toOpenSSL(data);
  auto ctx = make_cipher_ctx_ptr(EVP_CIPHER_CTX_new());
  int len1, len2;
  if (EVP_EncryptInit_ex(ctx.get(), getEncryptBitsFromEnum(bits), nullptr, k, iv) != 1) {
    return std::unexpected(oerr);
  }
  unsigned char* out = static_cast<unsigned char *>(malloc(
    sizeof(unsigned char) * data.size() + EVP_CIPHER_block_size(getEncryptBitsFromEnum(bits))));
  if (EVP_EncryptUpdate(ctx.get(), out, &len1, in, data.size()) != 1) {
    return std::unexpected(oerr);
  }
  if (EVP_EncryptFinal_ex(ctx.get(), out + len1, &len2) != 1) {
    return std::unexpected(oerr);
  }
  byteVec ciphertext = toByteVec(out, len1 + len2);
  free(out);
  return ciphertext;
}
