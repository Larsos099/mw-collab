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
  if (EVP_DigestFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(out.data()), nullptr) != 1) {
    return std::unexpected(oerr);
  }
  return out;
}


