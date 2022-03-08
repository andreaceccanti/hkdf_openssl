#include <iostream>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <boost/algorithm/hex.hpp>

void error_and_exit(const std::string& msg){
  std::cerr << msg << '\n';
  exit(1);
}


// Inspired by:
// https://wiki.openssl.org/index.php/EVP_Key_Derivation
//
const int DERIVED_KEY_SIZE_BYTES = 32;
const std::string KEY_STRING_HEX = std::string("7ac67a4e3a47609f1d9fd0b04b76b156042824f53f8ea1cce5a60acedc7c0b5d");
const std::string SALT = "351439db-5416-4641-9608-0836e4e5ba47";

int main(int argc, char** argv){

  if (argc < 2) {
    error_and_exit("Please provide a string param!");
  }

  char keyBytes[DERIVED_KEY_SIZE_BYTES] = {0};
  std::string hash = boost::algorithm::unhex(KEY_STRING_HEX);
  std::copy(hash.begin(), hash.end(), keyBytes);

  EVP_KDF *kdf;

  /* Find and allocate a context for the HKDF algorithm */
  if ((kdf = EVP_KDF_fetch(NULL, "hkdf", NULL)) == NULL) {
    error_and_exit("EVP_KDF_fetch");
  }

  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);

  if (kctx == NULL){
    error_and_exit("EVP_KDP_CTX_new");
  }

  /* Build up the parameters for the derivation */
  OSSL_PARAM params[5];

  params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)"sha256", 7);
  params[1] = OSSL_PARAM_construct_octet_string("salt", (char*) SALT.data(), SALT.length());
  params[2] = OSSL_PARAM_construct_octet_string("key", (void*) keyBytes, DERIVED_KEY_SIZE_BYTES);
  params[3] = OSSL_PARAM_construct_octet_string("info", argv[1], strlen(argv[1]));
  params[4] = OSSL_PARAM_construct_end();

  if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
    error_and_exit("EVP_KDF_CTX_set_params");
  }

  unsigned char derived[DERIVED_KEY_SIZE_BYTES];

  if (EVP_KDF_derive(kctx, derived, sizeof(derived),params) <= 0) {
      error_and_exit("EVP_KDF_derive");
  }

  EVP_KDF_CTX_free(kctx);

  std::string derivedKeyStr(derived,derived+DERIVED_KEY_SIZE_BYTES);

  std::string hexEncodedKey = boost::algorithm::hex(derivedKeyStr);

  std::transform(hexEncodedKey.begin(), hexEncodedKey.end(), hexEncodedKey.begin(),
      [](unsigned char c){ return std::tolower(c);});

  std::cout << hexEncodedKey << '\n';
  
}
