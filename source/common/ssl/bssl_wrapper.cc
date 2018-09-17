#include "common/ssl/bssl_wrapper.h"

int BIO_mem_contents(const BIO *bio, const uint8_t **out_contents,
                     size_t *out_len) {
  size_t length = BIO_get_mem_data((BIO *)bio, out_contents);
  *out_len = length;
  return 1;
}

void bssl::bio_free(BIO *a){
std::cerr << "!!!!!!!!!!!!!!!!!! bio_free \n";
  BIO_free(a);
}

void bssl::x509_free(X509 *a){
std::cerr << "!!!!!!!!!!!!!!!!!! x509_free \n";
  X509_free(a);
}

void bssl::x509_info_free(X509_INFO *a){
std::cerr << "!!!!!!!!!!!!!!!!!! x509_info_free \n";
  X509_INFO_free(a);
}

void bssl::x509_name_free(X509_NAME *a){
std::cerr << "!!!!!!!!!!!!!!!!!! x509_free \n";
  X509_NAME_free(a);
}

void bssl::ssl_free(SSL *a){
std::cerr << "!!!!!!!!!!!!!!!!!! ssl_free \n";
  SSL_free(a);
}

void bssl::ssl_ctx_free(SSL_CTX *a){
std::cerr << "!!!!!!!!!!!!!!!!!! ssl_ctx_free \n";
  SSL_CTX_free(a);
}

void bssl::general_name_free(GENERAL_NAME *a){
std::cerr << "!!!!!!!!!!!!!!!!!! geenral_name_free \n";
  GENERAL_NAME_free(a);
}

void bssl::evp_pkey_free(EVP_PKEY *a){
std::cerr << "!!!!!!!!!!!!!!!!!! evp_pkey_free \n";
  EVP_PKEY_free(a);
}

void bssl::ec_key_free(EC_KEY *a){
std::cerr << "!!!!!!!!!!!!!!!!!! ec_key_free \n";
  EC_KEY_free(a);
}

void bssl::rsa_free(RSA *a){
std::cerr << "!!!!!!!!!!!!!!!!!! rsa_free \n";
  RSA_free(a);
}

void bssl::bn_free(BIGNUM *a){
std::cerr << "!!!!!!!!!!!!!!!!!! bn_free \n";
//  BN_free(a);
}

void bssl::evp_md_ctx_free(EVP_MD_CTX *a){
std::cerr << "!!!!!!!!!!!!!!!!!! evp_md_ctx_free \n";
  EVP_MD_CTX_free(a);
}

void bssl::ecdsa_sig_free(ECDSA_SIG *a){
std::cerr << "!!!!!!!!!!!!!!!!!! ecdsa_sig_free \n";
  ECDSA_SIG_free(a);
}

