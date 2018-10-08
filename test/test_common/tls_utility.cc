#include "test/test_common/tls_utility.h"

#include "common/common/assert.h"

#include "openssl/ssl.h"

#include "common/ssl/bssl_wrapper.h"

namespace Envoy {
namespace Tls {
namespace Test {

std::vector<uint8_t> generateClientHello(const std::string& sni_name, const std::string& alpn) {
  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  //SSL_CTX_set_options(ctx.get(), flags);

  bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));

  // Ownership of these is passed to *ssl
  BIO* in = BIO_new(BIO_s_mem());
  BIO* out = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl.get(), in, out);

  SSL_set_connect_state(ssl.get());
  const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
  SSL_set_cipher_list(ssl.get(), PREFERRED_CIPHERS);
  if (!sni_name.empty()) {
    SSL_set_tlsext_host_name(ssl.get(), sni_name.c_str());
  }
  if (!alpn.empty()) {
//unsigned char vector[] = { 
//	2, 'h', '2',
//	8, 'h', 't', 't', 'p', '/', '1', '.', '1' 
//};
unsigned char vector[] = {
     6, 's', 'p', 'd', 'y', '/', '1',
     8, 'h', 't', 't', 'p', '/', '1', '.', '1'
 };
  const unsigned char* dat;
  unsigned int vector_len = sizeof(vector);
  unsigned int len;
int rc;

// rc = SSL_set_alpn_protos(ssl.get(), vector, vector_len);
//std::cerr << "****************** SSL_set_alpn_protos vector rc " << rc << " " << vector_len << " \n";

//SSL_get0_alpn_selected(ssl.get(), &dat, &len);
//std::cerr << "**************** SSL_get0_alpn_selected " << len << " \n";

//rc = SSL_CTX_set_alpn_protos(ctx.get(), vector, vector_len);
//std::cerr << "****************** SSL_CTX_set_alpn_protos vector rc " << rc << " " << vector_len << " \n";

//SSL_get0_alpn_selected(ssl.get(), &dat, &len);
//std::cerr << "**************** SSL_get0_alpn_selected " << len << " \n";

    rc = SSL_set_alpn_protos(ssl.get(), reinterpret_cast<const uint8_t*>(alpn.data()), alpn.size());
std::cerr << "****************** SSL_set_alpn_protos rc " << rc << " " << alpn.size() << " " << alpn << " \n";

SSL_get0_alpn_selected(ssl.get(), &dat, &len);
std::cerr << "**************** SSL_get0_alpn_selected " << len << " \n";

    rc = SSL_CTX_set_alpn_protos(ctx.get(), reinterpret_cast<const uint8_t*>(alpn.data()), alpn.size());
std::cerr << "****************** SSL_CTX_set_alpn_protos rc " << rc << " " << alpn.size() << " " << alpn << " \n";

SSL_get0_alpn_selected(ssl.get(), &dat, &len);
std::cerr << "**************** SSL_get0_alpn_selected " << len << " \n";

rc = SSL_extension_supported(TLSEXT_TYPE_application_layer_protocol_negotiation);
std::cerr << "*************** TLSEXT_TYPE_application_layer_protocol_negotiation " << rc << " \n";

SSL_SESSION *session = SSL_get_session(ssl.get());
std::cerr << "**************** SSL_get_session " << session << " \n"; 
  }

std::cerr << "**************** SSL_do_handshake client " << ssl.get() << " \n";
  SSL_do_handshake(ssl.get());

  const uint8_t* data = NULL;
  long data_len = BIO_get_mem_data(out, &data);

  ASSERT(data_len > 0);
  std::vector<uint8_t> buf(data, data + data_len);
  return buf;
}

} // namespace Test
} // namespace Tls
} // namespace Envoy
