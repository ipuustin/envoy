#include "fake_factory.h"

#include <memory>

#include "envoy/extensions/private_key_providers/cryptomb/v3/cryptomb.pb.h"
#include "envoy/extensions/private_key_providers/cryptomb/v3/cryptomb.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "source/common/config/datasource.h"
#include "source/common/config/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/private_key_providers/cryptomb/config.h"
#include "source/extensions/private_key_providers/cryptomb/ipp.h"

#include "openssl/rsa.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {
namespace CryptoMb {

FakeIppCryptoImpl::FakeIppCryptoImpl(bool supported_instruction_set)
    : supported_instruction_set_(supported_instruction_set) {}

FakeIppCryptoImpl::~FakeIppCryptoImpl() {
  BN_free(n_);
  BN_free(e_);
  BN_free(d_);
}

int FakeIppCryptoImpl::mbxIsCryptoMbApplicable(int64u) {
  return supported_instruction_set_ ? 1 : 0;
}

mbx_status FakeIppCryptoImpl::mbxNistp256EcdsaSignSslMb8(int8u* pa_sign_r[8], int8u* pa_sign_s[8],
                                                         const int8u* const pa_msg[8],
                                                         const BIGNUM* const pa_eph_skey[8],
                                                         const BIGNUM* const pa_reg_skey[8],
                                                         int8u* p_buffer) {

  mbx_status status = 0;

  for (int i = 0; i < 8; i++) {
    EC_KEY* key;
    ECDSA_SIG* sig;

    if (pa_eph_skey[i] == nullptr) {
      break;
    }

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_private_key(key, pa_reg_skey[i]);

    // Length of the message representative is equal to length of r (order of EC subgroup).
    sig = ECDSA_do_sign(pa_msg[i], 32, key);

    BN_bn2bin(sig->r, pa_sign_r[i]);
    BN_bn2bin(sig->s, pa_sign_s[i]);

    ECDSA_SIG_free(sig);
    EC_KEY_free(key);

    MBX_SET_STS(status, i, MBX_STATUS_OK);
  }

  UNREFERENCED_PARAMETER(pa_eph_skey);
  UNREFERENCED_PARAMETER(p_buffer);

  return status;
}

mbx_status FakeIppCryptoImpl::mbxRsaPrivateCrtSslMb8(
    const int8u* const from_pa[8], int8u* const to_pa[8], const BIGNUM* const p_pa[8],
    const BIGNUM* const q_pa[8], const BIGNUM* const dp_pa[8], const BIGNUM* const dq_pa[8],
    const BIGNUM* const iq_pa[8], int expected_rsa_bitsize) {

  mbx_status status = 0;

  for (int i = 0; i < 8; i++) {
    RSA* rsa;
    size_t out_len = 0;
    int ret;

    if (from_pa[i] == nullptr) {
      break;
    }

    rsa = RSA_new();

    RSA_set0_factors(rsa, BN_dup(p_pa[i]), BN_dup(q_pa[i]));
    RSA_set0_crt_params(rsa, BN_dup(dp_pa[i]), BN_dup(dq_pa[i]), BN_dup(iq_pa[i]));

    // The real mbx_rsa_private_crt_ssl_mb8 doesn't require these parameters to
    // be set, but BoringSSL does. That's why they are provided out-of-band in
    // the factory initialization.
    RSA_set0_key(rsa, BN_dup(n_), BN_dup(e_), BN_dup(d_));

    // From the docs: "Memory buffers of the plain- and ciphertext must be ceil(rsaBitlen/8) bytes
    // length."
    ret = RSA_sign_raw(rsa, &out_len, to_pa[i], expected_rsa_bitsize / 8, from_pa[i],
                       expected_rsa_bitsize / 8, RSA_NO_PADDING);

    RSA_free(rsa);

    MBX_SET_STS(status, i, ret ? MBX_STATUS_OK : MBX_STATUS_NULL_PARAM_ERR);
  }

  UNREFERENCED_PARAMETER(expected_rsa_bitsize);

  return status;
}

mbx_status FakeIppCryptoImpl::mbxRsaPublicSslMb8(const int8u* const from_pa[8],
                                                 int8u* const to_pa[8], const BIGNUM* const e_pa[8],
                                                 const BIGNUM* const n_pa[8],
                                                 int expected_rsa_bitsize) {
  mbx_status status = 0;

  for (int i = 0; i < 8; i++) {
    RSA* rsa;
    size_t out_len = 0;
    int ret;

    if (e_pa[i] == nullptr) {
      break;
    }

    rsa = RSA_new();

    RSA_set0_key(rsa, BN_dup(n_pa[i]), BN_dup(e_pa[i]), BN_dup(d_));

    ret = RSA_verify_raw(rsa, &out_len, to_pa[i], expected_rsa_bitsize / 8, from_pa[i],
                         expected_rsa_bitsize / 8, RSA_NO_PADDING);

    RSA_free(rsa);

    MBX_SET_STS(status, i, ret ? MBX_STATUS_OK : MBX_STATUS_NULL_PARAM_ERR);
  }

  UNREFERENCED_PARAMETER(expected_rsa_bitsize);

  return status;
}

FakeCryptoMbPrivateKeyMethodFactory::FakeCryptoMbPrivateKeyMethodFactory(
    bool supported_instruction_set)
    : supported_instruction_set_(supported_instruction_set) {}

Ssl::PrivateKeyMethodProviderSharedPtr
FakeCryptoMbPrivateKeyMethodFactory::createPrivateKeyMethodProviderInstance(
    const envoy::extensions::transport_sockets::tls::v3::PrivateKeyProvider& proto_config,
    Server::Configuration::TransportSocketFactoryContext& private_key_provider_context) {
  ProtobufTypes::MessagePtr message = std::make_unique<
      envoy::extensions::private_key_providers::cryptomb::v3::CryptoMbPrivateKeyMethodConfig>();

  Config::Utility::translateOpaqueConfig(proto_config.typed_config(), ProtobufWkt::Struct(),
                                         ProtobufMessage::getNullValidationVisitor(), *message);
  const envoy::extensions::private_key_providers::cryptomb::v3::CryptoMbPrivateKeyMethodConfig
      conf = MessageUtil::downcastAndValidate<const envoy::extensions::private_key_providers::
                                                  cryptomb::v3::CryptoMbPrivateKeyMethodConfig&>(
          *message, private_key_provider_context.messageValidationVisitor());

  std::shared_ptr<FakeIppCryptoImpl> fakeIpp =
      std::make_shared<FakeIppCryptoImpl>(supported_instruction_set_);

  // We need to get more RSA key params in order to be able to use BoringSSL signing functions.
  std::string private_key =
      Config::DataSource::read(conf.private_key(), false, private_key_provider_context.api());

  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(const_cast<char*>(private_key.data()), private_key.size()));

  bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (pkey != nullptr && EVP_PKEY_id(pkey.get()) == EVP_PKEY_RSA) {
    const BIGNUM *e, *n, *d;
    RSA* rsa = EVP_PKEY_get0_RSA(pkey.get());
    RSA_get0_key(rsa, &n, &e, &d);
    fakeIpp->setRsaKey(n, e, d);
  }

  IppCryptoSharedPtr ipp = std::dynamic_pointer_cast<IppCrypto>(fakeIpp);

  return std::make_shared<CryptoMbPrivateKeyMethodProvider>(conf, private_key_provider_context,
                                                            ipp);
}

} // namespace CryptoMb
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
