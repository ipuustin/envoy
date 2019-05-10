#pragma once

#include "envoy/event/dispatcher.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/private_key/private_key_config.h"

#include "common/config/utility.h"
#include "common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {

struct RsaPrivateKeyConnectionTestOptions {
  bool sync_mode_{};
  bool decrypt_expected_{};
  bool sign_expected_{};
  bool crypto_error_{};
};

// An example RSA private key method provider here for testing the decrypt() and sign()
// functionality.
class RsaPrivateKeyConnection : public virtual Ssl::PrivateKeyConnection {
public:
  RsaPrivateKeyConnection(SSL* ssl, Ssl::PrivateKeyConnectionCallbacks& cb,
                          Event::Dispatcher& dispatcher, bssl::UniquePtr<EVP_PKEY> pkey,
                          RsaPrivateKeyConnectionTestOptions& test_options);
  EVP_PKEY* getPrivateKey() { return pkey_.get(); };
  void delayed_op();

  // Store the output data temporarily.
  uint8_t* out_;
  size_t out_len_;

  // Is the operation finished?
  bool finished_{};
  RsaPrivateKeyConnectionTestOptions& test_options_;

private:
  Ssl::PrivateKeyConnectionCallbacks& cb_;
  Event::Dispatcher& dispatcher_;
  bssl::UniquePtr<EVP_PKEY> pkey_;
  Event::TimerPtr timer_;
};

class RsaPrivateKeyMethodProvider : public virtual Ssl::PrivateKeyMethodProvider {
public:
  RsaPrivateKeyMethodProvider(
      const ProtobufWkt::Struct& config,
      Server::Configuration::TransportSocketFactoryContext& factory_context);
  // Ssl::PrivateKeyMethodProvider
  Ssl::PrivateKeyConnectionPtr getPrivateKeyConnection(SSL* ssl,
                                                       Ssl::PrivateKeyConnectionCallbacks& cb,
                                                       Event::Dispatcher& dispatcher) override;
  Ssl::BoringSslPrivateKeyMethodSharedPtr getBoringSslPrivateKeyMethod() override;

  static int ssl_rsa_connection_index;

private:
  Ssl::BoringSslPrivateKeyMethodSharedPtr method_{};
  std::string private_key_;
  RsaPrivateKeyConnectionTestOptions test_options_;
};

class RsaPrivateKeyMethodFactory : public Ssl::PrivateKeyMethodProviderInstanceFactory {
public:
  Ssl::PrivateKeyMethodProviderSharedPtr
  createPrivateKeyMethodProviderInstance(const envoy::api::v2::auth::PrivateKeyMethod& message,
                                         Server::Configuration::TransportSocketFactoryContext&
                                             private_key_method_provider_context) override {
    return std::make_shared<RsaPrivateKeyMethodProvider>(message.config(),
                                                         private_key_method_provider_context);
  }

  std::string name() const override { return std::string("rsa_test"); };
};

} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
