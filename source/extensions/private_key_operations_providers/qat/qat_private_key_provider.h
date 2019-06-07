#pragma once

#include "envoy/api/api.h"
#include "envoy/event/dispatcher.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/private_key/private_key_config.h"

#include "source/extensions/private_key_operations_providers/qat/qat.pb.h"

#include "extensions/private_key_operations_providers/qat/qat.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProviders {

class QatPrivateKeyConnection {
public:
  QatPrivateKeyConnection(Ssl::PrivateKeyConnectionCallbacks& cb, Event::Dispatcher& dispatcher,
                          QatHandle& handle, bssl::UniquePtr<EVP_PKEY> pkey);

  void registerCallback(QatContext* ctx);
  void unregisterCallback();
  QatHandle& getHandle() { return handle_; };
  EVP_PKEY* getPrivateKey() { return pkey_.get(); };

private:
  Ssl::PrivateKeyConnectionCallbacks& cb_;
  Event::Dispatcher& dispatcher_;
  Event::FileEventPtr ssl_async_event_{};
  QatHandle& handle_;
  bssl::UniquePtr<EVP_PKEY> pkey_;
};

class QatPrivateKeyMethodProvider : public virtual Ssl::PrivateKeyMethodProvider {
public:
  QatPrivateKeyMethodProvider(
      const qat::QatPrivateKeyMethodConfig& config,
      Server::Configuration::TransportSocketFactoryContext& private_key_provider_context);
  // Ssl::PrivateKeyMethodProvider
  void registerPrivateKeyMethod(SSL* ssl, Ssl::PrivateKeyConnectionCallbacks& cb,
                                Event::Dispatcher& dispatcher) override;
  void unregisterPrivateKeyMethod(SSL* ssl) override;
  bool checkFips() override;
  Ssl::BoringSslPrivateKeyMethodSharedPtr getBoringSslPrivateKeyMethod() override;

private:
  Ssl::BoringSslPrivateKeyMethodSharedPtr method_{};
  std::shared_ptr<QatManager> manager_;
  std::shared_ptr<QatSection> section_;
  std::string section_name_;
  uint32_t poll_delay_;
  bool initialized_{};
  Api::Api& api_;
  bssl::UniquePtr<EVP_PKEY> pkey_;
};

} // namespace PrivateKeyMethodProviders
} // namespace Extensions
} // namespace Envoy
