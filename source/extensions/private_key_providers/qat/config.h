#pragma once

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/private_key/private_key_config.h"

#include "extensions/private_key_providers/qat/qat_private_key_provider.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {

class QatPrivateKeyMethodFactory : public Ssl::PrivateKeyMethodProviderInstanceFactory {
  // Ssl::PrivateKeyMethodProviderInstanceFactory
  Ssl::PrivateKeyMethodProviderSharedPtr createPrivateKeyMethodProviderInstance(
      const envoy::extensions::transport_sockets::tls::v3::PrivateKeyProvider& message,
      Server::Configuration::TransportSocketFactoryContext& private_key_provider_context);

public:
  std::string name() const { return "qat"; };
};
} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
