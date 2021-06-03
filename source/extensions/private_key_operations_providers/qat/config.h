#pragma once

#include "envoy/api/v2/auth/cert.pb.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/ssl/private_key/private_key_config.h"

#include "extensions/private_key_operations_providers/qat/qat_private_key_provider.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProviders {

class QatPrivateKeyMethodFactory : public Ssl::PrivateKeyMethodProviderInstanceFactory {
  // Ssl::PrivateKeyMethodProviderInstanceFactory
  Ssl::PrivateKeyMethodProviderSharedPtr createPrivateKeyMethodProviderInstance(
      const envoy::api::v2::auth::PrivateKeyProvider& message,
      Server::Configuration::TransportSocketFactoryContext& private_key_provider_context);

  std::string name() const { return "qat"; };
};
} // namespace PrivateKeyMethodProviders
} // namespace Extensions
} // namespace Envoy
