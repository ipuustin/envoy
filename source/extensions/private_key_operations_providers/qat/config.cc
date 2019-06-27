#include "extensions/private_key_operations_providers/qat/config.h"

#include <memory>

#include "envoy/registry/registry.h"

#include "common/config/utility.h"
#include "common/protobuf/message_validator_impl.h"
#include "common/protobuf/utility.h"

#include "source/extensions/private_key_operations_providers/qat/qat.pb.h"
#include "source/extensions/private_key_operations_providers/qat/qat.pb.validate.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProviders {

Ssl::PrivateKeyMethodProviderSharedPtr
QatPrivateKeyMethodFactory::createPrivateKeyMethodProviderInstance(
    const envoy::api::v2::auth::PrivateKeyProvider& message,
    Server::Configuration::TransportSocketFactoryContext& private_key_provider_context) {
  (void)private_key_provider_context;
  ProtobufTypes::MessagePtr proto_config = std::make_unique<qat::QatPrivateKeyMethodConfig>();

  Config::Utility::translateOpaqueConfig(message.typed_config(), ProtobufWkt::Struct(),
                                         ProtobufMessage::getNullValidationVisitor(),
                                         *proto_config);
  const qat::QatPrivateKeyMethodConfig conf =
      MessageUtil::downcastAndValidate<const qat::QatPrivateKeyMethodConfig&>(*proto_config);

  return std::make_shared<QatPrivateKeyMethodProvider>(conf, private_key_provider_context);
}

REGISTER_FACTORY(QatPrivateKeyMethodFactory, Ssl::PrivateKeyMethodProviderInstanceFactory);

} // namespace PrivateKeyMethodProviders
} // namespace Extensions
} // namespace Envoy
