#include "extensions/private_key_providers/qat/config.h"

#include <memory>

#include "envoy/extensions/private_key_providers/qat/v3/qat.pb.h"
#include "envoy/extensions/private_key_providers/qat/v3/qat.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "common/config/utility.h"
#include "common/protobuf/message_validator_impl.h"
#include "common/protobuf/utility.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {

Ssl::PrivateKeyMethodProviderSharedPtr
QatPrivateKeyMethodFactory::createPrivateKeyMethodProviderInstance(
    const envoy::extensions::transport_sockets::tls::v3::PrivateKeyProvider& message,
    Server::Configuration::TransportSocketFactoryContext& private_key_provider_context) {
  (void)private_key_provider_context;
  ProtobufTypes::MessagePtr proto_config = std::make_unique<
      envoy::extensions::private_key_providers::qat::v3::QatPrivateKeyMethodConfig>();

  Config::Utility::translateOpaqueConfig(message.typed_config(), ProtobufWkt::Struct(),
                                         ProtobufMessage::getNullValidationVisitor(),
                                         *proto_config);
  const envoy::extensions::private_key_providers::qat::v3::QatPrivateKeyMethodConfig
      conf = MessageUtil::downcastAndValidate<
          const envoy::extensions::private_key_providers::qat::v3::
              QatPrivateKeyMethodConfig&>(*proto_config,
                                          private_key_provider_context.messageValidationVisitor());

  return std::make_shared<QatPrivateKeyMethodProvider>(conf, private_key_provider_context);
}

REGISTER_FACTORY(QatPrivateKeyMethodFactory, Ssl::PrivateKeyMethodProviderInstanceFactory);

} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
