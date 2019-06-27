#include "extensions/private_key_operations_providers/qat/qat_private_key_provider.h"

#include <memory>

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "extensions/private_key_operations_providers/qat/qat.h"

#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace PrivateKeyMethodProvider {

SINGLETON_MANAGER_REGISTRATION(qat_manager);

void QatPrivateKeyConnection::registerCallback(QatContext* ctx) {

  // Get the receiving end of the notification pipe. The other end is written to by the polling
  // thread.
  int fd = ctx->getFd();

  ssl_async_event_ = dispatcher_.createFileEvent(
      fd,
      [this, ctx, fd](uint32_t events) -> void {
        CpaStatus status = CPA_STATUS_FAIL;
        {
          Thread::LockGuard data_lock(ctx->data_lock_);
          (void)events;
          int bytes = read(fd, &status, sizeof(status));
          if (bytes != sizeof(status)) {
            status = CPA_STATUS_FAIL;
          }
          ctx->setOpStatus(status);
        }
        this->cb_.onPrivateKeyMethodComplete();
      },
      Event::FileTriggerType::Edge, Event::FileReadyType::Read);
}

void QatPrivateKeyConnection::unregisterCallback() { ssl_async_event_ = nullptr; }

static ssl_private_key_result_t privateKeySign(SSL* ssl, uint8_t* out, size_t* out_len,
                                               size_t max_out, uint16_t signature_algorithm,
                                               const uint8_t* in, size_t in_len) {
  // Never return synchronously with signature.
  (void)out;
  (void)out_len;
  (void)max_out;

  RSA* rsa;
  const EVP_MD* md;
  bssl::ScopedEVP_MD_CTX ctx;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  uint8_t* msg;
  size_t msg_len;
  int prefix_allocated = 0;
  QatContext* qat_ctx = nullptr;
  int padding = RSA_NO_PADDING;

  QatPrivateKeyConnection* ops = static_cast<QatPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, QatManager::ssl_qat_connection_index));

  if (!ops) {
    return ssl_private_key_failure;
  }

  QatHandle& qat_handle = ops->getHandle();

  EVP_PKEY* rsa_pkey = ops->getPrivateKey();

  // Check if the SSL instance has correct data attached to it.
  if (!rsa_pkey) {
    goto error;
  }

  if (EVP_PKEY_id(rsa_pkey) != SSL_get_signature_algorithm_key_type(signature_algorithm)) {
    goto error;
  }

  rsa = EVP_PKEY_get0_RSA(rsa_pkey);
  if (rsa == nullptr) {
    goto error;
  }

  md = SSL_get_signature_algorithm_digest(signature_algorithm);
  if (!md) {
    goto error;
  }

  // Create QAT context which will be used for this particular signing/decryption.
  qat_ctx = new QatContext(qat_handle);
  if (qat_ctx == nullptr || !qat_ctx->init()) {
    goto error;
  }

  // The fd will become readable when the QAT operation has been completed.
  ops->registerCallback(qat_ctx);

  // Associate the SSL instance with the QAT Context.
  if (!SSL_set_ex_data(ssl, QatManager::ssl_qat_context_index, qat_ctx)) {
    goto error;
  }

  // Calculate the digest for signing.
  if (!EVP_DigestInit_ex(ctx.get(), md, nullptr) || !EVP_DigestUpdate(ctx.get(), in, in_len) ||
      !EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
    goto error;
  }

  // Addd RSA padding to the the hash. Supported types are PSS and PKCS1.
  if (SSL_is_signature_algorithm_rsa_pss(signature_algorithm)) {
    msg_len = RSA_size(rsa);
    msg = static_cast<uint8_t*>(OPENSSL_malloc(msg_len));
    if (!msg) {
      goto error;
    }
    prefix_allocated = 1;
    if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa, msg, hash, md, NULL, -1)) {
      goto error;
    }
    padding = RSA_NO_PADDING;
  } else {
    if (!RSA_add_pkcs1_prefix(&msg, &msg_len, &prefix_allocated, EVP_MD_type(md), hash, hash_len)) {
      goto error;
    }
    padding = RSA_PKCS1_PADDING;
  }

  // Start QAT decryption (signing) operation.
  if (!qat_ctx->decrypt(msg_len, msg, rsa, padding)) {
    goto error;
  }

  if (prefix_allocated) {
    OPENSSL_free(msg);
  }

  return ssl_private_key_retry;

error:
  if (prefix_allocated) {
    OPENSSL_free(msg);
  }
  delete qat_ctx;
  return ssl_private_key_failure;
}

static ssl_private_key_result_t privateKeyDecrypt(SSL* ssl, uint8_t* out, size_t* out_len,
                                                  size_t max_out, const uint8_t* in,
                                                  size_t in_len) {
  (void)out;
  (void)out_len;
  (void)max_out;

  RSA* rsa;
  QatContext* qat_ctx = nullptr;

  QatPrivateKeyConnection* ops = static_cast<QatPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, QatManager::ssl_qat_connection_index));

  if (!ops) {
    return ssl_private_key_failure;
  }

  QatHandle& qat_handle = ops->getHandle();
  EVP_PKEY* rsa_pkey = ops->getPrivateKey();

  // Check if the SSL instance has correct data attached to it.
  if (!rsa_pkey) {
    goto error;
  }

  rsa = EVP_PKEY_get0_RSA(rsa_pkey);
  if (rsa == nullptr) {
    goto error;
  }

  // Create QAT context which will be used for this particular signing/decryption.
  qat_ctx = new QatContext(qat_handle);
  if (qat_ctx == nullptr || !qat_ctx->init()) {
    goto error;
  }

  // The fd will become readable when the QAT operation has been completed.
  ops->registerCallback(qat_ctx);

  // Associate the SSL instance with the QAT Context.
  if (!SSL_set_ex_data(ssl, QatManager::ssl_qat_context_index, qat_ctx)) {
    goto error;
  }

  // Start QAT decryption (signing) operation.
  if (!qat_ctx->decrypt(in_len, in, rsa, RSA_NO_PADDING)) {
    goto error;
  }

  return ssl_private_key_retry;

error:
  delete qat_ctx;
  return ssl_private_key_failure;
}

static ssl_private_key_result_t privateKeyComplete(SSL* ssl, uint8_t* out, size_t* out_len,
                                                   size_t max_out) {

  QatPrivateKeyConnection* ops = static_cast<QatPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, QatManager::ssl_qat_connection_index));

  if (!ops) {
    return ssl_private_key_failure;
  }

  QatContext* qat_ctx =
      static_cast<QatContext*>(SSL_get_ex_data(ssl, QatManager::ssl_qat_context_index));

  if (!qat_ctx) {
    return ssl_private_key_failure;
  }

  // Check if the QAT operation is ready yet. This can happen if someone calls
  // the top-level SSL function too early. The op status is only set from this thread.
  if (qat_ctx->getOpStatus() == CPA_STATUS_RETRY) {
    return ssl_private_key_retry;
  }

  // If this point is reached, the QAT processing must be complete. We are allowed to delete the
  // qat_ctx now without fear of the polling thread trying to use it.

  // Unregister the callback to prevent it from being called again when the pipe is closed.
  ops->unregisterCallback();

  // See if the operation failed.
  if (qat_ctx->getOpStatus() != CPA_STATUS_SUCCESS) {
    delete qat_ctx;
    return ssl_private_key_failure;
  }

  *out_len = qat_ctx->getDecryptedDataLength();

  if (*out_len > max_out) {
    delete qat_ctx;
    return ssl_private_key_failure;
  }

  memcpy(out, qat_ctx->getDecryptedData(), *out_len);

  SSL_set_ex_data(ssl, QatManager::ssl_qat_context_index, nullptr);

  delete qat_ctx;
  return ssl_private_key_success;
}

Ssl::BoringSslPrivateKeyMethodSharedPtr
QatPrivateKeyMethodProvider::getBoringSslPrivateKeyMethod() {
  return method_;
}

bool QatPrivateKeyMethodProvider::checkFips() {
  RSA* rsa_private_key = EVP_PKEY_get0_RSA(pkey_.get());
  if (rsa_private_key == nullptr || !RSA_check_fips(rsa_private_key)) {
    return false;
  }
  return true;
}

QatPrivateKeyConnection::QatPrivateKeyConnection(Ssl::PrivateKeyConnectionCallbacks& cb,
                                                 Event::Dispatcher& dispatcher, QatHandle& handle,
                                                 bssl::UniquePtr<EVP_PKEY> pkey)
    : cb_(cb), dispatcher_(dispatcher), handle_(handle), pkey_(std::move(pkey)) {}

void QatPrivateKeyMethodProvider::registerPrivateKeyMethod(SSL* ssl,
                                                           Ssl::PrivateKeyConnectionCallbacks& cb,
                                                           Event::Dispatcher& dispatcher) {

  if (!initialized_ || section_ == nullptr || !section_->isInitialized()) {
    throw EnvoyException("QAT isn't properly initialized.");
  }

  QatHandle& handle = section_->getNextHandle();

  QatPrivateKeyConnection* ops =
      new QatPrivateKeyConnection(cb, dispatcher, handle, bssl::UpRef(pkey_));
  SSL_set_ex_data(ssl, QatManager::ssl_qat_connection_index, ops);
}

void QatPrivateKeyMethodProvider::unregisterPrivateKeyMethod(SSL* ssl) {
  QatPrivateKeyConnection* ops = static_cast<QatPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, QatManager::ssl_qat_connection_index));
  SSL_set_ex_data(ssl, QatManager::ssl_qat_connection_index, nullptr);
  delete ops;
}

QatPrivateKeyMethodProvider::QatPrivateKeyMethodProvider(
    const qat::QatPrivateKeyMethodConfig& conf,
    Server::Configuration::TransportSocketFactoryContext& factory_context)
    : api_(factory_context.api()) {

  manager_ = factory_context.singletonManager().getTyped<QatManager>(
      SINGLETON_MANAGER_REGISTERED_NAME(qat_manager),
      [] { return std::make_shared<QatManager>(); });

  section_name_ = conf.section_name();
  poll_delay_ = conf.poll_delay();
  std::string private_key = factory_context.api().fileSystem().fileReadToEnd(conf.private_key());

  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(const_cast<char*>(private_key.data()), private_key.size()));
  bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (pkey == nullptr) {
    throw EnvoyException("Failed to read private key from disk.");
  }
  pkey_ = std::move(pkey);

  std::shared_ptr<QatSection> section = manager_->findSection(section_name_);
  if (section != nullptr) {
    section_ = section;
  } else {
    section_ = manager_->addSection(section_name_);
    if (section_ != nullptr && section_->startSection(api_, poll_delay_)) {
      initialized_ = true;
    } else {
      throw EnvoyException("No QAT section name found.");
    }
  }

  method_ = std::make_shared<SSL_PRIVATE_KEY_METHOD>();
  method_->sign = privateKeySign;
  method_->decrypt = privateKeyDecrypt;
  method_->complete = privateKeyComplete;
}

} // namespace PrivateKeyMethodProvider
} // namespace Extensions
} // namespace Envoy
