#include "extensions/transport_sockets/tls/ssl_handshaker.h"

#include "envoy/stats/scope.h"

#include "common/common/assert.h"
#include "common/common/empty_string.h"
#include "common/common/hex.h"
#include "common/http/headers.h"

#include "extensions/transport_sockets/tls/utility.h"

#include "absl/strings/str_replace.h"
#include "openssl/err.h"
#include "openssl/x509v3.h"

using Envoy::Network::PostIoAction;

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace Tls {

void SslExtendedSocketInfoImpl::setCertificateValidationStatus(
    Envoy::Ssl::ClientValidationStatus validated) {
  certificate_validation_status_ = validated;
}

Envoy::Ssl::ClientValidationStatus SslExtendedSocketInfoImpl::certificateValidationStatus() const {
  return certificate_validation_status_;
}

SslHandshakerImpl::SslHandshakerImpl(bssl::UniquePtr<SSL> ssl, int ssl_extended_socket_info_index,
                                     Ssl::HandshakeCallbacks* handshake_callbacks)
    : ssl_(std::move(ssl)), handshake_callbacks_(handshake_callbacks),
      state_(Ssl::SocketState::PreHandshake) {
  SSL_set_ex_data(ssl_.get(), ssl_extended_socket_info_index, &(this->extended_socket_info_));
}

bool SslHandshakerImpl::peerCertificatePresented() const {
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  return cert != nullptr;
}

bool SslHandshakerImpl::peerCertificateValidated() const {
  return extended_socket_info_.certificateValidationStatus() ==
         Envoy::Ssl::ClientValidationStatus::Validated;
}

absl::Span<const std::string> SslHandshakerImpl::uriSanLocalCertificate() const {
  if (!cached_uri_san_local_certificate_.empty()) {
    return cached_uri_san_local_certificate_;
  }

  // The cert object is not owned.
  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_uri_san_local_certificate_.empty());
    return cached_uri_san_local_certificate_;
  }
  cached_uri_san_local_certificate_ = Utility::getSubjectAltNames(*cert, GEN_URI);
  return cached_uri_san_local_certificate_;
}

absl::Span<const std::string> SslHandshakerImpl::dnsSansLocalCertificate() const {
  if (!cached_dns_san_local_certificate_.empty()) {
    return cached_dns_san_local_certificate_;
  }

  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_dns_san_local_certificate_.empty());
    return cached_dns_san_local_certificate_;
  }
  cached_dns_san_local_certificate_ = Utility::getSubjectAltNames(*cert, GEN_DNS);
  return cached_dns_san_local_certificate_;
}

const std::string& SslHandshakerImpl::sha256PeerCertificateDigest() const {
  if (!cached_sha_256_peer_certificate_digest_.empty()) {
    return cached_sha_256_peer_certificate_digest_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_sha_256_peer_certificate_digest_.empty());
    return cached_sha_256_peer_certificate_digest_;
  }

  std::vector<uint8_t> computed_hash(SHA256_DIGEST_LENGTH);
  unsigned int n;
  X509_digest(cert.get(), EVP_sha256(), computed_hash.data(), &n);
  RELEASE_ASSERT(n == computed_hash.size(), "");
  cached_sha_256_peer_certificate_digest_ = Hex::encode(computed_hash);
  return cached_sha_256_peer_certificate_digest_;
}

const std::string& SslHandshakerImpl::sha1PeerCertificateDigest() const {
  if (!cached_sha_1_peer_certificate_digest_.empty()) {
    return cached_sha_1_peer_certificate_digest_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_sha_1_peer_certificate_digest_.empty());
    return cached_sha_1_peer_certificate_digest_;
  }

  std::vector<uint8_t> computed_hash(SHA_DIGEST_LENGTH);
  unsigned int n;
  X509_digest(cert.get(), EVP_sha1(), computed_hash.data(), &n);
  RELEASE_ASSERT(n == computed_hash.size(), "");
  cached_sha_1_peer_certificate_digest_ = Hex::encode(computed_hash);
  return cached_sha_1_peer_certificate_digest_;
}

const std::string& SslHandshakerImpl::urlEncodedPemEncodedPeerCertificate() const {
  if (!cached_url_encoded_pem_encoded_peer_certificate_.empty()) {
    return cached_url_encoded_pem_encoded_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_url_encoded_pem_encoded_peer_certificate_.empty());
    return cached_url_encoded_pem_encoded_peer_certificate_;
  }

  bssl::UniquePtr<BIO> buf(BIO_new(BIO_s_mem()));
  RELEASE_ASSERT(buf != nullptr, "");
  RELEASE_ASSERT(PEM_write_bio_X509(buf.get(), cert.get()) == 1, "");
  const uint8_t* output;
  size_t length;
  RELEASE_ASSERT(BIO_mem_contents(buf.get(), &output, &length) == 1, "");
  absl::string_view pem(reinterpret_cast<const char*>(output), length);
  cached_url_encoded_pem_encoded_peer_certificate_ = absl::StrReplaceAll(
      pem, {{"\n", "%0A"}, {" ", "%20"}, {"+", "%2B"}, {"/", "%2F"}, {"=", "%3D"}});
  return cached_url_encoded_pem_encoded_peer_certificate_;
}

const std::string& SslHandshakerImpl::urlEncodedPemEncodedPeerCertificateChain() const {
  if (!cached_url_encoded_pem_encoded_peer_cert_chain_.empty()) {
    return cached_url_encoded_pem_encoded_peer_cert_chain_;
  }

  // STACK_OF(X509)* cert_chain = SSL_get_peer_full_cert_chain(ssl());
  // FIXME: check if we need the "full" cert chain?
  STACK_OF(X509)* cert_chain = SSL_get_peer_cert_chain(ssl());
  if (cert_chain == nullptr) {
    ASSERT(cached_url_encoded_pem_encoded_peer_cert_chain_.empty());
    return cached_url_encoded_pem_encoded_peer_cert_chain_;
  }

  for (int i = 0; i < sk_X509_num(cert_chain); i++) {
    X509* cert = sk_X509_value(cert_chain, i);

    bssl::UniquePtr<BIO> buf(BIO_new(BIO_s_mem()));
    RELEASE_ASSERT(buf != nullptr, "");
    RELEASE_ASSERT(PEM_write_bio_X509(buf.get(), cert) == 1, "");
    const uint8_t* output;
    size_t length;
    RELEASE_ASSERT(BIO_mem_contents(buf.get(), &output, &length) == 1, "");

    absl::string_view pem(reinterpret_cast<const char*>(output), length);
    cached_url_encoded_pem_encoded_peer_cert_chain_ = absl::StrCat(
        cached_url_encoded_pem_encoded_peer_cert_chain_,
        absl::StrReplaceAll(
            pem, {{"\n", "%0A"}, {" ", "%20"}, {"+", "%2B"}, {"/", "%2F"}, {"=", "%3D"}}));
  }
  return cached_url_encoded_pem_encoded_peer_cert_chain_;
}

absl::Span<const std::string> SslHandshakerImpl::uriSanPeerCertificate() const {
  if (!cached_uri_san_peer_certificate_.empty()) {
    return cached_uri_san_peer_certificate_;
  }

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_uri_san_peer_certificate_.empty());
    return cached_uri_san_peer_certificate_;
  }
  cached_uri_san_peer_certificate_ = Utility::getSubjectAltNames(*cert, GEN_URI);
  return cached_uri_san_peer_certificate_;
}

absl::Span<const std::string> SslHandshakerImpl::dnsSansPeerCertificate() const {
  if (!cached_dns_san_peer_certificate_.empty()) {
    return cached_dns_san_peer_certificate_;
  }

  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_dns_san_peer_certificate_.empty());
    return cached_dns_san_peer_certificate_;
  }
  cached_dns_san_peer_certificate_ = Utility::getSubjectAltNames(*cert, GEN_DNS);
  return cached_dns_san_peer_certificate_;
}

uint16_t SslHandshakerImpl::ciphersuiteId() const {
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  if (cipher == nullptr) {
    return 0xffff;
  }

  // From the OpenSSL docs:
  //    SSL_CIPHER_get_id returns |cipher|'s id. It may be cast to a |uint16_t| to
  //    get the cipher suite value.
  return static_cast<uint16_t>(SSL_CIPHER_get_id(cipher));
}

std::string SslHandshakerImpl::ciphersuiteString() const {
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  if (cipher == nullptr) {
    return {};
  }

  return SSL_CIPHER_get_name(cipher);
}

const std::string& SslHandshakerImpl::tlsVersion() const {
  if (!cached_tls_version_.empty()) {
    return cached_tls_version_;
  }
  cached_tls_version_ = SSL_get_version(ssl());
  return cached_tls_version_;
}

void SslHandshakerImpl::asyncCb() {
  ENVOY_CONN_LOG(debug, "SSL async done!", handshake_callbacks_->connection());
  ASSERT(state_ != Ssl::SocketState::HandshakeComplete);

  if (state_ == Ssl::SocketState::ShutdownSent) {
    return;
  }

  while (state_ == Ssl::SocketState::HandshakeInProgress) {
    PostIoAction action = doHandshake();

    if (action == PostIoAction::Close) {
      // ctx_->stats().fail_async_handshake_error_.inc();
      ENVOY_CONN_LOG(debug, "async handshake completion error", handshake_callbacks_->connection());
      handshake_callbacks_->connection().close(Network::ConnectionCloseType::FlushWrite);
      return;
    }
  }
  // This function will not be called again, the handshake must be ready at this point.
  ASSERT(state_ != Ssl::SocketState::HandshakeInProgress);
}

Network::PostIoAction SslHandshakerImpl::doHandshake() {
  ENVOY_CONN_LOG(debug, "doHandshake", handshake_callbacks_->connection());
  ASSERT(state_ != Ssl::SocketState::HandshakeComplete && state_ != Ssl::SocketState::ShutdownSent);
  int rc = SSL_do_handshake(ssl());
  if (rc == 1) {
    ENVOY_CONN_LOG(debug, "handshake complete", handshake_callbacks_->connection());
    state_ = Ssl::SocketState::HandshakeComplete;
    handshake_callbacks_->onSuccess(ssl());

    // It's possible that we closed during the handshake callback.
    return handshake_callbacks_->connection().state() == Network::Connection::State::Open
               ? PostIoAction::KeepOpen
               : PostIoAction::Close;
  } else {
    OSSL_ASYNC_FD* fds;
    size_t numfds;
    int err = SSL_get_error(ssl(), rc);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      // TODO: This means that we need to wait for the socket to become readable/writable and
      // then try again. The waiting should be done in Envoy event loop also in the async case.
      ENVOY_CONN_LOG(debug, "SSL_ERROR_WANT_READ/WRITE", handshake_callbacks_->connection());
      return PostIoAction::KeepOpen;
    case SSL_ERROR_WANT_ASYNC:
      ENVOY_CONN_LOG(debug, "SSL handshake: request async handling", handshake_callbacks_->connection());

      if (state_ == Ssl::SocketState::HandshakeInProgress) {
        return PostIoAction::KeepOpen;
      }

      state_ = Ssl::SocketState::HandshakeInProgress;

      rc = SSL_get_all_async_fds(ssl(), NULL, &numfds);
      if (rc == 0) {
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      /* We only wait for the first fd here! Will fail if multiple async engines. */
      if (numfds != 1) {
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      fds = static_cast<OSSL_ASYNC_FD*>(malloc(numfds * sizeof(OSSL_ASYNC_FD)));
      if (fds == NULL) {
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      rc = SSL_get_all_async_fds(ssl(), fds, &numfds);
      if (rc == 0) {
        free(fds);
        handshake_callbacks_->onFailure();
        return PostIoAction::Close;
      }

      file_event_ = handshake_callbacks_->connection().dispatcher().createFileEvent(
          fds[0], [this](uint32_t /* events */) -> void { asyncCb(); },
          Event::FileTriggerType::Edge, Event::FileReadyType::Read);

      ENVOY_CONN_LOG(debug, "SSL async fd: {}, numfds: {}", handshake_callbacks_->connection(), fds[0],
                     numfds);
      free(fds);

      return PostIoAction::KeepOpen;
    default:
      ENVOY_CONN_LOG(debug, "handshake error: {}", handshake_callbacks_->connection(), err);
      state_ = Ssl::SocketState::HandshakeComplete;
      handshake_callbacks_->onFailure();
      return PostIoAction::Close;
    }
  }
}

const std::string& SslHandshakerImpl::serialNumberPeerCertificate() const {
  if (!cached_serial_number_peer_certificate_.empty()) {
    return cached_serial_number_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_serial_number_peer_certificate_.empty());
    return cached_serial_number_peer_certificate_;
  }
  cached_serial_number_peer_certificate_ = Utility::getSerialNumberFromCertificate(*cert.get());
  return cached_serial_number_peer_certificate_;
}

const std::string& SslHandshakerImpl::issuerPeerCertificate() const {
  if (!cached_issuer_peer_certificate_.empty()) {
    return cached_issuer_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_issuer_peer_certificate_.empty());
    return cached_issuer_peer_certificate_;
  }
  cached_issuer_peer_certificate_ = Utility::getIssuerFromCertificate(*cert);
  return cached_issuer_peer_certificate_;
}

const std::string& SslHandshakerImpl::subjectPeerCertificate() const {
  if (!cached_subject_peer_certificate_.empty()) {
    return cached_subject_peer_certificate_;
  }
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    ASSERT(cached_subject_peer_certificate_.empty());
    return cached_subject_peer_certificate_;
  }
  cached_subject_peer_certificate_ = Utility::getSubjectFromCertificate(*cert);
  return cached_subject_peer_certificate_;
}

const std::string& SslHandshakerImpl::subjectLocalCertificate() const {
  if (!cached_subject_local_certificate_.empty()) {
    return cached_subject_local_certificate_;
  }
  X509* cert = SSL_get_certificate(ssl());
  if (!cert) {
    ASSERT(cached_subject_local_certificate_.empty());
    return cached_subject_local_certificate_;
  }
  cached_subject_local_certificate_ = Utility::getSubjectFromCertificate(*cert);
  return cached_subject_local_certificate_;
}

absl::optional<SystemTime> SslHandshakerImpl::validFromPeerCertificate() const {
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    return absl::nullopt;
  }
  return Utility::getValidFrom(*cert);
}

absl::optional<SystemTime> SslHandshakerImpl::expirationPeerCertificate() const {
  bssl::UniquePtr<X509> cert(SSL_get_peer_certificate(ssl()));
  if (!cert) {
    return absl::nullopt;
  }
  return Utility::getExpirationTime(*cert);
}

const std::string& SslHandshakerImpl::sessionId() const {
  if (!cached_session_id_.empty()) {
    return cached_session_id_;
  }
  SSL_SESSION* session = SSL_get_session(ssl());
  if (session == nullptr) {
    ASSERT(cached_session_id_.empty());
    return cached_session_id_;
  }

  unsigned int session_id_length = 0;
  const uint8_t* session_id = SSL_SESSION_get_id(session, &session_id_length);
  cached_session_id_ = Hex::encode(session_id, session_id_length);
  return cached_session_id_;
}

} // namespace Tls
} // namespace TransportSockets
} // namespace Extensions
} // namespace Envoy
