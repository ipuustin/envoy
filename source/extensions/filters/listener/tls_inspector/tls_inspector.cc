#include "extensions/filters/listener/tls_inspector/tls_inspector.h"

#include <arpa/inet.h>

#include <cstdint>
#include <string>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/event/dispatcher.h"
#include "envoy/network/listen_socket.h"
#include "envoy/stats/stats.h"

#include "common/api/os_sys_calls_impl.h"
#include "common/common/assert.h"

#include "extensions/transport_sockets/well_known_names.h"

//#include "openssl/bytestring.h"
#include "openssl/ssl.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace TlsInspector {

Config::Config(Stats::Scope& scope, uint32_t max_client_hello_size)
    : stats_{ALL_TLS_INSPECTOR_STATS(POOL_COUNTER_PREFIX(scope, "tls_inspector."))},
      ssl_ctx_(SSL_CTX_new(TLS_method())),
      max_client_hello_size_(max_client_hello_size) {
std::cerr << "!!!!!!!!!!!!!!!!! Config::Config \n";

  if (max_client_hello_size_ > TLS_MAX_CLIENT_HELLO) {
    throw EnvoyException(fmt::format("max_client_hello_size of {} is greater than maximum of {}.",
                                     max_client_hello_size_, size_t(TLS_MAX_CLIENT_HELLO)));
  }

  //SSL_CTX_set_options(ssl_ctx_.get(), SSL_OP_NO_TICKET);
  SSL_CTX_set_session_cache_mode(ssl_ctx_.get(), SSL_SESS_CACHE_OFF);

  SSL_CTX_set_cert_cb(ssl_ctx_.get(), cert_cb, ssl_ctx_.get());
  //SSL_CTX_set_client_cert_cb(ssl_ctx_.get(), client_cert_cb);
  
  SSL_CTX_set_tlsext_servername_callback(ssl_ctx_.get(), tlsext_servername_cb);
  //SSL_CTX_set_alpn_select_cb(ssl_ctx_.get(), alpn_cb, nullptr);
  //SSL_CTX_set_next_protos_advertised_cb(ssl_ctx_.get(), next_cb, nullptr);

//  SSL_CTX_set_select_certificate_cb(
//      ssl_ctx_, [](const SSL_CLIENT_HELLO* client_hello) -> ssl_select_cert_result_t {
//        const uint8_t* data;
//        size_t len;
//        if (SSL_early_callback_ctx_extension_get(
//                client_hello, TLSEXT_TYPE_application_layer_protocol_negotiation, &data, &len)) {
//          Filter* filter = static_cast<Filter*>(SSL_get_app_data(client_hello->ssl));
//          filter->onALPN(data, len);
//        }
//        return ssl_select_cert_success;
//      });

//  SSL_CTX_set_tlsext_servername_callback(
//      ssl_ctx_, [](SSL* ssl, int* out_alert, void*) -> int {
//        Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
//        filter->onServername(SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name));

        // Return an error to stop the handshake; we have what we wanted already.
//        *out_alert = SSL_AD_USER_CANCELLED;
//        return SSL_TLSEXT_ERR_ALERT_FATAL;
//      });

std::cerr << "!!!!!!!!!!!!!!!!! Config::Config done \n";
}

int Config::next_cb(SSL *ssl,
              	const unsigned char **out,
              	unsigned int *outlen,
              	void *arg)
{
std::cerr << "!!!!!!!!!!!!!!!!! next_cb \n";
}

int Config::alpn_cb(SSL *ssl,
                   const unsigned char **out,
                   unsigned char *outlen,
                   const unsigned char *in,
                   unsigned int inlen,
                   void *arg)
{
std::cerr << "!!!!!!!!!!!!!!!!! alpn_cb \n";
  const uint8_t* data;
  size_t len;
  //if (SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_application_layer_protocol_negotiation, &data, &len)) {
    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
    filter->onALPN(data, len);
  //}
  return SSL_TLSEXT_ERR_OK;
}

int Config::client_cert_cb(SSL *ssl, X509 **x509, EVP_PKEY **pkey)
{
std::cerr << "!!!!!!!!!!!!!!!!! client_cert_cb \n";
  return 1;
}


int Config::cert_cb(SSL *ssl, void *arg)
{
std::cerr << "!!!!!!!!!!!!!!!!! cert_cb " << ssl << " \n";
  const unsigned char* data;
  unsigned int len;
  size_t size;
  //if (SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_application_layer_protocol_negotiation, &data, &len)) {
    //SSL_get0_next_proto_negotiated(ssl, &data, &len);
//std::cerr << "!!!!!!!!!!!!!!!!! SSL_get0_next_proto_negotiated " << len << " \n";
    SSL_get0_alpn_selected(ssl, &data, &len);
std::cerr << "!!!!!!!!!!!!!!!!! SSL_get0_alpn_selected " << len << " \n";
int rc = SSL_extension_supported(TLSEXT_TYPE_application_layer_protocol_negotiation);
std::cerr << "*************** TLSEXT_TYPE_application_layer_protocol_negotiation " << rc << " \n";


//SSL_SESSION *session = SSL_get_session(ssl);
//std::cerr << "!!!!!!!!!!!!!!!!!! SSL_get_session " << session << " \n";

//SSL_SESSION_get0_alpn_selected(session, &data, &size);
//std::cerr << "!!!!!!!!!!!!!!!!! SSL_SESSION_get0_alpn_selected " << size << " \n";

//unsigned char vector[] = { 
//	2, 'h', '2',
//	8, 'h', 't', 't', 'p', '/', '1', '.', '1' 
//};
//rc = SSL_SESSION_set1_alpn_selected(session, vector, sizeof(vector));
//std::cerr << "!!!!!!!!!!!!!!!!!! SSL_SESSION_set1_alpn_selected " << rc << " \n";

//SSL_SESSION_get0_alpn_selected(session, &data, &size);
//std::cerr << "!!!!!!!!!!!!!!!!! SSL_SESSION_get0_alpn_selected " << size << " \n";

//SSL_get0_alpn_selected(ssl, &data, &len);
//std::cerr << "!!!!!!!!!!!!!!!!! SSL_get0_alpn_selected " << len << " \n";

    Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
    filter->onALPN(data, len);
  //}

    //EVP_PKEY *pkey = EVP_PKEY_new();

    //RSA *rsa = RSA_generate_key(2048, 3, NULL, NULL);
    //EVP_PKEY_assign_RSA(pkey, rsa);

  //SSL_use_PrivateKey(ssl, pkey);

   //const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
  //SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);

  //SSL_CTX* ssl_ctx = (SSL_CTX*)arg;

  //X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
//std::cerr << "!!!!!!!!!!!!!!!!! SSL_CTX_get_cert_store " << store << " \n";

  //STACK_OF(X509_OBJECT) *x509_objects = X509_STORE_get0_objects(store);
//std::cerr << "!!!!!!!!!!!!!!!!! STACK_OF(X509_OBJECT) " << sk_X509_OBJECT_num(x509_objects) << " \n";
  //for (int i = 0; i < sk_X509_OBJECT_num(x509_objects); i++) {
//std::cerr << "!!!!!!!!!!!!!!!!! X509_OBJECT " << i << " \n";
 // }

 // STACK_OF(X509) *peer_certs = SSL_get_peer_cert_chain(ssl);
//std::cerr << "!!!!!!!!!!!!!!!!! peer " << sk_X509_num(peer_certs) << " \n";

 // STACK_OF(X509) *verified = SSL_get0_verified_chain(ssl);
//std::cerr << "!!!!!!!!!!!!!!!!! verified " << sk_X509_num(verified) << " \n";

  return 0;
}

int Config::tlsext_servername_cb(SSL *ssl, void *arg)
{
  std::cerr << "!!!!!!!!!!!!!!!!! tlsext_servername_cb \n";
  Filter* filter = static_cast<Filter*>(SSL_get_app_data(ssl));
  absl::string_view servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
std::cerr << "!!!!!!!!!!!!!!!!!! tlsext_servername_cb servername '" << servername << "' " << servername.empty() << " \n";
  filter->onServername(servername);

  return SSL_TLSEXT_ERR_OK;
}

bssl::UniquePtr<SSL> Config::newSsl() {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! Config::newSsl \n";
  return bssl::UniquePtr<SSL>{SSL_new(ssl_ctx_.get())};
}

thread_local uint8_t Filter::buf_[Config::TLS_MAX_CLIENT_HELLO];

Filter::Filter(const ConfigSharedPtr config) : config_(config), ssl_(config_->newSsl()) {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! Filter \n";
  RELEASE_ASSERT(sizeof(buf_) >= config_->maxClientHelloSize(), "");

  SSL_set_app_data(ssl_.get(), this);
  SSL_set_accept_state(ssl_.get());
}

Network::FilterStatus Filter::onAccept(Network::ListenerFilterCallbacks& cb) {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! onAccept \n";
  ENVOY_LOG(debug, "tls inspector: new connection accepted");
  Network::ConnectionSocket& socket = cb.socket();
  ASSERT(file_event_ == nullptr);

  file_event_ = cb.dispatcher().createFileEvent(
      socket.fd(),
      [this](uint32_t events) {
        if (events & Event::FileReadyType::Closed) {
          config_->stats().connection_closed_.inc();
          done(false);
          return;
        }

        ASSERT(events == Event::FileReadyType::Read);
        onRead();
      },
      Event::FileTriggerType::Edge, Event::FileReadyType::Read | Event::FileReadyType::Closed);

  // TODO(PiotrSikora): make this configurable.
  timer_ = cb.dispatcher().createTimer([this]() -> void { onTimeout(); });
  timer_->enableTimer(std::chrono::milliseconds(15000));

  // TODO(ggreenway): Move timeout and close-detection to the filter manager
  // so that it applies to all listener filters.

  cb_ = &cb;

  std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! onAccept done \n";
  return Network::FilterStatus::StopIteration;
}

void Filter::onALPN(const unsigned char* data, unsigned int len) {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! onALPN \n";

//std::vector<absl::string_view> protocols = {absl::string_view("h2"), absl::string_view("http/1.1")};
//protocols.emplace_back(reinterpret_cast<const char*>("\x02h2\x08http/1.1"), 12);
//  cb_->socket().setRequestedApplicationProtocols(protocols);
//  alpn_found_ = true;
}

void Filter::onServername(absl::string_view name) {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! onServername '" << name << "' \n";
  if (!name.empty()) {
    config_->stats().sni_found_.inc();
    cb_->socket().setRequestedServerName(name);
  } else {
    config_->stats().sni_not_found_.inc();
  }
  clienthello_success_ = true;
}

void Filter::onRead() {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! onRead \n";
  // This receive code is somewhat complicated, because it must be done as a MSG_PEEK because
  // there is no way for a listener-filter to pass payload data to the ConnectionImpl and filters
  // that get created later.
  //
  // The file_event_ in this class gets events everytime new data is available on the socket,
  // even if previous data has not been read, which is always the case due to MSG_PEEK. When
  // the TlsInspector completes and passes the socket along, a new FileEvent is created for the
  // socket, so that new event is immediately signalled as readable because it is new and the socket
  // is readable, even though no new events have ocurred.
  //
  // TODO(ggreenway): write an integration test to ensure the events work as expected on all
  // platforms.
  auto& os_syscalls = Api::OsSysCallsSingleton::get();
  ssize_t n = os_syscalls.recv(cb_->socket().fd(), buf_, config_->maxClientHelloSize(), MSG_PEEK);
  const int error = errno; // Latch errno right after the recv call.
  ENVOY_LOG(trace, "tls inspector: recv: {}", n);

  if (n == -1 && error == EAGAIN) {
    return;
  } else if (n < 0) {
    config_->stats().read_error_.inc();
    done(false);
    return;
  }

  // Because we're doing a MSG_PEEK, data we've seen before gets returned every time, so
  // skip over what we've already processed.
  if (static_cast<uint64_t>(n) > read_) {
    const uint8_t* data = buf_ + read_;
    const size_t len = n - read_;
    read_ = n;
    parseClientHello(data, len);
  }
}

void Filter::onTimeout() {
  ENVOY_LOG(trace, "tls inspector: timeout");
  config_->stats().read_timeout_.inc();
  done(false);
}

void Filter::done(bool success) {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!!! Filter::done \n";
  ENVOY_LOG(trace, "tls inspector: done: {}", success);
  timer_.reset();
  file_event_.reset();
  cb_->continueFilterChain(success);
}

void Filter::parseClientHello(const void* data, size_t len) {
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!! parseClientHello \n";

  // Ownership is passed to ssl_ in SSL_set_bio()
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data, len));

  // Make the mem-BIO return that there is more data
  // available beyond it's end
  BIO_set_mem_eof_return(bio.get(), -1);

  SSL_set_bio(ssl_.get(), bio.get(), bio.get());
  bio.release();

std::cerr << "!!!!!!!!!!!!!!! SSL_do_handshake server " << ssl_.get() << " \n";
  int ret = SSL_do_handshake(ssl_.get());
std::cerr << "!!!!!!!!!!!!!!! SSL_do_handshake ret " << ret << " " << SSL_get_error(ssl_.get(), ret) << " \n";
unsigned long l;
    //while ((l = ERR_get_error()) != 0)
//std::cerr << "!!!!!!!!!!!!!!! ERR_get_error " << ERR_GET_REASON(l) << " \n";

  // This should never succeed because an error is always returned from the SNI callback.
  ASSERT(ret <= 0);
  switch (SSL_get_error(ssl_.get(), ret)) {
  case SSL_ERROR_WANT_READ:
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!! parseClientHello SSL_ERROR_WANT_READ\n";
    if (read_ == config_->maxClientHelloSize()) {
      // We've hit the specified size limit. This is an unreasonably large ClientHello;
      // indicate failure.
      config_->stats().client_hello_too_large_.inc();
      done(false);
    }
    break;
  case SSL_ERROR_SSL:
std::cerr << "!!!!!!!!!!!!!!!!!!!!!!!!!! parseClientHello SSL_ERROR_SSL " << clienthello_success_ << " " << alpn_found_ << " \n";
    if (clienthello_success_) {
      config_->stats().tls_found_.inc();
      if (alpn_found_) {
        config_->stats().alpn_found_.inc();
      } else {
        config_->stats().alpn_not_found_.inc();
      }
      cb_->socket().setDetectedTransportProtocol(TransportSockets::TransportSocketNames::get().Tls);
    } else {
      config_->stats().tls_not_found_.inc();
    }
    done(true);
    break;
  default:
    done(false);
    break;
  }
}

} // namespace TlsInspector
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
