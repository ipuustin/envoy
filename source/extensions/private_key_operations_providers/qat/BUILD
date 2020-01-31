licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "qat_private_key_provider_lib",
    srcs = [
        "qat.cc",
        "qat_private_key_provider.cc",
    ],
    hdrs = [
        "qat.h",
        "qat_private_key_provider.h",
    ],
    external_deps = ["ssl"],
    deps = [
        "//include/envoy/api:api_interface",
        "//include/envoy/event:dispatcher_interface",
        "//include/envoy/registry",
        "//include/envoy/server:transport_socket_config_interface",
        "//include/envoy/singleton:manager_interface",
        "//include/envoy/ssl/private_key:private_key_config_interface",
        "//include/envoy/ssl/private_key:private_key_interface",
        "//source/common/common:thread_lib",
        "//source/extensions/transport_sockets/tls:utility_lib",
        "@com_intel_qat//:qat",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/private_key_operations_providers/qat/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    security_posture = "robust_to_untrusted_downstream",
    deps = [
        ":qat_private_key_provider_lib",
        "//include/envoy/protobuf:message_validator_interface",
        "//include/envoy/registry",
        "//include/envoy/ssl/private_key:private_key_config_interface",
        "//include/envoy/ssl/private_key:private_key_interface",
        "//source/common/config:utility_lib",
        "//source/common/protobuf:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/private_key_operations_providers/qat/v3:pkg_cc_proto",
    ],
)
