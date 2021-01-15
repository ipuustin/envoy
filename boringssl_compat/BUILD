load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_cc_library(
    name = "bssl_compat_cbs_lib",
    srcs = [
        "cbs.cc",
    ],
    hdrs = [
        "cbs.h",
    ],
    deps = ["@openssl_shared//:ssl"],
)

envoy_cc_library(
    name = "bssl_compat_lib",
    srcs = [
        "bssl.cc",
    ],
    hdrs = [
        "bssl.h",
    ],
    deps = ["@openssl_shared//:ssl"],
)
