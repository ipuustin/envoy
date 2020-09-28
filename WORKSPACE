workspace(name = "envoy")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("//bazel:repositories_extra.bzl", "envoy_dependencies_extra")

envoy_dependencies_extra()

load("//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

http_archive(
    name = "openssl",
    build_file = "@//:openssl.BUILD",
    sha256 = "281e4f13142b53657bd154481e18195b2d477572fdffa8ed1065f73ef5a19777",
    strip_prefix = "openssl-OpenSSL_1_1_1g",
    urls = ["https://github.com/openssl/openssl/archive/OpenSSL_1_1_1g.tar.gz"],
)

new_local_repository(
    name = "openssl_shared",
    build_file = "openssl_host_shared.BUILD",
    path = "/usr/lib64",
)

http_archive(
    name = "com_github_google_jwt_verify_patched",
    patch_args = ["-p1"],
    patches = ["//:jwt_verify-make-compatible-with-openssl.patch"],
    sha256 = "118f955620509f1634cbd918c63234d2048dce56b1815caf348d78e3c3dc899c",
    strip_prefix = "jwt_verify_lib-44291b2ee4c19631e5a0a0bf4f965436a9364ca7",
    urls = ["https://github.com/google/jwt_verify_lib/archive/44291b2ee4c19631e5a0a0bf4f965436a9364ca7.tar.gz"],
)

# TODO: Consider not using `bind`. See https://github.com/bazelbuild/bazel/issues/1952 for details.
bind(
    name = "jwt_verify_lib",
    actual = "@com_github_google_jwt_verify_patched//:jwt_verify_lib",
)
