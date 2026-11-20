# Dependency policy

## Supported baseline

`net-net` targets C++20. Linux is the deployment baseline; macOS is a supported developer environment. The project requires CMake 3.24 or newer, OpenSSL 3.0 or newer, libpcap, yaml-cpp 0.8 or newer, nlohmann/json 3.12 or newer, and GoogleTest 1.17 or newer for tests.

## Ownership and pinning

System-facing libraries (`libpcap`, OpenSSL, SQLite, yaml-cpp, nlohmann/json, and GoogleTest) are installed and patched by the host package manager or CI image. CMake declares a minimum compatible version and never hard-codes a Homebrew Cellar path.

Source-fetched libraries must use an immutable commit ID in `CMakeLists.txt`, with the human-readable release tag beside it. Current pins are:

| Dependency | Release | Immutable revision | Reason |
| --- | --- | --- | --- |
| SQLiteCpp | 3.3.1 | `4eb9964c2d71a3c03ebd04291f093a78783f58cf` | SQLite convenience wrapper |
| cpp-httplib | 0.58.0 | `4f3f9ef19be83ae97a5d9a059432dc00e445b7ab` | HTTP server/client |

The historical copy of `include/net-net/vendor/httplib.h` is no longer a build dependency and must not be included by new code. It can be removed after a clean build has validated the fetched replacement in CI.

## Update procedure

1. Check upstream release notes and security advisories.
2. Record the release tag, immutable commit ID, compatibility notes, and test result in the session handover record.
3. Update one dependency family per change.
4. Configure from an empty build directory and run the full CTest suite on macOS and Linux.
5. Treat changes to parsers, crypto, HTTP handling, or packet capture as security-sensitive; add focused regression tests before merging.

Python test tooling remains pinned in `requirements.txt`. Refresh it with `pip-compile --upgrade` (or equivalent lock generation) in a dedicated change; do not mix it with a runtime security change.
