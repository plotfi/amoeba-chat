cmake_minimum_required(VERSION 3.13)
project(attohttp LANGUAGES CXX)

add_executable(attohttpd attohttp.cpp)
target_compile_features(attohttpd PRIVATE cxx_std_17)

# Hardening flags for a network-facing daemon.  _FORTIFY_SOURCE=2 needs -O1+,
# which Release mode supplies.
target_compile_options(attohttpd PRIVATE
  -pthread
  # Exceptions stay on deliberately.  With -fno-exceptions a failed allocation
  # does not throw -- it calls std::terminate, so memory pressure killed the
  # whole server instead of the one request that asked for too much.  The
  # worker catches instead, and drops that connection.
  -fno-rtti
  -Wall
  -Wextra
  -Wformat
  -Wformat-security
  -Werror=format-security
  -fstack-protector-strong
  -D_FORTIFY_SOURCE=2
  -fPIE
)
target_link_options(attohttpd PRIVATE -pthread -pie)
if(UNIX AND NOT APPLE)
  # Full RELRO seals the GOT after startup.  macOS ld has no -z relro.
  target_link_options(attohttpd PRIVATE -Wl,-z,relro -Wl,-z,now)
endif()

# Optional TLS.  Set tls_cert/tls_key in attohttp.conf to turn it on.
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
  target_compile_definitions(attohttpd PRIVATE HAVE_OPENSSL)
  target_link_libraries(attohttpd PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  message(STATUS "OpenSSL found — TLS support enabled")
else()
  message(STATUS "OpenSSL not found — building without TLS support")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# -----------------------------------------------------------------------------
# Tests.  `ctest --test-dir build` runs the suite against the binary just built;
# the suite itself is plain Python with no third-party dependencies, so it also
# runs directly:  ./tests/run_tests.py [--quick]
# -----------------------------------------------------------------------------
enable_testing()
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
  add_test(NAME suite
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py)
  add_test(NAME suite-quick
           COMMAND ${Python3_EXECUTABLE}
                   ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py --quick)
  # Both point at the binary from this build tree rather than a stale one.
  set_tests_properties(suite suite-quick PROPERTIES
    ENVIRONMENT "ATTOHTTPD=$<TARGET_FILE:attohttpd>"
    TIMEOUT 900)
else()
  message(STATUS "Python3 not found - `ctest` will have nothing to run")
endif()
