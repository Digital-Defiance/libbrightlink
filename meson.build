# SPDX-License-Identifier: MIT
# libBrightLink — canonical C client for the BrightLink Protocol.

project('libbrightlink', 'c',
    version : '0.1.0',
    default_options : [
        'c_std=gnu99',
        'warning_level=3',
        'werror=false',
    ],
    license : 'MIT',
    meson_version : '>=0.56')

cc = meson.get_compiler('c')

# macOS clang hides BSD extensions like mkdtemp under strict-POSIX
# selection. _DARWIN_C_SOURCE re-enables them. Linux glibc handles this
# via _DEFAULT_SOURCE, which gnu99 already implies.
if host_machine.system() == 'darwin'
    add_project_arguments('-D_DARWIN_C_SOURCE', language : 'c')
endif

# Required deps. Both crypto stacks must be available; libBrightLink does
# not have a no-crypto build mode (the protocol is the crypto).
secp256k1_dep = dependency('libsecp256k1', required : true)
openssl_dep   = dependency('openssl',      required : true)

libbrightlink_inc = include_directories('include')

libbrightlink_sources = files(
    'src/brightlink.c',
    'src/brightlink_crypto.c',
    'src/pin_store.c',
    'src/pin_store_memory.c',
    'src/pin_store_file.c',
)

libbrightlink_lib = static_library('brightlink',
    libbrightlink_sources,
    include_directories : [libbrightlink_inc, include_directories('src')],
    dependencies : [secp256k1_dep, openssl_dep],
    install : false)

# Public dependency consumers use to link against libBrightLink. The
# include path is exported so consumers can `#include "brightlink/brightlink.h"`.
libbrightlink_dep = declare_dependency(
    link_with : libbrightlink_lib,
    include_directories : libbrightlink_inc,
    dependencies : [secp256k1_dep, openssl_dep])

# Tests live under tests/. Disable with -Dlibbrightlink_tests=false.
if get_option('libbrightlink_tests')
    subdir('tests')
endif

# Summary
output  = '\n'
output += 'libBrightLink @0@\n'.format(meson.project_version())
output += '  static archive: yes\n'
output += '  tests: @0@\n'.format(get_option('libbrightlink_tests'))
output += '  secp256k1: @0@\n'.format(secp256k1_dep.version())
output += '  openssl: @0@\n'.format(openssl_dep.version())
message(output)
