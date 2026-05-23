# SPDX-License-Identifier: MIT
subdir('mock-brightnexus')

# Round-trip integration test against the mock.
test_handshake_roundtrip = executable('test_handshake_roundtrip',
    'test_handshake_roundtrip.c',
    dependencies : [libbrightlink_dep],
    install : false)

test('handshake-roundtrip',
    test_handshake_roundtrip,
    env : { 'MESON_BUILD_ROOT' : meson.project_build_root() },
    depends : mock_brightnexus,
    timeout : 30)

# Pin-store unit test (no mock involved).
test_pin_store_file = executable('test_pin_store_file',
    'test_pin_store_file.c',
    dependencies : [libbrightlink_dep],
    install : false)

test('pin-store-file',
    test_pin_store_file,
    timeout : 10)
