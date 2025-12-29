# CPU tests
test_unicorn_m68k = executable('test_unicorn_m68k',
  'cpu/test_unicorn_m68k.c',
  dependencies: [cpu_dep, unicorn_dep, threads_dep, m_dep],
  include_directories: include_directories('../src/cpu')
)

test('Unicorn M68K wrapper test', test_unicorn_m68k)

# Dual-CPU harness test (always compiled now)
test_dualcpu = executable('test_dualcpu',
  'cpu/test_dualcpu.c',
  dependencies: [cpu_dep, unicorn_dep, threads_dep, m_dep],
  include_directories: include_directories('../src/cpu')
)

test('Dual-CPU harness test', test_dualcpu)

# Boot test
subdir('boot')

# Minimal halt test (simple - no InitAll, just UAE CPU)
test_halt_simple = executable('test_halt_simple',
  'test_halt_simple.cpp',
  link_with: [cpu_lib],
  dependencies: [unicorn_dep, threads_dep, m_dep],
  include_directories: [
    include_directories('../src/common/include'),
    include_directories('../src/cpu'),
    include_directories('../src/cpu/uae_cpu'),
  ]
)

test('Simple HALT test', test_halt_simple, args: ['roms/test_halt.bin'], workdir: meson.project_source_root() / 'tests')
