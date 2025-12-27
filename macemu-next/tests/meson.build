# CPU tests
test_unicorn_m68k = executable('test_unicorn_m68k',
  'cpu/test_unicorn_m68k.c',
  dependencies: [cpu_dep, unicorn_dep, threads_dep, m_dep],
  include_directories: include_directories('../src/cpu')
)

test('Unicorn M68K wrapper test', test_unicorn_m68k)

# Dual-CPU harness test (only if building with dualcpu backend)
if cpu_backend == 'dualcpu'
  test_dualcpu = executable('test_dualcpu',
    'cpu/test_dualcpu.c',
    dependencies: [cpu_dep, unicorn_dep, threads_dep, m_dep],
    include_directories: include_directories('../src/cpu')
  )

  test('Dual-CPU harness test', test_dualcpu)
endif
